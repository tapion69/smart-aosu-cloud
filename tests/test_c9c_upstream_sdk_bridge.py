"""Test genuine upstream SDK 0.1.3 objects + fake transport, no network.

Only synthetic AOSU/Tuya IDs, media keys and video frames. No camera calls,
credentials, identifiers or private APK in GitHub CI.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import runpy
import sys
import types
import unittest

from tuya_ipc_p2p_sdk.models import StreamConfig, MqttIdentity

ROOT=Path(__file__).resolve().parents[1]
DIR=ROOT/"custom_components"/"smart_aosu_cloud"
topology=runpy.run_path(str(DIR/"camera_topology.py"))
fake_package=types.ModuleType("smart_aosu_cloud")
fake_package.__path__=[str(DIR)]
fake_topology=types.ModuleType("smart_aosu_cloud.camera_topology")
fake_topology.select_tuya_standalone_target_typed=topology[
    "select_tuya_standalone_target_typed"]
fake_signaling=types.ModuleType("smart_aosu_cloud.tuya_mqtt_signaling")
fake_signaling._BROKER="m1.tuyaeu.com"
fake_signaling._PORT=8883
sys.modules.update({
    "smart_aosu_cloud":fake_package,
    "smart_aosu_cloud.camera_topology":fake_topology,
    "smart_aosu_cloud.tuya_mqtt_signaling":fake_signaling,
})
spec=importlib.util.spec_from_file_location(
    "smart_aosu_cloud.c9c_upstream_sdk_bridge",
    DIR/"c9c_upstream_sdk_bridge.py")
bridge=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=bridge
spec.loader.exec_module(bridge)

SN="SYNTHETIC_AOSU_SN_BETA"
DEV="SYNTHETIC_TUYA_DEVICE_ID"
UID="SYNTHETIC_TUYA_UID"
SID="SYNTHETIC_RTC_SESSION_ID"
LOCALKEY="ABCD"*4
AES=bytes.fromhex("a1"*16)
PASSWORD="synthetic_device_password_123"
JPEG=b"\xff\xd8"+b"SYNTHETIC_VIDEO"*100+b"\xff\xd9"


class Media:
    device_id=DEV
    owner_uid=UID
    session_id=SID
    local_key=LOCALKEY
    aes_key=AES
    ice_ufrag="ICE_UFRAG_SYNTHETIC"
    ice_password="ICE_PASSWORD_SYNTHETIC"
    relay={
        "username":"2030800000:synthetic",
        "credential":"SYNTHETIC_RELAY_CREDENTIAL",
        "sessionId":"RELAY_SERVER_SESSION_SYNTHETIC",
        "urls":["tcp4:relay.example.test:1443"],
    }
    ice_servers=[{"urls":["stun:stun.example.test:3478"]}]
    log_config={}
    trace_id="TRACE_SYNTHETIC"
    device_password=PASSWORD
    moto_id="SYNTHETIC_MOTO_ID"
    fresh=True
    def is_fresh(self):return self.fresh


def stub_mqtt(apk_identity,signer,tuya_session,install_id,device):
    assert device==DEV
    assert tuya_session.uid==UID
    return types.SimpleNamespace(
        client_id="synthetic-unique-mqtt-id",
        username="synthetic_mqtt_user_123",
        password="synthetic_mqtt_password_123",
    )


def prepare(media=None, uid=UID, cp=DEV, inventory=None, standalone=True):
    if media is None:media=Media()
    if inventory is None:inventory={DEV:{"devId":DEV,"category":"sp"}}
    return bridge.build_verified_sdk_backend(
        media=media,
        tuya_session=types.SimpleNamespace(uid=uid),
        install_id="SYNTHETIC_INSTALL_ID",
        apk_identity=object(),signer=object(),
        aosu_sn=SN,
        aosu_cp_device_id=cp,
        aosu_ty_cp_uuid=None,
        inventory=inventory,
        standalone_c9c=standalone,
        identity_factory=stub_mqtt,
    )


class TestSDKCompatibility(unittest.TestCase):
    def test_actual_upstream_streamconfig_and_mqtt_identity_objects(self):
        ready=prepare()
        self.assertIsInstance(ready._config,StreamConfig)
        self.assertIsInstance(ready._mqtt,MqttIdentity)
        self.assertEqual(ready._config.device_id,DEV)
        self.assertEqual(ready._config.p2p_session.session_id,SID)
        self.assertEqual(ready._config.p2p_session.aes_key,AES)
        self.assertEqual(ready._config.p2p_session.ice_password,Media.ice_password)
        self.assertEqual(ready._config.device_password,PASSWORD)
        self.assertEqual(ready._mqtt.host,"m1.tuyaeu.com")
        self.assertEqual(ready._mqtt.port,8883)
        status=ready.safe_status()
        self.assertFalse(status["connexion_effectuee"])
        self.assertTrue(status["identite_exacte"])
        self.assertEqual(status["appels_reseau"],0)
        self.assertFalse(status["video_confirmee"])

    def test_weak_unique_candidate_does_not_construct_backend(self):
        with self.assertRaisesRegex(bridge.C9CBackendError,
                                    "^c9c_identite_tuya_non_prouvee$"):
            prepare(cp=None)

    def test_ambiguous_or_conflicting_weak_matches_fail_closed(self):
        with self.assertRaises(bridge.C9CBackendError):
            prepare(cp=DEV, inventory={
                DEV:{"devId":DEV},
                "ANOTHER_TUYA_DEVICE":{"devId":"ANOTHER_TUYA_DEVICE","cpDeviceId":DEV}
            })

    def test_wrong_camera_or_stale_session_rejected(self):
        m=Media();m.device_id="DIFFERENT_DEVICE"
        with self.assertRaisesRegex(bridge.C9CBackendError,"session_ou_cible"):
            prepare(media=m)
        m=Media();m.fresh=False
        with self.assertRaises(bridge.C9CBackendError):
            prepare(media=m)

    def test_wrong_authenticated_uid_rejected(self):
        with self.assertRaisesRegex(bridge.C9CBackendError,"session_ou_cible"):
            prepare(uid="ANOTHER_TUYA_UID")

    def test_missing_p2p_material_rejected_before_connection(self):
        m=Media();m.relay={}
        with self.assertRaisesRegex(bridge.C9CBackendError,"rtc_sdk_incomplet"):
            prepare(media=m)
        m=Media();m.device_password=""
        with self.assertRaises(bridge.C9CBackendError):
            prepare(media=m)

    def test_wrong_topology_never_prepares_stream(self):
        with self.assertRaisesRegex(bridge.C9CBackendError,"cible_non_autorisee"):
            prepare(standalone=False)

    def test_never_show_session_or_media_keys_in_report_repr(self):
        ready=prepare()
        report=json.dumps(ready.safe_status())+repr(ready)
        for secret in (SN,DEV,SID,UID,PASSWORD,Media.trace_id,
                       "SYNTHETIC_MQTT","SYNTHETIC_RELAY"):
            self.assertNotIn(secret,report)
        self.assertFalse(ready.safe_status()["identifiants_retournes"])


class FakeActualStream:
    instances=[]
    def __init__(self, config, mqtt, uid, frame_cb):
        self.config=config
        self.mqtt=mqtt
        self.uid=uid
        self.on_frame=frame_cb
        self.closed=False
        self.started=False
        self.fail=False
        self.stop_event=None
        self.__class__.instances.append(self)
    async def async_start(self):
        self.started=True
        if self.fail:
            raise RuntimeError("PRIVATE_SECRET_SHOULD_NOT_ESCAPE")
        self.on_frame(JPEG)
        self.on_frame(b"NOT_A_JPEG")
        self.stop_event.set()
    async def async_wait_closed(self):
        await asyncio.Event().wait()
    async def async_close(self):
        self.closed=True


class TestActiveBackendCleanup(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        FakeActualStream.instances.clear()
        self.ready=prepare()
        self.stop=asyncio.Event()
        self.frames=[]
    def factory(self,*args):
        fake=FakeActualStream(*args)
        fake.stop_event=self.stop
        return fake

    async def test_real_backend_contract_one_play_and_jpeg_callback(self):
        result=await bridge.run_one_explicit_sdk_session(
            self.ready,stop_event=self.stop,on_frame=self.frames.append,
            explicit_owner_play=True,sdk_session_factory=self.factory)
        self.assertEqual(result["etat"],"arret_utilisateur")
        self.assertEqual(result["tentatives_p2p"],1)
        self.assertEqual(result["jpeg_recues"],1)
        self.assertTrue(result["video_visible_confirmee"])
        self.assertFalse(result["parite_sdk_aosu_native_prouvee"])
        self.assertEqual(self.frames,[JPEG])
        self.assertTrue(FakeActualStream.instances[0].closed)

    async def test_play_not_authorized_never_constructs_session(self):
        with self.assertRaisesRegex(bridge.C9CBackendError,"action_active_non_autorisee"):
            await bridge.run_one_explicit_sdk_session(
                self.ready,stop_event=self.stop,on_frame=self.frames.append,
                explicit_owner_play=False,sdk_session_factory=self.factory)
        self.assertFalse(FakeActualStream.instances)

    async def test_stop_before_start_never_sends_offer(self):
        self.stop.set()
        result=await bridge.run_one_explicit_sdk_session(
            self.ready,stop_event=self.stop,on_frame=self.frames.append,
            explicit_owner_play=True,sdk_session_factory=self.factory)
        self.assertEqual(result["tentatives_p2p"],0)
        self.assertFalse(FakeActualStream.instances)

    async def test_no_rtc_reuse_after_expiry(self):
        self.ready._media.fresh=False
        result=await bridge.run_one_explicit_sdk_session(
            self.ready,stop_event=self.stop,on_frame=self.frames.append,
            explicit_owner_play=True,sdk_session_factory=self.factory)
        self.assertEqual(result["etat"],"rtc_expire_avant_connexion")
        self.assertFalse(FakeActualStream.instances)

    async def test_upstream_error_is_sanitized_and_session_closed(self):
        def fail(*args):
            fake=self.factory(*args)
            fake.fail=True
            return fake
        result=await bridge.run_one_explicit_sdk_session(
            self.ready,stop_event=self.stop,on_frame=self.frames.append,
            explicit_owner_play=True,sdk_session_factory=fail)
        self.assertEqual(result["etat"],"connexion_ou_transport_echoue")
        self.assertFalse(result["video_visible_confirmee"])
        self.assertNotIn("PRIVATE_SECRET",json.dumps(result))
        self.assertTrue(FakeActualStream.instances[0].closed)


if __name__=="__main__":
    unittest.main()
