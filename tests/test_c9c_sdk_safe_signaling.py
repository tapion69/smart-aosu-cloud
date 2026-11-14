"""Safeguards for actual upstream 0.1.3 Tuya MQTT, entirely offline.

Exercises real MotoClient/StreamSession classes, but uses fake broker transport
and synthetic encrypted signaling frames; no camera, SDK login or network.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import types
import unittest

from tuya_ipc_p2p_sdk.models import MqttIdentity
from tuya_ipc_p2p_sdk.signaling.envelope import encode_payload
from tuya_ipc_p2p_sdk.models import StreamConfig

DIR=Path(__file__).resolve().parents[1]/"custom_components"/"smart_aosu_cloud"
package=sys.modules.get("smart_aosu_cloud")
if package is None:
    package=types.ModuleType("smart_aosu_cloud")
    package.__path__=[str(DIR)]
    sys.modules["smart_aosu_cloud"]=package
spec=importlib.util.spec_from_file_location(
    "smart_aosu_cloud.c9c_sdk_safe_signaling",
    DIR/"c9c_sdk_safe_signaling.py")
safe=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=safe
spec.loader.exec_module(safe)

DEV="SYNTHETIC_DEVICE_UID_123"
USER="SYNTHETIC_ACCOUNT_UID_123"
SESSION="SYNTHETIC_SESSION_ID_123"
KEY="ABCD"*4
MOTO="SYNTHETIC_MOTO_ID_123"
IDENTITY=MqttIdentity(
    host="m1.tuyaeu.com",
    port=8883,
    client_id="SYNTHETIC_CLIENT_ID",
    username="SYNTHETIC_USER",
    password="SYNTHETIC_PASSWORD")


def client(on_answer=None, moto=MOTO):
    return safe.SafeAosuMotoClient(
        identity=IDENTITY,uid=USER,device_id=DEV,
        session_id=SESSION,local_key=KEY,
        on_answer=on_answer or (lambda s:None),
        on_candidate=lambda s:None,
        on_disconnect=lambda n:None,
        moto_id=moto)


def frame(sender=DEV,recipient=USER,session=SESSION,kind="answer"):
    return encode_payload(
        KEY.encode(),42,b"ABCD",
        {"header":{"type":kind,"from":sender,"to":recipient,
                   "sessionid":session,"moto_id":MOTO},
         "msg":{"sdp":"v=0\r\nFAKE_SDP"}},1234567890,302)


class FakeBroker:
    arguments=[]
    def __init__(self,**kwargs):
        self.kwargs=kwargs
        self.__class__.arguments.append(kwargs)
        self.subscriptions=[]
        self.closed=False
    async def __aenter__(self):return self
    async def __aexit__(self,*args):self.closed=True
    async def subscribe(self,topic,qos):
        self.subscriptions.append((topic,qos))


class TestVerifiedVendorMoto(unittest.IsolatedAsyncioTestCase):
    def test_cryptographic_envelope_accepts_only_exact_camera_and_session(self):
        answers=[]
        moto=client(answers.append)
        moto._consume(frame())
        self.assertEqual(answers,["v=0\r\nFAKE_SDP"])
        for kwargs in (
            {"sender":"OTHER_CAMERA"},{"recipient":"OTHER_USER"},
            {"session":"OLD_SESSION"},
            {"sender":""},{"recipient":""},{"session":""},
        ):
            moto._consume(frame(**kwargs))
        self.assertEqual(answers,["v=0\r\nFAKE_SDP"])

    def test_malformed_encrypted_signal_never_becomes_callback(self):
        received=[]
        moto=client(received.append)
        for blob in (b"",b"not-an-envelope",b"2.2"+b"\x00"*30):
            moto._consume(blob)
        self.assertEqual(received,[])

    def test_moto_id_is_preserved_from_synthetic_aosu_rtc(self):
        moto=client()
        self.assertEqual(moto._header("offer")["moto_id"],MOTO)
        self.assertEqual(moto._header("disconnect")["moto_id"],MOTO)
        self.assertEqual(client(moto="bad space")._header("offer")["moto_id"],"")
        self.assertNotIn(MOTO,repr(moto))

    async def test_tls_context_verifies_host_and_certificate(self):
        old=safe.aiomqtt.Client
        FakeBroker.arguments.clear()
        safe.aiomqtt.Client=FakeBroker
        moto=client()
        async def reader():
            await asyncio.Event().wait()
        moto._async_read=reader
        try:
            await moto.async_connect()
            self.assertEqual(len(FakeBroker.arguments),1)
            options=FakeBroker.arguments[0]
            tls=options["tls_context"]
            self.assertEqual(tls.verify_mode,ssl.CERT_REQUIRED)
            self.assertTrue(tls.check_hostname)
            self.assertEqual(options["hostname"],"m1.tuyaeu.com")
            self.assertEqual(moto._client.subscriptions,
                             [(f"smart/mb/in/{DEV}",1)])
            await moto.async_close()
        finally:
            safe.aiomqtt.Client=old
        self.assertTrue(moto._client is None)

    async def test_rejected_broker_has_fixed_safe_error(self):
        class RefusingBroker(FakeBroker):
            async def __aenter__(self):
                raise OSError("PRIVATE_ENDPOINT_AND_CREDENTIAL")
        old=safe.aiomqtt.Client
        safe.aiomqtt.Client=RefusingBroker
        try:
            with self.assertRaisesRegex(ValueError,
                    "^c9c_signalisation_tls_ou_mqtt_refusee$"):
                await client().async_connect()
        finally:
            safe.aiomqtt.Client=old

    async def test_oem_moto_id_in_relay_offer_and_candidate(self):
        # The upstream SDK 0.1.3 uses moto_id="" in relay_frames.py.
        # Our AOSU subclass must not lose it after MQTT signaling.
        source={"p2pConfig":{
            "session":{
                "sessionId":SESSION,"aesKey":"af"*16,
                "iceUfrag":"ICEFAKE","icePassword":"ICEPASSFAKE",
            },
            "tcpRelay":{
                "username":"2000000000:test",
                "credential":"synthetic_credential",
                "sessionId":"SERVER_SESSION",
                "urls":["tcp4:relay.example.test:1443"],
            }, "ices":[]},
            "password":"SYNTHETIC_DEVICE_PASSWORD",
            "motoId":MOTO}
        config=StreamConfig.from_json(source,DEV,KEY)
        session=safe.SafeAosuStreamSession(config,IDENTITY,USER,lambda x:None)
        class FakeRelay:
            def __init__(self):self.sent=[]
            def send_tunnel_frame(self,key,data):self.sent.append((key,data))
        relay=FakeRelay()
        session._relay=relay
        session._candidates=["candidate:1 1 UDP 1 127.0.0.1 1000 typ host"]
        token=config.relay_token.with_session_id("SYNTHETIC_NEW_RENDEZVOUS")
        offer=types.SimpleNamespace(
            aes_key=bytes.fromhex("af"*16),session_id=SESSION,sdp="v=0\r\n")
        session._tunnel_signaling(offer,"TRACE_FAKE",token)
        self.assertEqual(len(relay.sent),2)
        decoded=[json.loads(payload) for _,payload in relay.sent]
        self.assertEqual([x["header"]["type"] for x in decoded],
                         ["offer","candidate"])
        self.assertEqual([x["header"]["moto_id"] for x in decoded],
                         [MOTO,MOTO])
        self.assertEqual(decoded[0]["header"]["path"],"relay")
        self.assertEqual(decoded[0]["msg"]["tcp_token"]["sessionId"],
                         "SYNTHETIC_NEW_RENDEZVOUS")
        # No sockets, no MQTT login, and no camera call.
        session._relay=None
        await session.async_close()

    async def test_real_sdk_stream_session_is_constructible_without_network(self):
        source={"p2pConfig":{
            "session":{
                "sessionId":SESSION,"aesKey":"af"*16,
                "iceUfrag":"ICEFAKE", "icePassword":"ICEPASSFAKE",
            },
            "tcpRelay":{
                "username":"2000000000:test",
                "credential":"synthetic_credential",
                "sessionId":"SERVER_SESSION",
                "urls":["tcp4:relay.example.test:1443"],
            }, "ices":[]},
            "password":"SYNTHETIC_DEVICE_PASSWORD",
            "motoId":MOTO}
        config=StreamConfig.from_json(source,DEV,KEY)
        session=safe.SafeAosuStreamSession(config,IDENTITY,USER,lambda x:None)
        self.assertEqual(session.frame_count,0)
        self.assertIsNone(session._moto)
        # No async_start, so no socket, no offer, no account call.
        await session.async_close()
        self.assertTrue(session._closing)


if __name__=="__main__":
    unittest.main()
