"""Synthetic, no-camera tests for future Thing-4 session-state adapter."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

BASE = Path(__file__).resolve().parents[1] / "custom_components" / "smart_aosu_cloud"
PATH = BASE / "c9c_thing4_session_state.py"
SPEC = importlib.util.spec_from_file_location("c9c_thing4_session_state_test", PATH)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)

Session = module.Thing4C9CSession
Phase = module.Phase
Error = module.SessionStateError
DEV = "TUYA_DEVICE_PRIVATE_SAMPLE"
SID = "RTC_SESSION_PRIVATE_SAMPLE"


def identified():
    session = Session()
    session.bind(
        tuya_device_id=DEV,
        selection="identite_exacte_cp_device_id_dev_id",
        aosu_c9c_unique=True,
    )
    return session


def ready():
    session = identified()
    session.configure(
        rtc_device_id=DEV, session_id=SID, p2p_specified_type=4,
        local_key_present=True, config_present=True, now=0,
    )
    return session


class C9CThing4SessionStateTests(unittest.TestCase):

    def test_no_network_or_transport_in_module(self):
        source = PATH.read_text()
        for forbidden in ("import requests", "import socket",
                          "import aiohttp", "import subprocess",
                          "mqtt.publish(", "asyncio.create_task(", "open("):
            self.assertNotIn(forbidden, source)
        self.assertFalse(Session().safe_status()["transport_reel_implemente"])

    def test_strong_typed_identity_only(self):
        for label in (
            "identite_exacte_serie",
            "identite_exacte_cp_device_id",
            "identite_exacte_cp_device_id_dev_id",
            "identite_exacte_ty_cp_uuid",
        ):
            with self.subTest(label=label):
                session = Session()
                session.bind(tuya_device_id=DEV, selection=label,
                             aosu_c9c_unique=True)
                self.assertEqual(session.phase, Phase.IDENTIFIED)

    def test_weak_or_missing_identity_cannot_start(self):
        for label in (
            "appareil_tuya_unique_sans_categorie_video",
            "camera_tuya_unique_non_confirmee", "", "identite_exacte",
            "identite_exacte_inconnue",
        ):
            with self.subTest(label=label):
                session = Session()
                with self.assertRaisesRegex(Error, "^identite_c9c_non_prouvee$"):
                    session.bind(tuya_device_id=DEV, selection=label,
                                 aosu_c9c_unique=True)
                self.assertEqual(session.phase, Phase.NEW)

    def test_aosu_topology_not_standalone_is_refused(self):
        with self.assertRaises(Error):
            Session().bind(tuya_device_id=DEV,
                           selection="identite_exacte_cp_device_id_dev_id",
                           aosu_c9c_unique=False)

    def test_cannot_configure_mismatched_tuya_device(self):
        session = identified()
        with self.assertRaisesRegex(Error,"configuration_c9c_non_conforme"):
            session.configure(
                rtc_device_id="OTHER_TUYA_DEVICE", session_id=SID,
                p2p_specified_type=4, local_key_present=True,
                config_present=True,
            )
        self.assertEqual(session.phase, Phase.IDENTIFIED)

    def test_cannot_configure_wrong_p2p_type_or_incomplete_data(self):
        variants = [
            {"p2p_specified_type":2},
            {"p2p_specified_type":True},
            {"local_key_present":False},
            {"config_present":False},
            {"session_id":""},
            {"session_id":"SESSION WITH SPACES"},
        ]
        original = dict(
            rtc_device_id=DEV, session_id=SID, p2p_specified_type=4,
            local_key_present=True, config_present=True, now=0,
        )
        for changed in variants:
            with self.subTest(changed=list(changed)):
                session = identified()
                with self.assertRaises(Error):
                    session.configure(**dict(original,**changed))

    def test_full_verified_sequence_only_first_frame_proves_video(self):
        session=ready()
        self.assertFalse(session.safe_status()["video_confirmee"])
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_offer_sent(now=3)
        session.on_mqtt_puback()
        self.assertEqual(session.phase,Phase.OFFER_SENT)
        self.assertTrue(session.safe_status()["broker_puback_observe"])
        self.assertFalse(session.safe_status()["connexion_authentifiee"])
        session.on_sdp_answer(from_device_id=DEV, session_id=SID,
                              validated=True, now=4)
        self.assertEqual(session.phase,Phase.ANSWER_RECEIVED)
        session.on_connect_confirmed(authenticated=True,now=5)
        self.assertEqual(session.phase,Phase.CONNECTED)
        self.assertFalse(session.safe_status()["video_confirmee"])
        session.on_media_frame(decoded=True,now=6)
        self.assertEqual(session.phase,Phase.STREAMING)
        self.assertTrue(session.safe_status()["video_confirmee"])
        self.assertTrue(session.safe_status()["au_moins_une_image_decodee"])

    def test_connect_callback_before_answer_is_tolerated(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_connect_confirmed(authenticated=True,now=3)
        self.assertEqual(session.phase,Phase.CONNECTING)
        session.on_offer_sent(now=4)
        session.on_sdp_answer(from_device_id=DEV,session_id=SID,
                              validated=True,now=5)
        self.assertEqual(session.phase,Phase.CONNECTED)

    def test_spurious_sdp_answer_before_offer_refused(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        with self.assertRaisesRegex(Error,"transition_interdite"):
            session.on_sdp_answer(from_device_id=DEV,session_id=SID,
                                  validated=True,now=3)

    def test_mismatched_or_unvalidated_answer_refused_without_leak(self):
        for from_id, session_id, checked in (
            (DEV,"OTHER_SESSION",True),
            ("OTHER_DEVICE",SID,True),
            (DEV,SID,False),
        ):
            session=ready()
            session.on_device_created(success=True,now=1)
            session.on_connect_started(now=2)
            session.on_offer_sent(now=3)
            with self.assertRaisesRegex(Error,"reponse_sdp_non_associee"):
                session.on_sdp_answer(from_device_id=from_id,
                    session_id=session_id,validated=checked,now=4)
            self.assertEqual(session.phase,Phase.OFFER_SENT)
            self.assertFalse(session.safe_status()["reponse_sdp_validee"])

    def test_http_accepted_or_mqtt_puback_never_proves_connection(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_offer_sent(now=3)
        session.on_mqtt_puback()
        self.assertEqual(session.safe_status()["phase"],"offre_emise")
        self.assertFalse(session.safe_status()["video_confirmee"])
        self.assertFalse(session.safe_status()["connexion_authentifiee"])

    def test_authentication_failure_erases_identifiers(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_connect_confirmed(authenticated=False,now=3)
        self.assertEqual(session.phase,Phase.FAILED)
        status=session.safe_status()
        self.assertFalse(status["cible_exacte_verifiee"])
        self.assertNotIn(DEV,str(status))
        self.assertNotIn(SID,str(session))

    def test_expiry_erases_identifiers_and_prevents_offer(self):
        session=ready()
        with self.assertRaisesRegex(Error,"configuration_expiree"):
            session.on_device_created(success=True,now=91)
        self.assertEqual(session.phase,Phase.FAILED)
        self.assertFalse(session.safe_status()["cible_exacte_verifiee"])

    def test_preview_without_real_answer_is_refused(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_offer_sent(now=3)
        with self.assertRaisesRegex(Error,"transition_interdite"):
            session.on_media_frame(decoded=True,now=4)

    def test_invalid_frame_does_not_prove_video(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_offer_sent(now=3)
        session.on_sdp_answer(from_device_id=DEV,session_id=SID,
                              validated=True,now=4)
        session.on_connect_confirmed(authenticated=True,now=5)
        with self.assertRaisesRegex(Error,"image_non_decodee"):
            session.on_media_frame(decoded=False,now=6)
        self.assertFalse(session.safe_status()["video_confirmee"])

    def test_stop_clears_all_session_flags(self):
        session=ready()
        session.on_device_created(success=True,now=1)
        session.on_connect_started(now=2)
        session.on_offer_sent(now=3)
        session.on_mqtt_puback()
        session.on_sdp_answer(from_device_id=DEV,session_id=SID,
                              validated=True,now=4)
        session.on_connect_confirmed(authenticated=True,now=5)
        session.on_media_frame(decoded=True,now=6)
        session.stop()
        status=session.safe_status()
        self.assertEqual(status["phase"],"arretee")
        for key in ("cible_exacte_verifiee","broker_puback_observe",
                    "reponse_sdp_validee","connexion_authentifiee",
                    "au_moins_une_image_decodee","video_confirmee"):
            self.assertFalse(status[key])
        with self.assertRaises(Error):
            session.on_offer_sent()

    def test_private_metadata_never_leaks_from_repr_or_status(self):
        session=ready()
        joined=json.dumps(session.safe_status())+repr(session)
        for secret in (DEV,SID):
            self.assertNotIn(secret,joined)
        self.assertFalse(session.safe_status()["identifiants_retournes"])
        self.assertFalse(session.safe_status()["secrets_retournes"])


if __name__ == "__main__":
    unittest.main()
