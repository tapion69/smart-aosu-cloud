"""Offline C9C MQTT provenance tests: no credentials, network or real camera."""
from __future__ import annotations
import ast
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/"custom_components"/"smart_aosu_cloud"
P=BASE/"c9c_thing4_mqtt_evidence.py"
spec=importlib.util.spec_from_file_location("test_c9c_thing4_mqtt_evidence_lib",P)
m=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=m
spec.loader.exec_module(m)
Observer=m.C9CMqttSessionEvidence
CAM="PRIVATE_CAMERA_DEVICE_1"
UID="PRIVATE_USER_ACCOUNT_1"
SID="PRIVATE_REAL_SESSION_1"
SDP=("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n"
     "m=application 9 imm 6001\r\n"
     "a=rtpmap:6001 AES/KCP 330\r\n"
     "a=ice-ufrag:PRIVATE\r\na=ice-pwd:PRIVATE\r\n")


def signal(kind="answer",*,sender=CAM,recipient=UID,session=SID,sdp=SDP):
    return ({"type":kind,"from":sender,"to":recipient,"sessionid":session,
             "path":"mqtt"},
            {"sdp":sdp} if kind=="answer" else
            {"candidate":"candidate:1 1 UDP 1 127.0.0.1 1000 typ host"} if kind=="candidate"
            else {})


class TestC9CMqttEvidence(unittest.TestCase):
    def observer(self):
        v=Observer(CAM,UID,SID)
        v.mark_offer_sent()
        return v

    def test_exact_answer_after_offer_is_observed_not_connected(self):
        v=self.observer()
        h,msg=signal()
        self.assertEqual(v.classify(302,h,msg),
                         "reponse_sdp_liee_a_notre_session")
        status=v.safe_status()
        self.assertTrue(status["reponse_sdp_origine_verifiee"])
        self.assertFalse(status["connexion_p2p_authentifiee"])
        self.assertFalse(status["image_decodee"])
        self.assertFalse(status["video_confirmee"])
        self.assertFalse(status["SDK_Thing4_initialise"])

    def test_wrong_sender_rejected_even_with_matching_session(self):
        v=self.observer()
        h,msg=signal(sender="ANOTHER_DEVICE_PRIVATE_1")
        self.assertEqual(v.classify(302,h,msg),
                         "origine_ou_destination_incorrecte")
        self.assertFalse(v.safe_status()["reponse_sdp_origine_verifiee"])
        self.assertEqual(v.safe_status()["reponses_origine_invalide"],1)

    def test_wrong_recipient_rejected_even_with_matching_session(self):
        v=self.observer()
        h,msg=signal(recipient="ANOTHER_USER_PRIVATE_1")
        self.assertEqual(v.classify(302,h,msg),
                         "origine_ou_destination_incorrecte")
        self.assertFalse(v.safe_status()["reponse_sdp_origine_verifiee"])

    def test_missing_sender_or_recipient_are_not_accepted(self):
        for key in ("from","to"):
            with self.subTest(key=key):
                v=self.observer()
                h,msg=signal()
                del h[key]
                self.assertEqual(v.classify(302,h,msg),
                                 "origine_ou_destination_incorrecte")

    def test_old_session_answer_rejected(self):
        v=self.observer()
        h,msg=signal(session="OLD_PRIVATE_SESSION_2")
        self.assertEqual(v.classify(302,h,msg),"autre_session")
        self.assertEqual(v.safe_status()["reponses_autre_session"],1)
        self.assertFalse(v.safe_status()["reponse_sdp_origine_verifiee"])

    def test_mqtt_puback_not_a_camera_response(self):
        v=self.observer()
        v.mark_puback(11)
        self.assertTrue(v.safe_status()["puback_broker"])
        self.assertFalse(v.safe_status()["reponse_sdp_origine_verifiee"])
        self.assertFalse(v.safe_status()["video_confirmee"])

    def test_unexpected_packet_id_is_not_offer_puback(self):
        v=self.observer()
        for value in (10,12,0,None,"11",True):
            v.mark_puback(value)
        self.assertFalse(v.safe_status()["puback_broker"])

    def test_no_offer_no_valid_signal_or_ack(self):
        v=Observer(CAM,UID,SID)
        h,msg=signal()
        self.assertEqual(v.classify(302,h,msg),"offre_non_envoyee")
        v.mark_puback(11)
        self.assertFalse(v.safe_status()["puback_broker"])

    def test_candidates_and_disconnect_require_exact_provenance(self):
        v=self.observer()
        h,msg=signal("candidate",sender="WRONG_PRIVATE_DEVICE")
        self.assertEqual(v.classify(302,h,msg),
                         "origine_ou_destination_incorrecte")
        h,msg=signal("candidate")
        self.assertEqual(v.classify(302,h,msg),"candidat_confirme")
        self.assertEqual(v.safe_status()["candidats_origine_verifiee"],1)
        h,msg=signal("disconnect",recipient="DIFFERENT_USER")
        self.assertEqual(v.classify(302,h,msg),
                         "origine_ou_destination_incorrecte")
        self.assertFalse(v.safe_status()["deconnexion_distante_confirmee"])
        h,msg=signal("disconnect")
        self.assertEqual(v.classify(302,h,msg),"deconnexion_confirmee")
        self.assertTrue(v.safe_status()["deconnexion_distante_confirmee"])

    def test_wrong_protocol_does_not_count(self):
        v=self.observer()
        h,msg=signal()
        for p in (22,301,"302",None,True,302.0):
            self.assertEqual(v.classify(p,h,msg),"protocole_non_302")
        self.assertFalse(v.safe_status()["reponse_sdp_origine_verifiee"])

    def test_malformed_or_misrouted_answer_never_reaches_media(self):
        for bad_sdp in ("", "PRIVATE", "v=0\r\nAES/KCP",
                        "v=0"+"A"*20000, None):
            with self.subTest(kind=type(bad_sdp).__name__):
                v=self.observer()
                h,msg=signal(sdp=bad_sdp)
                self.assertEqual(v.classify(302,h,msg),
                                 "reponse_sdp_incompatible")
                self.assertFalse(v.safe_status()["reponse_sdp_origine_verifiee"])

    def test_unexpected_types_are_discarded(self):
        v=self.observer()
        for kind in ("offer","start","unknown",42,None):
            h,msg=signal(kind)
            self.assertEqual(v.classify(302,h,msg),"type_non_pertinent")

    def test_no_secret_or_vendor_string_in_status_or_repr(self):
        v=self.observer()
        h,msg=signal()
        v.classify(302,h,msg)
        blob=json.dumps(v.safe_status())+repr(v)
        for private in (CAM,UID,SID,"PRIVATE","AES/KCP"):
            self.assertNotIn(private,blob)
        self.assertFalse(v.safe_status()["identifiants_retournes"])

    def test_invalid_ids_fail_before_probe(self):
        for values in ((None,UID,SID),(CAM,None,SID),
                       (CAM,UID,""),(" ",UID,SID)):
            with self.subTest(values=[str(x)[:1] for x in values]):
                with self.assertRaises(ValueError):
                    Observer(*values)

    def test_offer_route_only_c9c_and_before_media(self):
        s=(BASE/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
        self.assertIn("if use_moto_id else None",s)
        self.assertIn("C9CMqttSessionEvidence(",s)
        self.assertIn("c9c_evidence.mark_offer_sent()",s)
        self.assertIn("c9c_evidence.mark_puback(11)",s)
        self.assertIn("c9c_evidence.classify(protocol,header,msg)",s)
        self.assertIn("if verdict == 'origine_ou_destination_incorrecte'",s)
        self.assertIn("if verdict == 'reponse_sdp_incompatible'",s)
        self.assertLess(s.index("c9c_evidence.classify(protocol,header,msg)"),
                        s.index("result['reponse_sdp_recue']=True"))
        self.assertLess(s.index("if verdict == 'origine_ou_destination_incorrecte'"),
                        s.index("result['reponse_sdp_recue']=True"))
        self.assertIn("def finish_probe()",s)
        self.assertIn("c9c_evidence.safe_status() if c9c_evidence is not None",s)
        self.assertIn("return finish_probe()",s)
        ast.parse(s)


if __name__=="__main__":
    unittest.main()
