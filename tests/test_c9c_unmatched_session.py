"""Offline checks for redacted mismatched C9C MQTT messages."""
from pathlib import Path
import runpy
import unittest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
classify=runpy.run_path(str(ROOT/"c9c_session_classify.py"))["classify_unmatched_c9c_message"]

class TestC9CUnmatchedSignals(unittest.TestCase):
    def test_previous_session_answer_redacted(self):
        o=classify(302,{"header":{"type":"answer","sessionid":"PREVIOUS_PRIVATE",
            "from":"PRIVATE_CAMERA","to":"PRIVATE_UID"},
            "msg":{"sdp":"PRIVATE_SDP"}},
            expected_session="CURRENT",expected_device="PRIVATE_CAMERA",
            expected_uid="PRIVATE_UID")
        self.assertEqual(o["kind"],"answer")
        self.assertEqual(o["session_state"],"differente")
        self.assertTrue(o["answer_sdp_present"])
        self.assertTrue(o["from_device"])
        for value in ("PREVIOUS_PRIVATE","PRIVATE_CAMERA","PRIVATE_UID","PRIVATE_SDP"):
            self.assertNotIn(value,str(o))

    def test_non302_numeric_buckets_and_known_kind(self):
        for v,label in [(6,"0_99"),(218,"100_299"),(356,"300_399"),
                        (405,"autre"),("356","autre"),(True,"autre")]:
            with self.subTest(v=v):
                o=classify(v,{"header":{"type":"candidate"}},
                    expected_session="a",expected_device="b",expected_uid="c")
                self.assertEqual(o["protocol_bucket"],label)
                self.assertEqual(o["kind"],"candidate")

    def test_never_bypass_matching_session(self):
        o=classify(302,{"header":{"sessionid":"CURRENT"}},
            expected_session="CURRENT",expected_device="b",expected_uid="c")
        self.assertEqual(o["session_state"],"identique")
        self.assertFalse(o["answer_sdp_present"])

    def test_route_only_used_under_manual_moto_guard(self):
        src=(ROOT/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
        self.assertIn("if use_moto_id:",src)
        self.assertIn("classify_unmatched_c9c_message(",src)
        self.assertIn("if header.get('sessionid')!=media.session_id:",src)
        self.assertIn("diag['reponses_session_incorrecte']+=1",src)

if __name__=="__main__":
    unittest.main()
