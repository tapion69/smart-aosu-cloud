"""Offline signal classifier tests; private values cannot appear in output."""
import ast
from pathlib import Path
import runpy
import unittest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
NS=runpy.run_path(str(ROOT/"c9c_mqtt_classify.py"))
classify=NS["classify_observed_signal"]

class ClassifyC9CSignals(unittest.TestCase):
    def test_decryptable_302_video_answer_and_identity(self):
        key=b"1"*16
        private_device="PRIVATE_DEVICE"
        private_uid="PRIVATE_UID"
        def decode(got_key,raw):
            self.assertEqual(got_key,key)
            return 302,{"header":{"type":"answer","from":private_device,
                                  "to":private_uid},"msg":{"sdp":"PRIVATE_SDP"}}
        out=classify(b"2.2"+b"x"*32,key=key,device_id=private_device,
                     uid=private_uid,decoder=decode)
        self.assertEqual(out["protocol"],"302")
        self.assertEqual(out["type"],"answer")
        self.assertTrue(out["decoded"])
        self.assertTrue(out["from_device"])
        self.assertTrue(out["to_user"])
        for secret in (private_device,private_uid,"PRIVATE_SDP"):
            self.assertNotIn(secret,str(out))

    def test_other_formats_and_invalid_decryption(self):
        calls=[]
        def decode(k,r):
            calls.append(1)
            raise ValueError("PRIVATE_KEY_IN_ERROR")
        other=classify(b"OTHER",key=b"a"*16,device_id="device",
                       uid="user",decoder=decode)
        self.assertFalse(other["pv22"])
        self.assertEqual(len(calls),0)
        failed=classify(b"2.2" + b"x"*32,key=b"a"*16,
                        device_id="device",uid="user",decoder=decode)
        self.assertTrue(failed["pv22"])
        self.assertFalse(failed["decoded"])
        self.assertNotIn("PRIVATE",str(failed))
        invalid=classify(b"2.2"+b"x"*32,key=None,
                         device_id="device",uid="user",decoder=decode)
        self.assertFalse(invalid["decoded"])
        self.assertEqual(len(calls),1)

    def test_safe_fixed_enums_and_no_publish(self):
        out=classify(b"2.2"+b"x"*32,key=b"a"*16,
                     device_id="d",uid="u",
                     decoder=lambda *_:(9999,{"header":{"type":"PRIVATE_TYPE",
                                                          "from":"PRIVATE_FROM"}}))
        self.assertEqual(out["protocol"],"other")
        self.assertEqual(out["type"],"other")
        self.assertNotIn("PRIVATE",str(out))
        src=(ROOT/"c9c_mqtt_passive.py").read_text()
        self.assertIn("classify_observed_signal(",src)
        self.assertNotIn("_send_once",src)
        self.assertNotIn("_mqtt_publish",src)
        self.assertNotIn("ptz_maintien",src)
        for file in ("c9c_mqtt_classify.py","c9c_mqtt_passive.py"):
            ast.parse((ROOT/file).read_text(encoding="utf-8"))

if __name__=="__main__":
    unittest.main()
