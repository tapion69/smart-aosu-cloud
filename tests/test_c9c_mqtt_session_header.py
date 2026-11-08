"""Offline C9C session envelope comparisons, never return private wire values."""
import runpy
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
CLASSIFY=runpy.run_path(str(ROOT/"c9c_mqtt_classify.py"))["classify_observed_signal"]
KEY=b"0"*16

class SessionHeaderTests(unittest.TestCase):
    def test_official_answer_with_sdp(self):
        hidden="PERSONAL_PRIVATE_SESSION"
        def decode(*_):
            return 302,{"header":{
                "type":"answer","from":"device-private","to":"uid-private",
                "path":"mqtt","sessionid":hidden,"moto_id":"MOTO_PRIVATE"},
                "msg":{"sdp":"v=0\r\na=rtpmap:6001 AES/KCP 330\r\n"}}
        o=CLASSIFY(b"2.2"+b"x"*28,key=KEY,device_id="device-private",
                   uid="uid-private",decoder=decode)
        for f in ("decoded","from_device","to_user","path_mqtt",
                  "sessionid_present","moto_id_present",
                  "answer_sdp_present","answer_aes_kcp","answer_to_user"):
            self.assertTrue(o[f],f)
        self.assertEqual(o["protocol"],"302")
        self.assertNotIn(hidden,str(o))
        self.assertNotIn("PRIVATE",str(o))

    def test_candidate_without_moto_and_wrong_destination(self):
        def decode(*_):
            return 302,{"header":{"type":"candidate","from":"device-private",
                                   "to":"different-client","path":"different-path",
                                   "sessionid":"private"},
                        "msg":{"candidate":"PRIVATE_CANDIDATE"}}
        o=CLASSIFY(b"2.2"+b"x"*28,key=KEY,device_id="device-private",
                   uid="uid-private",decoder=decode)
        self.assertTrue(o["candidate_ice_present"])
        self.assertTrue(o["path_other"])
        self.assertFalse(o["to_user"])
        self.assertFalse(o["moto_id_present"])
        self.assertNotIn("PRIVATE",str(o))

if __name__=="__main__":unittest.main()
