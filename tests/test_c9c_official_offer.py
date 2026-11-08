"""Passive official MQTT offer structure classification, no network and no private output."""
from pathlib import Path
import unittest
import runpy

BASE=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
classify=runpy.run_path(str(BASE/"c9c_mqtt_classify.py"))["classify_observed_signal"]

class C9COfficialOfferTests(unittest.TestCase):
    def test_official_offer_shape_without_value_leak(self):
        secret="SECRET_MOTO"
        payload={"header":{
            "type":"offer","from":"PRIVATE_USER","to":"PRIVATE_CAMERA",
            "sessionid":"SECRET_SESSION","moto_id":secret,"path":"mqtt",
            "trace_id":"SECRET_TRACE","is_pre":0,"p2p_skill":1635,
            "security_level":3
        },"msg":{"sdp":"v=0\r\na=rtpmap:6001 AES/KCP 330\r\n",
          "preconnect":True,"token":[{"urls":["turn:PRIVATE_ADDRESS"]}],
          "tcp_token":{"credential":"SECRET_TOKEN"},"log":{}}}
        out=classify(b"2.2"+b"a"*28,key=b"1"*16,
            device_id="PRIVATE_CAMERA",uid="PRIVATE_USER",
            decoder=lambda *_:(302,payload))
        for field in ("from_user","to_device","sessionid_present",
           "moto_id_present","path_mqtt","offer_sdp_present","offer_aes_kcp",
           "offer_trace_present","offer_is_pre_zero","offer_p2p_skill_1635",
           "offer_security_level_3","offer_preconnect_true",
           "offer_token_present","offer_tcp_token_present","offer_log_present"):
            self.assertTrue(out[field],field)
        for private in ("SECRET","PRIVATE","AES/KCP","turn:"):
            self.assertNotIn(private,str(out))

    def test_unexpected_wire_values_fail_closed(self):
        payload={"header":{"type":"offer","is_pre":True,"security_level":3.0,
          "p2p_skill":"1635","moto_id":""},"msg":{"sdp":"PRIVATE",
          "token":"PRIVATE_TOKEN","tcp_token":[],"log":"PRIVATE"}}
        out=classify(b"2.2"+b"a"*28,key=b"1"*16,
           device_id="a",uid="b",decoder=lambda *_:(302,payload))
        for field in ("offer_is_pre_zero","offer_security_level_3",
                      "offer_p2p_skill_1635","moto_id_present",
                      "offer_token_present","offer_tcp_token_present",
                      "offer_log_present","offer_aes_kcp"):
            self.assertFalse(out[field],field)
        self.assertNotIn("PRIVATE",str(out))

    def test_no_mqtt_publish_and_retain_guard(self):
        src=(BASE/"c9c_mqtt_passive.py").read_text(encoding="utf-8")
        self.assertIn('if t & 0x01:',src)
        self.assertIn('"abonnement_sortant":False',src)
        self.assertIn('("sortant","smart/mb/out/"+device_id)',src)
        self.assertNotIn("_mqtt_publish",src)
        self.assertNotIn("_send_once",src)

if __name__=="__main__":
    unittest.main()
