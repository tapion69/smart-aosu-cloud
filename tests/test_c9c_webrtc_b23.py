"""Offline checks for the C9C WebRTC passive beta23 diagnostic."""
import ast
import json
import runpy
import unittest
from pathlib import Path
COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
inspect=runpy.run_path(str(COMP/"c9c_webrtc_probe_b23.py"))["inspect_webrtc_hints"]
CHANNEL=(COMP/"c9c_webrtc_channel_b23.py").read_text(encoding="utf-8")
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")

class TestWebRTCBeta23(unittest.TestCase):
    def test_no_guess_from_uid_or_aes_kcp(self):
        report,msid=inspect({"p2pConfig":{"session":{
            "aesKey":"00"*16,"moto_id":"some-moto"}}},{"supportsWebrtc":True})
        self.assertIsNone(msid)
        self.assertTrue(report["ipc_aes_kcp_present"])
        self.assertTrue(report["moto_id_present"])
        self.assertFalse(report["auth_webrtc_present"])
        self.assertFalse(report["msid_explicite_present"])
        self.assertFalse(report["offre_webrtc_preparee"])
    def test_private_values_never_returned(self):
        raw={"data":{"webrtcConfig":{"motoId":"private-moto",
              "auth":"private-auth","supportsWebrtc":True},
              "mqttConfig":{"msid":"private-msid"}}}
        report,msid=inspect(raw,{})
        self.assertEqual(msid,"private-msid")
        self.assertTrue(report["auth_webrtc_present"])
        self.assertTrue(report["msid_explicite_present"])
        for secret in ("private-moto","private-auth","private-msid"):
            self.assertNotIn(secret,json.dumps(report))
    def test_ambiguous_msid_never_used(self):
        report,msid=inspect({"msid":"test-a","data":{
            "mqttConfig":{"msid":"test-b"}}},{})
        self.assertIsNone(msid)
        self.assertTrue(report["msid_ambigu"])
        self.assertFalse(report["abonnement_mqtt_possible"])
    def test_safe_subscribe_only(self):
        for source in (CHANNEL,RTC,INIT):
            ast.parse(source)
        self.assertNotIn("_mqtt_publish(",CHANNEL)
        self.assertNotIn("send_offer(",CHANNEL)
        self.assertIn("_mqtt_subscribe_packet(",CHANNEL)
        self.assertIn("_COOLDOWN_S=600",CHANNEL)
        self.assertIn("ssl.CERT_REQUIRED",CHANNEL)
        self.assertIn("if standalone_c9c_webrtc_audit and (",RTC)
        self.assertIn("standalone_c9c_video_test or standalone_c9c_wake_then_video",RTC)
        self.assertIn("standalone_c9c_webrtc_audit=True",INIT)
        self.assertIn("this._webrtc(true)",UI)
        self.assertIn("this._webrtc(false)",UI)
        self.assertNotIn("ptz_maintien",UI)

if __name__=="__main__":unittest.main()
