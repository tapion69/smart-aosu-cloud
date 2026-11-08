"""Offline checks for opt-in wake-then-video wiring; no Tuya calls."""
import ast
import unittest
from pathlib import Path

COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
LIVE=(COMP/"tuya_live_preview.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
JS=(COMP/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")

class TestWakeThenVideo(unittest.TestCase):
    def test_only_explicit_manual_c9c(self):
        self.assertIn("standalone_c9c_wake_then_video:bool=False",RTC)
        self.assertIn("if standalone_c9c_wake_then_video and (",RTC)
        self.assertIn("standalone_c9c_video_test is not True or interactive_live is not True",RTC)
        self.assertIn("standalone_c9c_wake_then_video=self._standalone_wake_then_video",LIVE)
        self.assertIn("call.data.get('confirmation_reveil_et_video') is True",INIT)
        self.assertIn("this._play(true)",JS)
        self.assertIn("this._play(false)",JS)
    def test_awake_must_be_seen_before_offer(self):
        offer=(COMP/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
        wake=(COMP/"c9c_wake_probe.py").read_text(encoding="utf-8")
        self.assertIn("wake_before_offer=standalone_c9c_wake_then_video",RTC)
        self.assertIn("try_wake_c9c_on_open_socket(",offer)
        self.assertIn("sock.sendall(_mqtt_publish(topic, payload, 2))",wake)
        self.assertIn("if not awake:",offer)
        self.assertIn("'reveil_non_confirme_offre_non_envoyee'",offer)
        self.assertIn("result['reveil_et_video']['puback_offre']=True",offer)
        self.assertIn("out['reveil_et_video']",RTC)
        ast.parse(offer)
        ast.parse(wake)
    def test_no_other_video_path_changed(self):
        self.assertIn("if standalone_c9c_wake_then_video and not standalone_c9c_video_test:",LIVE)
        self.assertIn("use_standalone_c9c_moto_id=(standalone_c9c_video_test is True)",RTC)
        self.assertIn("standalone_c9c_wake_then_video=(",INIT)
        self.assertNotIn("ptz_maintien",JS)
        ast.parse(RTC)
        ast.parse(LIVE)
        ast.parse(INIT)
if __name__=="__main__":unittest.main()
