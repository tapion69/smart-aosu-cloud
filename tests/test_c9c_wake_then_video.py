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
        start=RTC.index("if standalone_c9c_wake_then_video:\n                # Use")
        end=RTC.index("if tester_offre_mqtt is True and private is not None:",start)
        block=RTC[start:end]
        self.assertIn("wake=try_wake_c9c_once(",block)
        self.assertIn("wake.get('puback_wake') is True",block)
        self.assertIn("wake_count > 0",block)
        self.assertIn("if not awake:",block)
        self.assertIn("return out",block)
        self.assertIn("out['reveil_et_video']",block)
    def test_no_other_video_path_changed(self):
        self.assertIn("if standalone_c9c_wake_then_video and not standalone_c9c_video_test:",LIVE)
        self.assertIn("use_standalone_c9c_moto_id=(standalone_c9c_video_test is True)",RTC)
        self.assertIn("standalone_c9c_wake_then_video=(",INIT)
        self.assertNotIn("ptz_maintien",JS)
        ast.parse(RTC)
        ast.parse(LIVE)
        ast.parse(INIT)
if __name__=="__main__":unittest.main()
