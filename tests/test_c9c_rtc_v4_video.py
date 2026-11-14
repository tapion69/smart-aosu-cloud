"""C9C active RTC alignment with native Thing-4; IPC-v4 probes stay read-only."""
import ast
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT/"custom_components"/"smart_aosu_cloud"
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
LIVE=(COMP/"tuya_live_preview.py").read_text(encoding="utf-8")
JS=(COMP/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")

class C9CNativeRTCVideoTests(unittest.TestCase):
    def test_classic_rtc_on_active_c9c_but_v4_kept_for_diagnostics(self):
        tree=ast.parse(RTC)
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
                and n.name=="run_tuya_oem_inventory")
        assign=next(n for n in ast.walk(fn) if isinstance(n,ast.Assign)
                    and any(isinstance(t,ast.Name) and t.id=="rtc_ipc_v4"
                            for t in n.targets))
        expr=ast.Expression(assign.value)
        ast.fix_missing_locations(expr)
        method=compile(expr,"<rtc route>","eval")
        def choice(c9c, v4, wake=False, webrtc=False):
            return eval(method,{"standalone_c9c_video_test":c9c,
                                "standalone_c9c_v4_rtc_audit":v4,
                                "standalone_c9c_wake_only":wake,
                                "standalone_c9c_webrtc_audit":webrtc})
        self.assertFalse(choice(False,False))  # C5L, legacy, H1L
        self.assertFalse(choice(True,False))   # active Thing-4 C9C: classic
        self.assertTrue(choice(False,True))    # IPC-v4 passive
        self.assertTrue(choice(False,False,wake=True))
        self.assertTrue(choice(False,False,webrtc=True))
        self.assertTrue(choice(True,True))     # rejected combined modes upstream

    def test_existing_video_signaling_is_untouched(self):
        self.assertIn("standalone_c9c_video_test=self._standalone_video_test_mode",LIVE)
        self.assertIn("run_tuya_mqtt_offer(",RTC)
        self.assertIn("use_standalone_c9c_moto_id=(standalone_c9c_video_test is True)",RTC)
        self.assertIn("rtc_ipc_v4",RTC)
        self.assertIn("standalone_c9c=(standalone_c9c_video_test is True)",RTC)
        self.assertIn("else 'thing.m.rtc.config.get'",RTC)
        self.assertIn("'rtc_api_source':report.get('rtc_api_source'",LIVE)
        self.assertIn("last.rtc_api_source==='ipc_v4'",JS)
        self.assertNotIn("ptz_maintien",JS)

    def test_syntax(self):
        ast.parse(LIVE)
        ast.parse(RTC)

if __name__=="__main__":
    unittest.main()
