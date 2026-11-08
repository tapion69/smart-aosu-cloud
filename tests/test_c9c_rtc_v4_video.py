"""Offline RTC-v4 route regression tests for C9C manual video only."""
import ast
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT/"custom_components"/"smart_aosu_cloud"
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
LIVE=(COMP/"tuya_live_preview.py").read_text(encoding="utf-8")
JS=(COMP/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")

class C9CIPCV4VideoTests(unittest.TestCase):
    def test_route_is_scoped_to_manual_c9c_or_passive_v4(self):
        tree=ast.parse(RTC)
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
                and n.name=="run_tuya_oem_inventory")
        assign=next(n for n in ast.walk(fn) if isinstance(n,ast.Assign)
                    and any(isinstance(t,ast.Name) and t.id=="rtc_ipc_v4"
                            for t in n.targets))
        expr=ast.Expression(assign.value)
        ast.fix_missing_locations(expr)
        method=compile(expr,"<rtc route>","eval")
        def choice(c9c, v4):
            return eval(method,{"standalone_c9c_video_test":c9c,
                                "standalone_c9c_v4_rtc_audit":v4})
        self.assertFalse(choice(False,False))  # C5L, legacy, H1L
        self.assertTrue(choice(True,False))    # manual C9C
        self.assertTrue(choice(False,True))    # passive v4
        self.assertTrue(choice(True,True))     # guarded combination elsewhere

    def test_existing_video_signaling_is_untouched(self):
        self.assertIn("standalone_c9c_video_test=self._standalone_video_test_mode",LIVE)
        self.assertIn("run_tuya_mqtt_offer(",RTC)
        self.assertIn("use_standalone_c9c_moto_id=(standalone_c9c_video_test is True)",RTC)
        self.assertIn("rtc_ipc_v4",RTC)
        self.assertIn("'rtc_api_source':report.get('rtc_api_source'",LIVE)
        self.assertIn("last.rtc_api_source==='ipc_v4'",JS)
        self.assertNotIn("ptz_maintien",JS)

    def test_syntax(self):
        ast.parse(LIVE)
        ast.parse(RTC)

if __name__=="__main__":
    unittest.main()
