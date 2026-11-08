"""Offline sanity checks for the opt-in IPC-v4 RTC inspection branch."""
from pathlib import Path
import ast
import unittest

ROOT=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
INV=(ROOT/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
INIT=(ROOT/"__init__.py").read_text(encoding="utf-8")
FRONT=(ROOT/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")

class V4AuditSafetyTests(unittest.TestCase):
    def test_manual_only_and_default_preserved(self):
        self.assertIn("standalone_c9c_v4_rtc_audit:bool=False",INV)
        self.assertIn("if standalone_c9c_v4_rtc_audit and (",INV)
        self.assertIn("if standalone_c9c_v4_rtc_audit:\n",INV)
        self.assertIn("'m.ipc.v4.rtc.config.get' if standalone_c9c_v4_rtc_audit",INV)
        self.assertIn("else 'thing.m.rtc.config.get'",INV)
        self.assertIn("or standalone_c9c_v4_rtc_audit):",INV)
        self.assertIn("client._tuya_oem_media_bootstrap=None",INV)

    def test_service_does_not_send_offer(self):
        self.assertIn("async def comparer_rtc_ipc_v4_c9c_autonome(call):",INIT)
        self.assertIn("standalone_c9c_v4_rtc_audit=True,tester_mqtt=False",INIT)
        self.assertIn("tester_offre_mqtt=False,tester_relais_tcp=False",INIT)
        self.assertIn("if runtime.live_controller.running:",INIT)
        self.assertIn("supports_response=SupportsResponse.ONLY",INIT)
        self.assertNotIn("ptz_maintien",FRONT)

    def test_syntax(self):
        ast.parse(INV)
        ast.parse(INIT)

if __name__=="__main__":
    unittest.main()
