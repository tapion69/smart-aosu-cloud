"""Offline wiring tests for the beta24 C9C-only IPC v2 read."""
import ast,unittest
from pathlib import Path
COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")
class TestIpcV2B24(unittest.TestCase):
    def test_branch_isolated_before_any_rtc_or_offer(self):
        ast.parse(RTC);ast.parse(INIT)
        idx=RTC.index("if standalone_c9c_ipc_v2_audit:")
        chunk=RTC[idx:RTC.index("rtc_ipc_v4 = (",idx)]
        self.assertIn("read('thing.m.ipc.config.get',{'devId':target})",chunk)
        self.assertIn("return {**out,'etat':'ipc_v2_obtenue'}",chunk)
        self.assertNotIn("run_tuya_mqtt_offer(",chunk)
        self.assertNotIn("inspect_rtc_media(",chunk)
    def test_only_selected_c9c_and_safe_response(self):
        self.assertIn("or standalone_c9c_ipc_v2_audit):",RTC)
        self.assertIn("standalone_c9c_ipc_v2_audit=True",INIT)
        self.assertIn("select_standalone_c9c_key(runtime.data)",INIT)
        self.assertIn("'schema':{key:raw.get(key) is True for key in flags}",INIT)
        self.assertIn("this._ipcV2B24()",UI)
        self.assertNotIn("ptz_maintien",UI)
if __name__=="__main__":unittest.main()
