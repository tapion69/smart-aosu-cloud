"""Offline wiring guardrails for one-click C9C beta31 report."""
import ast,unittest
from pathlib import Path
COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
INV=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
JS=(COMP/"frontend/c9c-autonome-b1.js").read_text(encoding="utf-8")
SVC=(COMP/"services.yaml").read_text(encoding="utf-8")
HELP=(COMP/"c9c_full_audit_b31.py").read_text(encoding="utf-8")
class TestCompleteWiring(unittest.TestCase):
    def test_isolated_before_video(self):
        for source in (INV,INIT,HELP):
            ast.parse(source)
        self.assertIn("standalone_c9c_full_audit_b31:bool=False",INV)
        ix=INV.index("if standalone_c9c_full_audit_b31:",INV.index("out['methode_selection_rtc']"))
        end=INV.index("if standalone_c9c_tuya_detail_audit:",ix)
        block=INV[ix:end]
        self.assertIn("run_full_c9c_audit_b31(",block)
        self.assertIn("return {**out,'etat':(",block)
        for forbidden in ("run_tuya_mqtt_offer(","try_wake_c9c","publishDevice("):
            self.assertNotIn(forbidden,block)
    def test_explicit_consent_and_safe_response(self):
        self.assertIn("standalone_c9c_full_audit_b31=True",INIT)
        self.assertIn("select_standalone_c9c_key(runtime.data)",INIT)
        self.assertIn("'diagnostiquer_c9c_complet_b31'",INIT)
        self.assertIn("'etapes':steps,'identite':identity",INIT)
        self.assertIn("'identifiants_retournes':False",INIT)
        self.assertIn('id="fullb31"',JS)
        self.assertIn("this._fullB31()",JS)
        self.assertIn("lines.join('\\n')",JS)
        self.assertIn("diagnostiquer_c9c_complet_b31:",SVC)
        for bad in ("run_tuya_mqtt_offer(","socket.create_connection(","send_offer("):
            self.assertNotIn(bad,HELP)
if __name__=="__main__":unittest.main()
