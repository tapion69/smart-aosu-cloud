"""Synthetic offline tests of beta30 P2PType classification."""
import runpy,ast,json,unittest
from pathlib import Path
COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
SUM=runpy.run_path(str(COMP/"c9c_tuya_device_b27.py"))["summarize_tuya_device_b27"]
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend/c9c-autonome-b1.js").read_text(encoding="utf-8")
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
def read(d):
    return SUM(d,expected_device_id="SECRET_ID",aosu_sn="SECRET_SN",aosu_coop=None)
class TestP2PTypeBeta30(unittest.TestCase):
    def test_known_numeric_types(self):
        self.assertEqual(read({"skills":{"p2pType":2}})["p2p_sdk_type_b30"],"ppcs_2")
        self.assertEqual(read({"data":{"skills":{"p2pType":4.0}}})["p2p_sdk_type_b30"],"thing_4")
    def test_other_types_not_guessed(self):
        for x in (-1,0,1,3,5,99):
            self.assertEqual(read({"skills":{"p2pType":x}})["p2p_sdk_type_b30"],"autre_numerique")
        for x in ("4",True,None,{}):
            self.assertEqual(read({"skills":{"p2pType":x}})["p2p_sdk_type_b30"],"non_numerique")
    def test_missing_and_conflicting(self):
        self.assertEqual(read({})["p2p_sdk_type_b30"],"absent")
        self.assertEqual(read({"p2pType":4})["p2p_sdk_type_b30"],"hors_skills")
        self.assertEqual(read({"skills":{"p2pType":2},"device":{"skills":{"p2pType":4}}})
                         ["p2p_sdk_type_b30"],"valeurs_multiples")
    def test_secrets_and_identity(self):
        out=read({"device":{"skills":{"p2pType":2},
                 "p2pSpecifiedType":1,"productId":"SECRET_PID",
                 "password":"SECRET_PASS"}})
        self.assertTrue(out["p2p_specified_type_present"])
        self.assertFalse(out["identite_aosu_tuya_etablie"])
        for secret in ("SECRET_PID","SECRET_PASS","SECRET_ID"):
            self.assertNotIn(secret,json.dumps(out))
    def test_safe_service(self):
        ast.parse(INIT);ast.parse(RTC)
        self.assertIn("read('thing.m.device.get',{'devId':target})",RTC)
        self.assertIn("'p2p_sdk_b30':data.get('p2p_sdk_type_b30')",INIT)
        self.assertIn("if data.get('p2p_sdk_type_b30') in allowed_p2p",INIT)
        self.assertIn("Fiche Tuya beta30",UI)
        self.assertNotIn("ptz_maintien",UI)
if __name__=="__main__":unittest.main()
