"""Offline C9C Tuya device detail identity audit tests; no account or network."""
import ast,json,runpy,unittest
from pathlib import Path
COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
SUM=runpy.run_path(str(COMP/"c9c_tuya_device_b27.py"))["summarize_tuya_device_b27"]
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend/c9c-autonome-b1.js").read_text(encoding="utf-8")
class TestC9CTuyaDeviceB27(unittest.TestCase):
    def test_sn_matching_is_proof_but_secrets_never_exported(self):
        data={"data":{"deviceInfo":{"sn":"SECRET_SN","devId":"SECRET_ID",
              "localKey":"SECRET_KEY","model":"C9C","name":"PRIVATE_NAME"}}}
        result=SUM(data,expected_device_id="SECRET_ID",
                   aosu_sn="SECRET_SN",aosu_coop=None)
        self.assertTrue(result["identite_aosu_tuya_etablie"])
        self.assertTrue(result["numero_serie_exact"])
        self.assertTrue(result["modele_c9c_exact"])
        self.assertEqual(result["etat_correspondance"],
                         "identite_exacte_dans_fiche_tuya")
        for secret in ("SECRET_SN","SECRET_ID","SECRET_KEY","PRIVATE_NAME"):
            self.assertNotIn(secret,json.dumps(result))
    def test_model_only_never_proves_identity(self):
        data={"result":{"model":"C9C","sn":"WRONG_SN","category":"ipc"}}
        r=SUM(data,expected_device_id="SECRET_ID",
              aosu_sn="SECRET_SN",aosu_coop=None)
        self.assertFalse(r["identite_aosu_tuya_etablie"])
        self.assertEqual(r["etat_correspondance"],
                         "modele_c9c_seulement_non_confirmant")
    def test_absent_fields_are_unknown(self):
        r=SUM({"data":{}},expected_device_id="SECRET",
              aosu_sn="PRIVATE_SN",aosu_coop=None)
        self.assertFalse(r["identite_aosu_tuya_etablie"])
        self.assertFalse(r["numero_serie_present"])
        self.assertTrue(r["categorie_absente"])
    def test_coop_reference_match(self):
        r=SUM({"result":{"device":{"cpDeviceId":"SECRET_REF"}}},
              expected_device_id="SECRET_ID",
              aosu_sn="SECRET_SN",aosu_coop="SECRET_REF")
        self.assertTrue(r["reference_coop_exacte"])
        self.assertTrue(r["identite_aosu_tuya_etablie"])
        self.assertNotIn("SECRET_REF",json.dumps(r))
    def test_wiring_stops_before_rtc_or_mqtt(self):
        for text in (RTC,INIT):
            ast.parse(text)
        pos=RTC.index("if standalone_c9c_tuya_detail_audit:")
        end=RTC.index("# Drop previous provisional media credentials",pos)
        block=RTC[pos:end]
        self.assertIn("read('thing.m.device.get',{'devId':target})",block)
        self.assertIn("return {**out,'etat':'fiche_tuya_obtenue'}",block)
        self.assertNotIn("run_tuya_mqtt_offer(",block)
        self.assertNotIn("inspect_rtc_media(",block)
        self.assertIn("standalone_c9c_tuya_detail_audit=True",INIT)
        self.assertIn("select_standalone_c9c_key(runtime.data)",INIT)
        self.assertIn("this._tuyaDetail27()",UI)
        self.assertNotIn("ptz_maintien",UI)
if __name__=="__main__":unittest.main()
