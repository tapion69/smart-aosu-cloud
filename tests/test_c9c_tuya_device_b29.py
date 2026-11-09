"""Offline standalone C9C Tuya identity diagnostics — beta29.

Synthetic fixtures only. No Home Assistant, Tuya account, camera or network.
"""
import ast
import json
import runpy
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT/"custom_components/smart_aosu_cloud"
SUM=runpy.run_path(str(COMP/"c9c_tuya_device_b27.py"))["summarize_tuya_device_b27"]
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend/c9c-autonome-b1.js").read_text(encoding="utf-8")
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")

def parse(detail, sn="AOSU_SN", coop=None):
    return SUM(detail, expected_device_id="TUYA_ID", aosu_sn=sn, aosu_coop=coop)

class TestC9CTuyaIdentityB29(unittest.TestCase):
    def test_missing_sn_is_not_a_mismatch(self):
        out=parse({"result":{"device":{"devId":"TUYA_ID","productId":"PRIVATE_PID"}}})
        self.assertEqual(out["etat_sn_b29"],"absent_dans_tuya")
        self.assertFalse(out["numero_serie_present"])
        self.assertEqual(out["etat_reference_b29"],"aosu_reference_indisponible")
        self.assertFalse(out["identite_aosu_tuya_etablie"])
        self.assertTrue(out["product_id_present"])

    def test_present_but_different_is_not_proof_of_wrong_camera(self):
        out=parse({"data":{"deviceInfo":{"sn":"OTHER_SN","model":"Unknown"}}},
                  coop="AOSU_COOP")
        self.assertEqual(out["etat_sn_b29"],"present_sans_egalite")
        self.assertEqual(out["etat_reference_b29"],"absente_dans_tuya")
        self.assertEqual(out["etat_modele_b29"],"present_autre_ou_inconnu")
        self.assertFalse(out["identite_aosu_tuya_etablie"])

    def test_strong_sn_and_reference_match(self):
        out=parse({"data":{"sn":"AOSU_SN","cpDeviceId":"AOSU_COOP"}},
                  coop="AOSU_COOP")
        self.assertEqual(out["etat_sn_b29"],"egal")
        self.assertEqual(out["etat_reference_b29"],"egale")
        self.assertTrue(out["identite_aosu_tuya_etablie"])

    def test_product_and_p2p_hints_do_not_prove_identity(self):
        payload={"result":{"device":{
          "devId":"TUYA_ID","modelName":"C9C",
          "productBean":{"productId":"PRIVATE_PID","category":"ipc"},
          "skills":{"p2pType":3},"capabilities":{"playback":True},
          "p2pConfig":{"token":"PRIVATE_TOKEN"},"supportP2p":True,
          "password":"PRIVATE_PASSWORD","uuid":"PRIVATE_UUID"
        }}}
        out=parse(payload)
        for flag in ("product_bean_present","product_id_dans_product_bean",
                     "skills_bloc_present","capacites_bloc_present",
                     "p2p_type_champ_present","p2p_config_bloc_present",
                     "p2p_support_bool_present","categorie_video_reconnue",
                     "modele_c9c_exact"):
            self.assertTrue(out[flag],flag)
        self.assertFalse(out["identite_aosu_tuya_etablie"])
        for secret in ("PRIVATE_PID","PRIVATE_PASSWORD","PRIVATE_UUID",
                       "PRIVATE_TOKEN","TUYA_ID"):
            self.assertNotIn(secret,json.dumps(out))

    def test_aosu_sn_unavailable_and_non_video_category(self):
        out=parse({"category":"gw","productId":"PRIVATE_PID"},sn=None)
        self.assertEqual(out["etat_sn_b29"],"aosu_sn_indisponible")
        self.assertEqual(out["etat_categorie_b29"],"non_video_reconnue")
        self.assertFalse(out["identite_aosu_tuya_etablie"])

    def test_network_wiring_unmodified_and_whitelisted_output(self):
        ast.parse(INIT)
        ast.parse(RTC)
        self.assertIn("read('thing.m.device.get',{'devId':target})",RTC)
        self.assertIn("return {**out,'etat':'fiche_tuya_obtenue'}",RTC)
        self.assertIn("'comparaison_b29':",INIT)
        self.assertIn("if data.get('etat_sn_b29') in allowed_sn",INIT)
        self.assertIn("if data.get('etat_reference_b29') in allowed_ref",INIT)
        self.assertIn("this._tuyaDetail27()",UI)
        self.assertIn("Fiche Tuya beta29",UI)
        self.assertIn("SN présent, non concordant",UI)
        self.assertIn("référence AOSU indisponible",UI)
        self.assertNotIn("ptz_maintien",UI)

if __name__=="__main__":
    unittest.main()
