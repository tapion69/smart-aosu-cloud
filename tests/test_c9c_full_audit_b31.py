"""Offline, single-run beta31 C9C audit with fake Tuya responses."""
from __future__ import annotations
import runpy,json,unittest
from pathlib import Path
COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
FN=runpy.run_path(str(COMP/"c9c_full_audit_b31.py"))
PARSE=runpy.run_path(str(COMP/"c9c_tuya_device_b27.py"))["summarize_tuya_device_b27"]
HINTS=runpy.run_path(str(COMP/"c9c_webrtc_probe_b23.py"))["inspect_webrtc_hints"]
RTC=runpy.run_path(str(COMP/"c9c_rtc_schema.py"))["summarize_c9c_rtc_schema"]
run=FN["run_full_c9c_audit_b31"]

def safe_answer(payload):
    return payload,{"serveur_accepte":True,"rejet_explicite":False}

def conduct(data,inventory=None,sn="AOSU_SN",coop=None):
    calls=[]
    def read(action,params):
        calls.append((action,params))
        return safe_answer(data[action])
    report=run(read,target="PRIVATE_ID",inventory=inventory or {},
               aosu_sn=sn,aosu_coop=coop,
               parse_device=PARSE,parse_hints=HINTS,parse_rtc=RTC)
    return report,calls

class TestComprehensiveC9CB31(unittest.TestCase):
    def test_full_six_calls_and_no_private_values(self):
        data={
          "thing.m.device.get":{"device":{"devId":"PRIVATE_ID","sn":"AOSU_SN",
              "productId":"secret_PID12","productVersion":"1.0",
              "skills":{"p2pType":4},"token":"PRIVATE_TOKEN"}},
          "thing.m.product.info.get":{"data":{"category":"ipc",
              "model":"C9C","productId":"secret_PID12","capabilities":{"video":True}}},
          "thing.m.product.thing.model":{"data":{"supportsVideo":True}},
          "thing.m.ipc.config.get":{"p2pConfig":{"session":{"aesKey":"PRIVATE_KEY"},
              "ices":[{"urls":"turn:secret.host"}]},"supportsWebrtc":True},
          "m.ipc.v4.rtc.config.get":{"p2pConfig":{"session":{"aesKey":"PRIVATE_KEY"},
              "ices":[{"urls":"turn:secret.host"}],"motoId":"private_moto"},
              "auth":"PRIVATE_AUTH"},
          "thing.m.rtc.config.get":{"p2pConfig":{"session":{"aesKey":"PRIVATE_KEY"}}}
        }
        report,calls=conduct(data)
        self.assertEqual(report["etat"],"termine")
        self.assertEqual(len(calls),6)
        self.assertEqual(report["appels_api"],6)
        self.assertTrue(report["identite"]["identite_exacte"])
        self.assertEqual(report["identite"]["p2p_sdk"],"thing_4")
        self.assertEqual(report["produit"]["categorie"],"camera")
        self.assertEqual(report["produit"]["modele"],"c9c")
        self.assertTrue(report["rtc"]["rtc_v4"]["moto_id"])
        self.assertTrue(report["rtc"]["rtc_v4"]["auth_webrtc"])
        for token in ("secret_PID12","PRIVATE_ID","AOSU_SN","PRIVATE_TOKEN",
                      "PRIVATE_KEY","PRIVATE_AUTH","private_moto","secret.host"):
            self.assertNotIn(token,json.dumps(report))
        self.assertEqual(report["mqtt_publications"],0)
        self.assertEqual(report["commandes_ptz"],0)

    def test_missing_product_does_not_stop_rtc(self):
        data={k:{} for k in ("thing.m.device.get",
            "thing.m.ipc.config.get","m.ipc.v4.rtc.config.get",
            "thing.m.rtc.config.get")}
        report,calls=conduct(data)
        self.assertEqual(len(calls),4)
        self.assertEqual(report["etapes"]["produit"],"non_tentee_product_id_absent")
        self.assertEqual(report["etapes"]["modele_produit"],"non_tentee_product_id_absent")
        self.assertEqual(report["etapes"]["rtc_v4"],"acceptee")

    def test_ambiguous_product_skips_product_calls(self):
        data={k:{} for k in ("thing.m.ipc.config.get","m.ipc.v4.rtc.config.get",
                             "thing.m.rtc.config.get")}
        data["thing.m.device.get"]={"data":{"productId":"product_ABC12"}}
        report,calls=conduct(data,inventory={"productId":"product_DIFF12"})
        self.assertEqual(len(calls),4)
        self.assertTrue(report["reference_produit"]["product_id_ambigu"])
        self.assertEqual(report["etapes"]["produit"],"non_tentee_produit_ambigu")

    def test_denied_product_does_not_export_response_or_retry(self):
        calls=[]
        def read(action,params):
            calls.append(action)
            if action=="thing.m.product.info.get":
                return {"password":"SECRET"},{"serveur_accepte":False,
                        "rejet_explicite":True}
            if action=="thing.m.device.get":
                return safe_answer({"productId":"product_12345"})
            return safe_answer({})
        r=run(read,target="PRIVATE_ID",inventory={},
              aosu_sn=None,aosu_coop=None,
              parse_device=PARSE,parse_hints=HINTS,parse_rtc=RTC)
        self.assertEqual(calls.count("thing.m.product.info.get"),1)
        self.assertEqual(r["etapes"]["produit"],"refusee")
        self.assertEqual(r["etapes"]["rtc_classique"],"acceptee")
        self.assertNotIn("SECRET",json.dumps(r))
        self.assertLessEqual(len(calls),6)

if __name__=="__main__":
    unittest.main()
