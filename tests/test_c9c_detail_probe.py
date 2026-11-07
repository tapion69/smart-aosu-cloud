"""Tests offline: verify no private identifiers leave C9C detailed diagnostics."""
import ast
import json
from pathlib import Path
import unittest

BASE=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
SRC=(BASE/"c9c_detail_probe.py").read_text(encoding="utf-8")
TREE=ast.parse(SRC)
FUNCS=[node for node in TREE.body if isinstance(node,ast.FunctionDef)
       and node.name in ("_valid","_detail_references","summarize_c9c_detail")]
NS={"summarize_info":lambda payload:{"references":{"cpDeviceId":True},
     "audit_provider_p2p":{"candidat":{"sdk_provider_declare_nom":"THING",
                                            "p2p_type_declare":2}}}}
exec(compile(ast.Module(body=FUNCS,type_ignores=[]),"<offline>", "exec"),NS)

class TestC9CDetail(unittest.TestCase):
    def test_cross_match_private_ids_not_exposed(self):
        sn="SECRET_SERIE"
        match="SECRET_TUYA_ID"
        payload={"errno":0,"data":{"sn":sn,"cpDeviceInfo":{"cpDeviceId":match}}}
        cache={"devices":{match:{"localKey":"SECRET_LOCAL_KEY"}}}
        result=NS["summarize_c9c_detail"](payload,sn,cache)
        self.assertTrue(result["correspondance_reference_tuya"])
        self.assertTrue(result["numero_serie_concordant"])
        self.assertEqual(result["fournisseur_p2p_fiche"],"THING")
        for private in (sn,match,"SECRET_LOCAL_KEY"):
            self.assertNotIn(private,json.dumps(result))
    def test_missing_or_nonmatching_evidence(self):
        result=NS["summarize_c9c_detail"](
            {"errno":0,"data":{"cpDeviceId":"OTHER_SECRET"}},
            "SN_SECRET",{"devices":{"dev":{"category":"gw"}}})
        self.assertEqual(result["etat"],"fiche_obtenue")
        self.assertFalse(result["correspondance_reference_tuya"])
        self.assertFalse(result["numero_serie_contradictoire"])
        self.assertEqual(result["commandes_camera"],0)
    def test_invalid_response_safe(self):
        result=NS["summarize_c9c_detail"]({"errno":1,"data":{"cpDeviceId":"PRIVATE"}},
                                            "SN",None)
        self.assertEqual(result["etat"],"reponse_invalide")
        self.assertNotIn("PRIVATE",str(result))
    def test_source_fails_closed(self):
        for text in ("allow_redirects=False","verify=True",
                     "_last_c9c_detail_probe", "with client._dp_lock",
                     "len(response.content) > 262144"):
            self.assertIn(text,SRC)
        self.assertNotIn("print(",SRC)

if __name__=="__main__":unittest.main()
