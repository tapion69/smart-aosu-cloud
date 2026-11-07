"""Offline C9C RTC schema checks, without Home Assistant, vendor or network."""
import ast
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
SOURCE=(ROOT/"c9c_rtc_schema.py").read_text(encoding="utf-8")
tree=ast.parse(SOURCE)
functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)]
ns={"Any":object}
exec(compile(ast.Module(body=functions,type_ignores=[]),"<rtc>", "exec"),ns)

class RTCSchemaTests(unittest.TestCase):
    def test_turn_and_known_version(self):
        raw={"data":{"p2pConfig":{"session":{"sessionId":"SECRET_SESSION"},
            "ices":[{"urls":["stun:private.address","turn:secret.ip:3478"]}],
            "tcpRelay":{"username":"SECRET_USER"}},"motoId":"PRIVATE_MOTO"}}
        dev={"pv":"2.3","localKey":"PRIVATE_LOCAL_KEY"}
        r=ns["summarize_c9c_rtc_schema"](raw,dev)
        self.assertTrue(r["serveur_turn_dans_ices"])
        self.assertTrue(r["moto_id_present"])
        self.assertEqual(r["version_mqtt_pv_connue"],"2.3")
        self.assertTrue(r["relais_tcp_declare"])
        for secret in ("SECRET","private","3478"):
            self.assertNotIn(secret,str(r))
    def test_unknown_fields_never_echoed(self):
        r=ns["summarize_c9c_rtc_schema"]({"bogus":"VERY_PRIVATE"},{"pv":"PRIVATE_PROTO"})
        self.assertEqual(r["version_mqtt_pv_connue"],"non_identifiee")
        self.assertFalse(r["serveur_turn_dans_ices"])
        self.assertNotIn("PRIVATE",str(r))
    def test_no_automatic_offer_in_service(self):
        src=(ROOT/"__init__.py").read_text(encoding="utf-8")
        self.assertIn("standalone_c9c_rtc_audit=True, tester_mqtt=False",src)
        self.assertIn("supports_response=SupportsResponse.ONLY",src)

if __name__=="__main__":unittest.main()
