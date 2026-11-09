"""Offline proof that only Fiche Tuya has a 20-min manual login gate."""
import ast
import unittest
from pathlib import Path

COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
SRC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")

class TestC9CFicheLoginB28(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ast.parse(SRC)
        tree=ast.parse(SRC)
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
                  and n.name=="_c9c_detail_login_allowed")
        scope={}
        exec(compile(ast.fix_missing_locations(
            ast.Module(body=[node],type_ignores=[])),"<offline>","exec"),scope)
        cls.allow=staticmethod(scope["_c9c_detail_login_allowed"])

    def test_20_minute_minimum_from_last_global_login(self):
        fn=self.allow
        # Global login took place at t=0; expiration is t=3600.
        self.assertFalse(fn(1199,3600,0))
        self.assertTrue(fn(1200,3600,0))
        self.assertTrue(fn(1900,3600,0))
        # The unrelated one-hour gate would still deny at t=1900.
        self.assertTrue(1900 < 3600)

    def test_dedicated_detail_retry_cooldown(self):
        fn=self.allow
        self.assertFalse(fn(1500,3600,2400))
        self.assertTrue(fn(2400,3600,2400))
        # Another manual detail login at t=2400 extends both gates.
        self.assertFalse(fn(3599,6000,3600))
        self.assertTrue(fn(3600,6000,3600))

    def test_only_explicit_detail_enters_exception(self):
        s=SRC
        self.assertIn("if standalone_c9c_tuya_detail_audit:",s)
        self.assertIn("_c9c_detail_login_allowed(",s)
        self.assertIn("elif now < _LAST_LOGIN.get(client_key,0)",s)
        self.assertIn("'limite_login_une_heure'",s)
        self.assertIn("limite_reconnexion_fiche_tuya_20_minutes",s)
        self.assertIn("_LAST_C9C_DETAIL_LOGIN[client_key]=now+1200",s)
        self.assertIn("and 0 <= now-created < 1800",s)
        self.assertIn("cache.get('session_uid') == session.uid",s)
        self.assertIn("standalone_c9c_tuya_detail_audit=True",INIT)
        self.assertIn("'limite_reconnexion_fiche_tuya_20_minutes'",INIT)
        self.assertNotIn("ptz_maintien",SRC)

if __name__=="__main__":
    unittest.main()
