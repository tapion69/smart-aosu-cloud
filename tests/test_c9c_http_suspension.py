"""Ensure rejected, non-native C9C HTTP probe cannot send another request."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

SOURCE=Path(__file__).resolve().parents[1]/"custom_components"/"smart_aosu_cloud"/"tuya_rtc_inventory.py"


def extract_probe():
    tree=ast.parse(SOURCE.read_text(encoding="utf-8"))
    fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
            and n.name=="run_tuya_oem_inventory")
    namespace={}
    module=ast.Module(body=[ast.ImportFrom(module="__future__",
                             names=[ast.alias(name="annotations")],level=0),fn],
                      type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module,str(SOURCE),"exec"),namespace)
    return namespace["run_tuya_oem_inventory"]


class ExperimentalC9CHttpSuspension(unittest.TestCase):
    def test_approved_old_http_test_suspended_with_no_camera_traffic(self):
        run=extract_probe()
        result=run(None,standalone_c9c_http_offer_test=True,
                   tester_rtc=True,confirmation_envoi_mot_de_passe=True,
                   confirmation_offre_http=True,
                   confirmation_cible_unique_non_prouvee=True)
        self.assertEqual(result["etat"],"offre_http_suspendue_parite_session_absente")
        self.assertFalse(result["requete_http_effectuee"])
        self.assertEqual(result["appel_reseau"],0)
        self.assertEqual(result["commande_camera"],0)
        self.assertEqual(result["commandes_ptz"],0)
        self.assertEqual(result["offres_mqtt_envoyees"],0)
        self.assertFalse(result["video_lancee"])

    def test_missing_confirmation_stays_refused(self):
        run=extract_probe()
        result=run(None,standalone_c9c_http_offer_test=True,
                   tester_rtc=True,confirmation_envoi_mot_de_passe=True,
                   confirmation_offre_http=False)
        self.assertEqual(
            result["etat"],"offre_http_c9c_confirmation_et_exclusivite_requises")
        self.assertEqual(result["appel_reseau"],0)

    def test_no_http_mode_still_uses_legacy_route(self):
        source=SOURCE.read_text(encoding="utf-8")
        self.assertIn("elif confirmation_offre_http or confirmation_cible_unique_non_prouvee:",source)
        self.assertIn("if standalone_c9c_video_test:",source)
        # The suspension is only inside the explicit manual HTTP branch.
        block=source.split("if standalone_c9c_http_offer_test:",1)[1].split(
            "elif confirmation_offre_http or confirmation_cible_unique_non_prouvee:",1)[0]
        self.assertIn("offre_http_suspendue_parite_session_absente",block)
        init=(SOURCE.parent/"__init__.py").read_text(encoding="utf-8")
        self.assertIn("'offre_http_suspendue_parite_session_absente'",init)


if __name__=="__main__":
    unittest.main()
