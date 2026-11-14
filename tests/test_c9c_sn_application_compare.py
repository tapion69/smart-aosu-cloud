"""No-network, no-Home-Assistant tests of private AOSU application SN check."""
from __future__ import annotations

import ast
import runpy
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "custom_components" / "smart_aosu_cloud"
COMPARE = runpy.run_path(str(BASE / "c9c_sn_application_compare.py"))
compare = COMPARE["compare_app_sn_locally"]


class TestAppSnComparison(unittest.TestCase):
    def test_exact_match_is_local_and_does_not_assert_tuya_identity(self):
        serial = "C9C-PRIVATE-TEST-01"
        response = compare(serial, serial)
        self.assertEqual(response["etat"], "sn_application_egal_aosu")
        self.assertTrue(response["sn_application_correspond"])
        self.assertFalse(response["identite_aosu_tuya_etablie_par_ce_test"])
        self.assertEqual(response["appels_reseau"], 0)
        self.assertEqual(response["offres_http_envoyees"], 0)
        self.assertEqual(response["offres_mqtt_envoyees"], 0)
        self.assertEqual(response["commandes_ptz"], 0)
        self.assertEqual(response["commandes_camera"], 0)
        self.assertFalse(response["video_lancee"])
        self.assertNotIn(serial, repr(response))
        self.assertFalse(response["identifiants_retournes"])

    def test_different_serial_is_not_normalized_into_false_positive(self):
        response = compare("C9C-PRIVATE-TEST-01", "C9C-PRIVATE-TEST-02")
        self.assertEqual(response["etat"], "sn_application_different_aosu")
        self.assertFalse(response["sn_application_correspond"])
        self.assertTrue(response["sn_aosu_cache_present"])
        self.assertNotIn("PRIVATE", repr(response))
        self.assertEqual(compare("abcde", "ABCDE")["etat"],
                         "sn_application_different_aosu")

    def test_unavailable_cloud_serial_is_not_a_mismatch(self):
        response = compare("C9C-PRIVATE-TEST-01", None)
        self.assertEqual(response["etat"], "sn_aosu_cache_indisponible")
        self.assertFalse(response["sn_aosu_cache_present"])

    def test_invalid_user_input_never_leaks(self):
        for invalid in (None, "", "abc", " AOSU123 ", "AOSU\n123",
                        "private" * 25, 12345, {"sn": "AOSU123"}):
            with self.subTest(invalid_type=type(invalid).__name__):
                response = compare(invalid, "AOSU123")
                self.assertEqual(response["etat"], "sn_application_invalide")
                self.assertNotIn("AOSU123", repr(response))

    def test_home_assistant_action_only_calls_ram_comparator(self):
        source = (BASE / "__init__.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        handlers = [n for n in ast.walk(tree)
                    if isinstance(n, ast.AsyncFunctionDef)
                    and n.name == "comparer_sn_application_c9c"]
        self.assertEqual(len(handlers), 1)
        handler = ast.get_source_segment(source, handlers[0])
        self.assertIn("compare_app_sn_locally", handler)
        self.assertIn("select_standalone_c9c_key", handler)
        for forbidden in ("run_tuya_oem_inventory(", "do_oem_read(",
                          "run_tuya_mqtt_offer(", "logger.", "_LOGGER.",
                          "print(", "async_add_executor_job(", "requests."):
            self.assertNotIn(forbidden, handler)
        self.assertIn(
            "hass.services.async_register(DOMAIN,'comparer_sn_application_c9c'",
            source)
        services = (BASE / "services.yaml").read_text(encoding="utf-8")
        self.assertIn("comparer_sn_application_c9c:", services)
        self.assertIn("sn_application_aosu:", services)


if __name__ == "__main__":
    unittest.main()
