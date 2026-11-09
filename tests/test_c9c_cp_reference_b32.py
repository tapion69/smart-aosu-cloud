"""Offline beta32 regression: no misrouting or private CP ID export."""
from __future__ import annotations
import ast
import json
import runpy
import unittest
from pathlib import Path

COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
extract=runpy.run_path(str(COMP/"c9c_cp_reference_b32.py"))["extract_c9c_cp_reference"]
topology=runpy.run_path(str(COMP/"camera_topology.py"))
select=topology["select_tuya_standalone_target"]
API=(COMP/"api.py").read_text(encoding="utf-8")
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend/c9c-autonome-b1.js").read_text(encoding="utf-8")

class TestCPReferenceB32(unittest.TestCase):
    def test_root_and_nested_sources(self):
        cases=(
            ({"coopUUID":"SECRET_A"}, "coop_uuid_racine"),
            ({"cpDeviceId":"SECRET_A"}, "cp_device_id_racine"),
            ({"cpDeviceInfo":{"cpDeviceId":"SECRET_A"}}, "cp_device_info"),
            ({"coopUUID":"SECRET_A","cpDeviceInfo":{"cpDeviceId":"SECRET_A"}},
             "champs_concordants"),
            ({"coopUUID":"SECRET_A","cpDeviceId":"SECRET_A",
              "cpDeviceInfo":{"cpDeviceId":"SECRET_A"}},"champs_concordants"),
        )
        for record,status in cases:
            with self.subTest(status=status):
                private,source=extract(record)
                self.assertEqual(private,"SECRET_A")
                self.assertEqual(source,status)
                self.assertNotIn(private,json.dumps({"source":source}))
                target,selection=select({"TUYA_1":{"devId":private}},
                    camera_sn="AOSU_SN",camera_coop=private)
                self.assertEqual((target,selection),("TUYA_1","identite_exacte"))

    def test_conflicts_fail_closed(self):
        for record in (
            {"coopUUID":"SECRET_A","cpDeviceId":"SECRET_B"},
            {"cpDeviceInfo":{"cpDeviceId":"SECRET_B"},"coopUUID":"SECRET_A"},
            {"cpDeviceInfo":{"cpDeviceId":"SECRET_C"},"cpDeviceId":"SECRET_B"}
        ):
            private,status=extract(record)
            self.assertIsNone(private)
            self.assertEqual(status,"references_contradictoires")
        self.assertEqual(select({"x":{"devId":"SECRET_A"}},
                         camera_sn="AOSU_SN",camera_coop=None)[1],
                         "appareil_tuya_unique_sans_categorie_video")

    def test_missing_invalid_and_untrusted_keys(self):
        for record,status in (
            (None,"fiche_absente"),
            ({},"absente"),
            ({"cpDeviceInfo":{"uuid":"SECRET_A"}},"absente"),
            ({"cpDeviceId":"SECRET_A\n"},"format_invalide"),
            ({"cpDeviceInfo":{"cpDeviceId":88}},"format_invalide"),
            ({"cpDeviceId":" "+("A"*10)},"format_invalide"),
            ({"coopUUID":"A"*257},"format_invalide"),
        ):
            with self.subTest(status=status):
                private,observed=extract(record)
                self.assertIsNone(private)
                self.assertEqual(observed,status)

    def test_selection_fails_closed_for_multiple_matching_devices(self):
        cp,status=extract({"cpDeviceInfo":{"cpDeviceId":"SECRET_A"}})
        target,method=select({"one":{"uuid":cp},"two":{"cpDeviceId":cp}},
                             camera_sn="SN",camera_coop=cp)
        self.assertIsNone(target)
        self.assertEqual(method,"correspondance_ambigue")

    def test_route_isolated_from_legacy_and_no_secret_leak(self):
        for code in (API,INIT):
            ast.parse(code)
        self.assertIn("extract_c9c_cp_reference(standalone[0])",API)
        self.assertIn("self._standalone_c9c_coop_id=private_cp",API)
        self.assertIn("self._standalone_c9c_cp_source=cp_source",API)
        self.assertIn("self._standalone_c9c_coop_id=None",API)
        self.assertIn("self._standalone_c9c_cp_source='absente'",API)
        self.assertIn("'origine_aosu_cp':aosu_source",INIT)
        self.assertIn("if aosu_source in allowed_aosu_sources",INIT)
        self.assertIn("Origine référence AOSU",UI)
        self.assertNotIn("ptz_maintien",UI)
        self.assertIn("has_h1l_video_topology", (COMP/"camera_topology.py").read_text())
        self.assertIn("model')=='C5L'",API)

if __name__=="__main__":
    unittest.main()
