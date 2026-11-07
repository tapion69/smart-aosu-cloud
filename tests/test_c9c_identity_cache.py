"""Read-only C9C identity diagnostics without HA, login or network."""
import ast
import json
import runpy
import time
import types
import unittest
from pathlib import Path

COMP=Path(__file__).resolve().parents[1]/"custom_components"/"smart_aosu_cloud"
AUDIT=runpy.run_path(str(COMP/"c9c_identity_diagnostic.py"))
TOPO=runpy.run_path(str(COMP/"camera_topology.py"))
DATA={"a":{"is_camera":True,"model":"C9C","via_device":None}}

def inspect(devices, sn="PRIVATE_SN", coop=None):
    client=types.SimpleNamespace(_standalone_c9c_sn=sn,
                                 _standalone_c9c_coop_id=coop)
    return AUDIT["inspect_c9c_identity_cache"](
        data=DATA,client=client,
        cache={"created":time.monotonic(),"devices":devices},
        select_standalone=TOPO["select_standalone_c9c_key"],
        select_tuya=TOPO["select_tuya_standalone_target"])

class IdentityTests(unittest.TestCase):
    def test_exact_serial_and_private_data_redacted(self):
        r=inspect({"PRIVATE_DEVICE":{"sn":"PRIVATE_SN","name":"SECRET_NAME",
                                    "localKey":"SECRET_KEY"}})
        self.assertEqual(r["etat"],"identite_exacte_confirmee")
        for secret in ("PRIVATE_DEVICE","PRIVATE_SN","SECRET_NAME","SECRET_KEY"):
            self.assertNotIn(secret,json.dumps(r))

    def test_singleton_unproved(self):
        r=inspect({"PRIVATE_DEVICE":{"devId":"WRONG","localKey":"SECRET_KEY"}})
        self.assertEqual(r["etat"],"identite_non_prouvee")
        self.assertFalse(r["correspondance"]["identite_exacte_confirmee"])
        self.assertEqual(r["correspondance"]["selection_rtc"],
                         "appareil_tuya_unique_sans_categorie_video")
        self.assertTrue(r["unique_appareil_tuya"]["categorie_absente"])

    def test_coop_exact(self):
        r=inspect({"x":{"deviceId":"MATCHING_COOP"}},coop="MATCHING_COOP")
        self.assertEqual(r["etat"],"identite_exacte_confirmee")
        self.assertEqual(r["correspondance"]["coop_exact_nombre"],1)
        self.assertNotIn("MATCHING_COOP",json.dumps(r))

    def test_ambiguous(self):
        r=inspect({"x":{"category":"sp"},"y":{"category":"ipc"}})
        self.assertEqual(r["etat"],"selection_impossible")
        self.assertEqual(r["commandes_camera"],0)
        self.assertFalse(r["video_lancee"])

    def test_missing_cache(self):
        client=types.SimpleNamespace(_standalone_c9c_sn="SN",
                                     _standalone_c9c_coop_id=None)
        r=AUDIT["inspect_c9c_identity_cache"](
            data=DATA,client=client,cache=None,
            select_standalone=TOPO["select_standalone_c9c_key"],
            select_tuya=TOPO["select_tuya_standalone_target"])
        self.assertEqual(r["etat"],"inventaire_tuya_non_charge")

    def test_registration_and_no_video_commands(self):
        source=(COMP/"__init__.py").read_text(encoding="utf-8")
        js=(COMP/"frontend/c9c-autonome-b1.js").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn("diagnostiquer_identite_c9c_autonome",source)
        self.assertIn("tester_rtc=False",source)
        self.assertIn("tester_mqtt=False",source)
        self.assertIn("tester_offre_mqtt=False",source)
        self.assertIn("confirmation_lecture_tuya:true",js)
        self.assertIn("Vérifier identité",js)
        self.assertNotIn("ptz_maintien",js)

if __name__=="__main__":unittest.main()
