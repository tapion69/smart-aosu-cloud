"""Synthetic safeguards for the external AOSU-to-Tuya camera identity bridge."""
import json
import runpy
import struct
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
TOOL=runpy.run_path(str(ROOT/"tools"/"aosu_sdk_route_offline.py"))
ROUTE=runpy.run_path(str(ROOT/"custom_components"/"smart_aosu_cloud"/"camera_topology.py"))


class RouteOfflineTests(unittest.TestCase):
    def test_static_evidence_never_claims_runtime_identity(self):
        class Stub:
            def method(self,*args): return b""
            def calls(self,*args): return True
            def field_access(self,*args): return True
        data=TOOL["summarize"]({n:Stub() for n in
            ("classes6.dex","classes11.dex","classes16.dex")},17)
        self.assertEqual(data["dex_count"],17)
        self.assertTrue(all(data["facts"].values()))
        self.assertFalse(data["identity_confirmed"])
        self.assertFalse(data["video_confirmed"])
        self.assertEqual(data["network_calls"],0)
        self.assertNotIn("SECRET_SN",json.dumps(data))

    def test_invoke_opcode_is_not_field_reference(self):
        probe=TOOL["DexIndex"].referenced
        raw=struct.pack("<HHH",0x106e,123,0)
        self.assertTrue(probe(raw,123,(0x6e,)))
        self.assertFalse(probe(raw,123,(0x54,)))
        self.assertFalse(probe(raw,124,(0x6e,)))

    def test_product_id_and_thing_only_is_heuristic(self):
        choose=ROUTE["select_tuya_standalone_target"]
        devices={"ty":{"productId":"product123","skills":{"p2pType":4}}}
        self.assertEqual(choose(devices,camera_sn="AOSU_SN",camera_coop=None),
                         ("ty","appareil_tuya_unique_sans_categorie_video"))
        self.assertNotEqual(choose(devices,camera_sn="AOSU_SN",
                                   camera_coop=None)[1],"identite_exacte")

    def test_explicit_matching_cp_device_id(self):
        choose=ROUTE["select_tuya_standalone_target"]
        devices={"ty":{"deviceId":"CP_EXACT","skills":{"p2pType":4}}}
        self.assertEqual(choose(devices,camera_sn="AOSU_SN",
                                camera_coop="CP_EXACT"),
                         ("ty","identite_exacte"))
        self.assertNotEqual(choose(devices,camera_sn="AOSU_SN",
                                   camera_coop=None)[1],"identite_exacte")

    def test_no_c5l_or_station_mixup(self):
        choose=ROUTE["select_standalone_c9c_key"]
        self.assertIsNone(choose({"b":{"model":"H1L"},
                                  "c":{"is_camera":True,"model":"C9C"}}))
        self.assertIsNone(choose({"c":{"is_camera":True,"model":"C5L"}}))


if __name__=="__main__":unittest.main()
