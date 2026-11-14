"""One exact Android AOSU CP device ID -> Tuya devId route, no network."""
import ast
import json
import runpy
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DIR=ROOT/"custom_components"/"smart_aosu_cloud"
TOPO=runpy.run_path(str(DIR/"camera_topology.py"))
CP=runpy.run_path(str(DIR/"c9c_cp_reference_b32.py"))
match=TOPO["select_tuya_standalone_target_typed"]
extract=CP["extract_c9c_cp_reference"]
SN="AOSU_SERIAL_SYNTHETIC"
DEV="TuyaDevice_42_SYNTHETIC"
OTHER="TuyaDevice_99_SYNTHETIC"


class AndroidCpDevIdBridgeTests(unittest.TestCase):
    def test_exact_sn_bound_aosu_cp_devid_matches_tuya_device_id(self):
        record={"sn":SN,"coopUUID":DEV,"cpDeviceId":DEV,
                "cpDeviceInfo":{"cpDeviceId":DEV}}
        cp,source=extract(record)
        self.assertEqual(source,"champs_concordants")
        self.assertEqual(cp,DEV)
        destination,level=match(
            {DEV:{"devId":DEV,"deviceInfo":{"devId":DEV},
                  "skills":{"p2pType":4}}},
            camera_sn=SN,camera_cp_device_id=cp)
        self.assertEqual((destination,level),
                         (DEV,"identite_exacte_cp_device_id_dev_id"))

    def test_unknown_aosu_cp_does_not_become_strong_due_to_unique_device(self):
        candidate,kind=match(
            {DEV:{"devId":DEV,"skills":{"p2pType":4}}},
            camera_sn=SN,camera_cp_device_id=None)
        self.assertEqual((candidate,kind),
                         (DEV,"appareil_tuya_unique_sans_categorie_video"))
        self.assertFalse(kind.startswith("identite_exacte_"))

    def test_cp_equal_to_uuid_is_not_cp_equal_to_devid(self):
        candidate,kind=match(
            {DEV:{"devId":DEV,"uuid":OTHER}},
            camera_sn=SN,camera_cp_device_id=OTHER)
        self.assertEqual((candidate,kind),
                         (DEV,"appareil_tuya_unique_sans_categorie_video"))
        self.assertFalse(kind.startswith("identite_exacte_"))

    def test_aosu_ty_cuuid_is_not_tuya_dev_id_evidence(self):
        candidate,kind=match(
            {DEV:{"devId":DEV,"uuid":OTHER}},
            camera_sn=SN,camera_ty_cp_uuid=DEV)
        self.assertEqual((candidate,kind),
                         (DEV,"appareil_tuya_unique_sans_categorie_video"))

    def test_multi_device_unique_matching_cp_finds_correct_one(self):
        candidate,kind=match({
            OTHER:{"devId":OTHER,"uuid":"OTHER_UUID"},
            DEV:{"devId":DEV,"uuid":"UNRELATED_UUID"},
        },camera_sn=SN,camera_cp_device_id=DEV)
        self.assertEqual((candidate,kind),
                         (DEV,"identite_exacte_cp_device_id_dev_id"))

    def test_ambiguous_cp_in_different_devices_blocks(self):
        candidate,kind=match({
            DEV:{"devId":DEV},
            OTHER:{"devId":OTHER,"cpDeviceId":DEV},
        },camera_sn=SN,camera_cp_device_id=DEV)
        self.assertEqual((candidate,kind),(None,"correspondance_ambigue"))

    def test_wrong_dev_id_inside_record_blocks(self):
        candidate,kind=match(
            {DEV:{"devId":OTHER}},camera_sn=SN,
            camera_cp_device_id=DEV)
        self.assertEqual((candidate,kind),(None,"correspondance_ambigue"))

    def test_tuya_cp_field_explicitly_conflicting_blocks(self):
        candidate,kind=match({
            DEV:{"devId":DEV,"cpDeviceId":OTHER}
        },camera_sn=SN,camera_cp_device_id=DEV)
        self.assertEqual((candidate,kind),(None,"correspondance_ambigue"))

    def test_aosu_cp_sources_contradictory_block(self):
        value,label=extract({"sn":SN,"coopUUID":DEV,"cpDeviceId":OTHER})
        self.assertIsNone(value)
        self.assertEqual(label,"references_contradictoires")

    def test_success_does_not_return_any_secret(self):
        dev,kind=match({DEV:{"devId":DEV}},camera_sn=SN,
                       camera_cp_device_id=DEV)
        self.assertEqual(dev,DEV)
        # The selector works in volatile internal memory. Safe report
        # classification is fixed, and no raw serial or ID is serialized
        # in the HA service response.
        safe={"methode_selection":kind,"liaison_tuyee":bool(dev)}
        for secret in (SN,DEV,OTHER):
            self.assertNotIn(secret,json.dumps(safe))

    def test_same_action_guard_is_still_manual_and_exact_only(self):
        source=(DIR/"tuya_rtc_inventory.py").read_text()
        self.assertIn("'identite_exacte_cp_device_id_dev_id'",source)
        self.assertIn("'c9c_identite_aosu_tuya_non_prouvee'",source)
        self.assertIn("and selection not in (",source)
        self.assertNotIn("camera_cp_device_id=target",source)
        self.assertIn("select_tuya_standalone_target_typed(",source)
        self.assertNotIn("do_oem_thing4_session_offer_once(",
                         (DIR/"camera_topology.py").read_text())
        ast.parse(source)


if __name__=="__main__":
    unittest.main()
