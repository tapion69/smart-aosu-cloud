"""AOSU 5.10.12 Ty CP UUID identity: offline, no accounts/camera/API."""
import ast
import json
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'custom_components' / 'smart_aosu_cloud'
CP = runpy.run_path(str(BASE / 'c9c_cp_reference_b32.py'))
TOPO = runpy.run_path(str(BASE / 'camera_topology.py'))
extract = CP['extract_c9c_ty_cp_uuid']
choose = TOPO['select_tuya_standalone_target_typed']
SN = 'SYNTHETIC_AOSU_SN'
TYUUID = 'SYNTHETIC_TUYA_UUID'
DEVICEID = 'SYNTHETIC_TUYA_DEVICE_ID'
CPID = 'SYNTHETIC_AOSU_CP_DEVICE_ID'


class TestTyCpUuidIdentity(unittest.TestCase):
    def test_sdk_ty_platform_reads_only_nested_cp_uuid(self):
        case = {'sn': SN, 'deviceId': 'OTHER_AOSU_DEVICE_ID',
                'cpDeviceId': CPID, 'coopUUID': CPID,
                'cpDeviceInfo': {'cpDeviceId': CPID, 'cpUuid': TYUUID}}
        value, source = extract(case)
        self.assertEqual((value, source), (TYUUID, 'cp_uuid_ty_explicite'))
        self.assertNotEqual(value, case['cpDeviceId'])
        self.assertNotEqual(value, case['deviceId'])
        self.assertNotIn(value, json.dumps({'source': source}))
        self.assertEqual(extract({'cpUuid': TYUUID}),
                         (None, 'champ_cp_device_info_absent'))
        self.assertEqual(extract({'cpDeviceInfo': {'cpDeviceId': CPID}}),
                         (None, 'cp_uuid_absent'))

    def test_conflicting_or_malformed_aosu_ty_uuid_does_not_match(self):
        for row in (
            {'cpUuid': 'OTHER', 'cpDeviceInfo': {'cpUuid': TYUUID}},
            {'cpDeviceInfo': {'cpUuid': ' BAD_ID '}},
            {'cpDeviceInfo': {'cpUuid': 123}},
            {'cpDeviceInfo': {'cpUuid': ''}},
        ):
            with self.subTest(row=row):
                uuid, _source = extract(row)
                self.assertIsNone(uuid)

    def test_typed_uuid_links_only_to_tuya_uuid_not_devid(self):
        devices = {'cam': {'devId': DEVICEID, 'uuid': TYUUID,
                           'skills': {'p2pType': 4}}}
        self.assertEqual(choose(devices, camera_sn=SN,
                                camera_ty_cp_uuid=TYUUID),
                         ('cam', 'identite_exacte_ty_cp_uuid'))
        # AOSU Ty cpUuid equalling an arbitrary Tuya devId is not an
        # identity proof: the original implementation conflated these.
        self.assertEqual(
            choose(devices, camera_sn=SN, camera_ty_cp_uuid=DEVICEID),
            ('cam', 'appareil_tuya_unique_sans_categorie_video'))
        self.assertEqual(
            choose({'cam': {'devId': DEVICEID, 'uuid': TYUUID}},
                   camera_sn=SN, camera_cp_device_id=DEVICEID),
            ('cam', 'appareil_tuya_unique_sans_categorie_video'))

    def test_cp_device_id_and_sn_are_independently_typed(self):
        devices = {'cam': {'devId': DEVICEID, 'cpDeviceId': CPID}}
        self.assertEqual(choose(devices, camera_sn=SN,
                                camera_cp_device_id=CPID),
                         ('cam', 'identite_exacte_cp_device_id'))
        self.assertEqual(
            choose({'cam': {'devId': DEVICEID, 'serialNumber': SN}},
                   camera_sn=SN),
            ('cam', 'identite_exacte_serie'))

    def test_ambiguous_or_contradictory_links_never_select_camera(self):
        ambiguous = {
            'one': {'devId': 'one', 'uuid': TYUUID},
            'two': {'devId': 'two', 'cpDeviceId': CPID}}
        self.assertEqual(
            choose(ambiguous,camera_sn=SN,
                   camera_cp_device_id=CPID,camera_ty_cp_uuid=TYUUID),
            (None,'correspondance_ambigue'))
        conflicting = {'cam': {'devId': DEVICEID,
                               'uuid': TYUUID,
                               'deviceInfo': {'uuid': 'OTHER_UUID'}}}
        self.assertEqual(
            choose(conflicting,camera_sn=SN,camera_ty_cp_uuid=TYUUID),
            (None, 'correspondance_ambigue'))
        # The inventory's devId itself cannot contradict the selected key.
        wrong = {'cam': {'devId': 'OTHER_TUYA_DEVICE', 'uuid': TYUUID}}
        self.assertEqual(
            choose(wrong,camera_sn=SN,camera_ty_cp_uuid=TYUUID),
            (None,'correspondance_ambigue'))

    def test_weak_matching_cannot_be_promoted_to_camera_command(self):
        devices={'only': {'devId':'only','skills':{'p2pType':4}}}
        self.assertEqual(choose(devices,camera_sn=SN),
                         ('only','appareil_tuya_unique_sans_categorie_video'))
        route=(BASE/'tuya_rtc_inventory.py').read_text(encoding='utf-8')
        self.assertIn('select_tuya_standalone_target_typed(',route)
        self.assertIn("and selection not in (",route)
        self.assertIn("'c9c_identite_aosu_tuya_non_prouvee'",route)
        self.assertLess(route.index('select_tuya_standalone_target_typed('),
                        route.index("and selection not in ("))
        api=(BASE/'api.py').read_text(encoding='utf-8')
        self.assertIn('extract_c9c_ty_cp_uuid(standalone[0])',api)
        self.assertIn('self._standalone_c9c_ty_cp_uuid=None',api)
        self.assertNotIn('print(', (BASE/'c9c_cp_reference_b32.py').read_text())
        ast.parse(api)
        ast.parse(route)

    def test_existing_c5l_h1l_and_readonly_selector_remain_unchanged(self):
        self.assertTrue(TOPO['has_h1l_video_topology']({
            'base': {'model':'H1L'},
            'c9': {'is_camera':True,'model':'C9C3CA11','via_device':'base'}}))
        self.assertEqual(
            TOPO['select_tuya_standalone_target'](
                {'dev': {'devId':DEVICEID}},
                camera_sn=SN,camera_coop=DEVICEID),
            ('dev','identite_exacte'))
        # Only the active VIDEO/WAKE route uses the stricter selector.
        src=(BASE/'tuya_rtc_inventory.py').read_text(encoding='utf-8')
        self.assertIn('else:\n                    target, selection = select_tuya_standalone_target(',src)


if __name__ == '__main__':
    unittest.main()
