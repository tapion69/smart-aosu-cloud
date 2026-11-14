"""AOSU 5.10.12 Ty CP UUID identity: offline, no accounts/camera/API."""
import ast
import json
import runpy
import time
import types
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
        devices = {DEVICEID: {'devId': DEVICEID, 'uuid': TYUUID,
                           'skills': {'p2pType': 4}}}
        self.assertEqual(choose(devices, camera_sn=SN,
                                camera_ty_cp_uuid=TYUUID),
                         (DEVICEID, 'identite_exacte_ty_cp_uuid'))
        # AOSU Ty cpUuid equalling an arbitrary Tuya devId is not an
        # identity proof: the original implementation conflated these.
        self.assertEqual(
            choose(devices, camera_sn=SN, camera_ty_cp_uuid=DEVICEID),
            (DEVICEID, 'appareil_tuya_unique_sans_categorie_video'))
        # AOSU SDK TyDeviceCenter reads GzDeviceInfo.cpDeviceId and passes
        # that exact value to createCameraP2P(devId). This is a distinct
        # verified SDK route from incorrectly comparing Ty cpUuid to devId.
        self.assertEqual(
            choose({DEVICEID: {'devId': DEVICEID, 'uuid': TYUUID}},
                   camera_sn=SN, camera_cp_device_id=DEVICEID),
            (DEVICEID, 'identite_exacte_cp_device_id_dev_id'))

    def test_cp_device_id_and_sn_are_independently_typed(self):
        devices = {DEVICEID: {'devId': DEVICEID, 'cpDeviceId': CPID}}
        self.assertEqual(choose(devices, camera_sn=SN,
                                camera_cp_device_id=CPID),
                         (DEVICEID, 'identite_exacte_cp_device_id'))
        self.assertEqual(
            choose({DEVICEID: {'devId': DEVICEID, 'serialNumber': SN}},
                   camera_sn=SN),
            (DEVICEID, 'identite_exacte_serie'))

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

    def test_private_same_session_detail_uuid_report_never_sends_video(self):
        inspect = runpy.run_path(
            str(BASE / 'c9c_identity_diagnostic.py')
        )['inspect_c9c_identity_cache']
        client = types.SimpleNamespace(
            _standalone_c9c_sn=SN,
            _standalone_c9c_coop_id=None,
            _standalone_c9c_ty_cp_uuid=TYUUID,
            _c9c_reverse_uuid_cache={
                'created':time.monotonic(),
                'session_uid':'FAKE_SESSION_UID',
                'target':DEVICEID,
                'candidates':(('uuid_tuya',TYUUID),)
            }
        )
        data={'camera':{'is_camera':True,'model':'C9C','via_device':None}}
        cache={'created':time.monotonic(),
               'session_uid':'FAKE_SESSION_UID',
               'devices':{DEVICEID:{'devId':DEVICEID}}}
        result=inspect(
            data=data,client=client,cache=cache,
            select_standalone=TOPO['select_standalone_c9c_key'],
            select_tuya=TOPO['select_tuya_standalone_target'],
            select_tuya_typed=choose)
        comparison=result['comparaison_ty_cp_uuid']
        self.assertTrue(comparison['ty_cp_uuid_aosu_present'])
        self.assertTrue(comparison['uuid_tuya_present'])
        self.assertTrue(comparison['concordance_directe'])
        self.assertFalse(result['correspondance']['identite_exacte_confirmee'])
        self.assertFalse(result['video_lancee'])
        self.assertEqual(result['commandes_camera'],0)
        for secret in (TYUUID,DEVICEID,SN,'FAKE_SESSION_UID'):
            self.assertNotIn(secret,json.dumps(result))
        client._c9c_reverse_uuid_cache['session_uid']='OTHER_SESSION'
        bad=inspect(
            data=data,client=client,cache=cache,
            select_standalone=TOPO['select_standalone_c9c_key'],
            select_tuya=TOPO['select_tuya_standalone_target'],
            select_tuya_typed=choose)
        self.assertFalse(bad['comparaison_ty_cp_uuid']['concordance_directe'])

    def test_tuya_uuid_presence_is_independent_from_aosu_uuid(self):
        inspect = runpy.run_path(str(BASE / 'c9c_identity_diagnostic.py'))[
            'inspect_c9c_identity_cache']
        client = types.SimpleNamespace(
            _standalone_c9c_sn=SN,
            _standalone_c9c_coop_id=None,
            _standalone_c9c_ty_cp_uuid=None,
            _c9c_reverse_uuid_cache={
                'created':time.monotonic(),
                'session_uid':'FAKE_SESSION_UID',
                'target':DEVICEID,
                'candidates':(('uuid_tuya',TYUUID),)
            })
        report=inspect(
            data={'camera':{'is_camera':True,'model':'C9C','via_device':None}},
            client=client,
            cache={'created':time.monotonic(),
                   'session_uid':'FAKE_SESSION_UID',
                   'devices':{DEVICEID:{'devId':DEVICEID}}},
            select_standalone=TOPO['select_standalone_c9c_key'],
            select_tuya=TOPO['select_tuya_standalone_target'],
            select_tuya_typed=choose)
        cp=report['comparaison_ty_cp_uuid']
        self.assertFalse(cp['ty_cp_uuid_aosu_present'])
        self.assertTrue(cp['fiche_tuya_uuid_recente'])
        self.assertTrue(cp['uuid_tuya_present'])
        self.assertFalse(cp['concordance_directe'])
        self.assertFalse(report['video_lancee'])
        for val in (TYUUID,DEVICEID,SN,'FAKE_SESSION_UID'):
            self.assertNotIn(val,json.dumps(report))

    def test_card_b43_uses_new_versioned_resource_and_backend_marker(self):
        init=(BASE/'__init__.py').read_text(encoding='utf-8')
        js=(BASE/'frontend/c9c-autonome-b1.js').read_text(encoding='utf-8')
        self.assertIn("'/smart-aosu/c9c-autonome-b42.js'",init)
        self.assertIn("'/smart-aosu/c9c-autonome-b43.js'",init)
        self.assertIn("'/smart-aosu/c9c-autonome-b1.js'",init)
        self.assertIn("result['version_diagnostic']='b43'",init)
        self.assertIn("Carte b43 ; diagnostic serveur",js)
        self.assertIn('cpUuid Ty AOSU présent',js)
        self.assertIn('UUID Tuya récent',js)
        self.assertIn('cpUuid AOSU = UUID Tuya',js)

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
