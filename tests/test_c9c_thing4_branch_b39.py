"""Beta39: Android Thing type-4 route uses CameraInfoBean.id, not p2pId.

Synthetic fixtures only: no camera, account, APK, network, or private data.
"""
import json
import runpy
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]/'custom_components'/'smart_aosu_cloud'
N=runpy.run_path(str(BASE/'c9c_sdk_preflight_b37.py'))
compare=N['compare_rtc_sdk_b38']
K='FAKE_SECRET_DEVICE_REFERENCE'

def rtc(*,kind=4,with_id=True,config=True,p2pid=False):
    data={'p2pSpecifiedType':kind, 'sessionTid':'SENSITIVE_SESSION_TID',
          'p2pPolicy':1, 'sessionId':'SENSITIVE_SESSION_ID',
          'p2pConfig':{'session':{'id':'UNRELATED_NESTED_ICE_ID'}} if config else None}
    if with_id:data['id']=K
    if p2pid:data['p2pId']='OLD_TRANSPORT_ID'
    return {'data':data}

class TestNativeThing4Routing(unittest.TestCase):
    def test_exact_type4_and_camera_info_id_without_legacy_p2pid(self):
        r=compare(rtc(with_id=False),rtc(),
                  ipc_accepted=True,classic_accepted=True)
        sdk=r['rtc_sdk_classique']
        self.assertEqual(sdk['p2p_specified_type_categorie'],'thing_4')
        self.assertTrue(sdk['camera_info_id_racine_present'])
        self.assertTrue(sdk['branche_thing4_compatible_avec_champs'])
        self.assertFalse(sdk['p2p_id'])
        self.assertFalse(r['ipc_v4']['camera_info_id_racine_present'])
        self.assertFalse(r['identite_c9c_etablie'])
        self.assertFalse(r['creation_p2p_effectuee'])
        self.assertFalse(r['video_autorisee'])
        self.assertNotIn(K,json.dumps(r))

    def test_nested_ice_id_must_not_masquer_missing_camera_info_id(self):
        r=compare(rtc(),rtc(with_id=False),
                  ipc_accepted=True,classic_accepted=True)
        sdk=r['rtc_sdk_classique']
        self.assertFalse(sdk['camera_info_id_racine_present'])
        self.assertFalse(sdk['branche_thing4_compatible_avec_champs'])
        self.assertEqual(sdk['p2p_specified_type_categorie'],'thing_4')

    def test_type2_does_not_activate_thing4_regardless_of_p2pid(self):
        r=compare(rtc(),rtc(kind=2,p2pid=True),
                  ipc_accepted=True,classic_accepted=True)
        sdk=r['rtc_sdk_classique']
        self.assertEqual(sdk['p2p_specified_type_categorie'],'p2p_2')
        self.assertTrue(sdk['p2p_id'])
        self.assertFalse(sdk['branche_thing4_compatible_avec_champs'])

    def test_server_values_are_never_relayed_to_home_assistant(self):
        for value,want in ((4,'thing_4'),('4','thing_4'),
                           (2,'p2p_2'),(1,'tutk_1'),
                           ('SECRETS_FROM_SERVER','autre'),
                           (None,'absent'),(7,'autre')):
            with self.subTest(value=value):
                a=rtc(kind=value)
                b=compare(a,a,ipc_accepted=True,classic_accepted=True)
                self.assertEqual(b['rtc_sdk_classique']['p2p_specified_type_categorie'],want)
                self.assertNotIn(K,json.dumps(b))
                self.assertNotIn('SECRETS_FROM_SERVER',json.dumps(b))

    def test_missing_config_or_rejected_endpoint_remains_unproven(self):
        a=compare(rtc(),rtc(config=False),
                  ipc_accepted=True,classic_accepted=True)
        self.assertFalse(a['rtc_sdk_classique']['branche_thing4_compatible_avec_champs'])
        b=compare(rtc(),rtc(),
                  ipc_accepted=True,classic_accepted=False)
        self.assertEqual(b['rtc_sdk_classique']['p2p_specified_type_categorie'],'absent')
        self.assertFalse(b['rtc_sdk_classique']['camera_info_id_racine_present'])
        self.assertFalse(b['rtc_sdk_classique']['branche_thing4_compatible_avec_champs'])

    def test_read_only_flow_and_video_untouched(self):
        src=(BASE/'tuya_rtc_inventory.py').read_text()
        self.assertIn("read('m.ipc.v4.rtc.config.get',{'devId':target})",src)
        self.assertIn("'thing.m.rtc.config.get'",src)
        self.assertNotIn("read('thing.m.rtc.session.init'",src)
        self.assertIn('if standalone_c9c_sdk_b37_audit and (',src)
        self.assertNotIn('mqtt_publish(', (BASE/'c9c_sdk_preflight_b37.py').read_text())

if __name__=='__main__':
    unittest.main()
