"""Read-only beta38: compare Android SDK RTC config API to IPC-v4.

No actual network, APK or account. Test data is synthetic and fully private.
"""
import json
import runpy
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'custom_components'/'smart_aosu_cloud'
NS=runpy.run_path(str(BASE/'c9c_sdk_preflight_b37.py'))
compare=NS['compare_rtc_sdk_b38']
V4={'data':{'p2pConfig':{'session':{'sessionId':'SECRET_V4_SESSION'}},
            'sessionTid':'SECRET_V4_TID','p2pPolicy':'PRIVATE_POLICY'}}
CLASSIC={'data':{'p2pId':'SECRET_CLASSIC_P2P_ID',
                 'p2pConfig':'{"opaque":"SECRET_CONFIGURATION"}',
                 'sessionTid':'SECRET_CLASSIC_TID',
                 'p2pPolicy':'PRIVATE_POLICY2',
                 'p2pSpecifiedType':4,
                 'password':'PRIVATE_CAMERA_PASSWORD',
                 'token':'PRIVATE_TUYA_TOKEN',
                 'skill':'PRIVATE_CAPABILITY_TEXT'}}


class TestRtcComparisonB38(unittest.TestCase):
    def test_classic_contains_unique_p2p_id_but_never_proves_camera(self):
        r=compare(V4,CLASSIC,ipc_accepted=True,classic_accepted=True)
        self.assertTrue(r['ipc_v4']['acceptee'])
        self.assertTrue(r['rtc_sdk_classique']['acceptee'])
        self.assertEqual(r['ipc_v4']['p2p_config_format'],'objet')
        self.assertEqual(r['rtc_sdk_classique']['p2p_config_format'],'chaine')
        self.assertTrue(r['p2p_id_seulement_classique'])
        self.assertTrue(r['rtc_sdk_classique']['p2p_id'])
        self.assertFalse(r['ipc_v4']['p2p_id'])
        self.assertTrue(r['rtc_sdk_classique']['session_tid'])
        self.assertTrue(r['rtc_sdk_classique']['p2p_specified_type'])
        self.assertTrue(r['client_tid_produit_localement_par_sdk'])
        self.assertFalse(r['session_init_appelee'])
        for flag in ('identite_c9c_etablie','creation_p2p_effectuee',
                     'video_autorisee','secrets_retournes','identifiants_retournes'):
            self.assertFalse(r[flag])
        for count in ('appels_reseau_supplementaires','commandes_camera',
                      'commandes_ptz','offres_mqtt'):
            self.assertEqual(r[count],0)
        safe=json.dumps(r)
        for val in ('SECRET_V4_SESSION','SECRET_V4_TID',
                    'SECRET_CLASSIC_P2P_ID','SECRET_CONFIGURATION',
                    'PRIVATE_POLICY','PRIVATE_POLICY2',
                    'SECRET_CLASSIC_TID','PRIVATE_CAMERA_PASSWORD',
                    'PRIVATE_TUYA_TOKEN','PRIVATE_CAPABILITY_TEXT'):
            self.assertNotIn(val,safe)

    def test_no_false_p2p_id_when_neither_api_returns_it(self):
        a={'data':{'p2pConfig':{},'sessionTid':'X'}}
        b={'data':{'p2pConfig':'encryp-opaque','p2pPolicy':4}}
        r=compare(a,b,ipc_accepted=True,classic_accepted=True)
        self.assertTrue(r['p2p_id_absent_des_deux'])
        self.assertFalse(r['p2p_id_seulement_classique'])
        self.assertFalse(r['rtc_sdk_classique']['p2p_id'])
        self.assertFalse(r['video_autorisee'])

    def test_refused_classic_does_not_inspect_server_data(self):
        r=compare(V4,CLASSIC,ipc_accepted=True,classic_accepted=False)
        self.assertFalse(r['rtc_sdk_classique']['acceptee'])
        self.assertFalse(r['rtc_sdk_classique']['p2p_id'])
        self.assertEqual(r['rtc_sdk_classique']['p2p_config_format'],'absent')
        self.assertTrue(r['ipc_v4']['session_tid'])
        self.assertFalse(r['video_autorisee'])

    def test_rtc_config_string_not_decoded_or_emitted(self):
        r=compare({'data':{'p2pConfig':'{not:json:SECRET2'}},
                  {'data':{'p2pConfig':'{not:json:SECRET3'}},
                  ipc_accepted=True,classic_accepted=True)
        self.assertEqual(r['ipc_v4']['p2p_config_format'],'chaine')
        self.assertEqual(r['rtc_sdk_classique']['p2p_config_format'],'chaine')
        self.assertNotIn('SECRET2',json.dumps(r))
        self.assertNotIn('SECRET3',json.dumps(r))

    def test_manual_reader_never_initializes_rtc_session(self):
        code=(BASE/'tuya_rtc_inventory.py').read_text()
        self.assertIn("read('thing.m.rtc.config.get',{'devId':target})",code)
        self.assertIn("read('m.ipc.v4.rtc.config.get',{'devId':target})",code)
        self.assertNotIn("read('thing.m.rtc.session.init'",code)
        self.assertIn('if standalone_c9c_sdk_b37_audit and (',code)
        self.assertIn('or tester_mqtt or tester_offre_mqtt',code)


if __name__=='__main__':
    unittest.main()
