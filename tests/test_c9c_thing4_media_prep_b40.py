"""Beta40: REAL Python SDP builder on synthetic Thing-4 RTC data, never sent.

No user credentials, network, camera or vendor APK. The route uses exactly the
same inspect_rtc_media function as the existing Smart AOSU video engine.
"""
import importlib.util
import json
import runpy
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'custom_components'/'smart_aosu_cloud'
N=runpy.run_path(str(BASE/'c9c_sdk_preflight_b37.py'))
align=N['summarize_thing4_media_alignment_b40']
spec=importlib.util.spec_from_file_location(
    'aosu_test_private_media_bootstrap',BASE/'tuya_media_bootstrap.py')
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
inspect=module.inspect_rtc_media
TARGET='FAKE_OWN_DEVICE_ID'
KEY='abcdefgh12345678'
UID='FAKE_USER'
AES='00112233445566778899aabbccddeeff'


def rtc(ident=TARGET, *, mode=4, full=True):
    blob={
       'session':{
          'sessionId':'PRIVATE_SESSION_ID',
          'aesKey':AES,
          'iceUfrag':'PRIVATE_ICE_UFRAG',
          'icePassword':'PRIVATE_ICE_PASSWORD',
          'traceId':'PRIVATE_TRACE_ID'},
       'ices':[{'urls':['turn:example.invalid:3478']}],
       'tcpRelay':{'username':'PRIVATE_RELAY_USER',
                   'credential':'PRIVATE_RELAY_CREDENTIAL',
                   'sessionId':'PRIVATE_RELAY_SESSION',
                   'urls':['turn:example.invalid:443']},
       'log':{'private':'NOT_PUBLIC'}}
    if not full:blob['session'].pop('icePassword')
    return {'data':{'id':ident,'p2pSpecifiedType':mode,
                    'p2pConfig':blob, 'sessionTid':'PRIVATE_TID'}}


class TestThing4MediaPrepB40(unittest.TestCase):
    def run_alignment(self, c=None, v=None, *, target=TARGET,
                      classic_accepted=True):
        c=rtc() if c is None else c
        v=rtc() if v is None else v
        classic_report, classic_private=inspect(c,TARGET,KEY,UID)
        v4_report,v4_private=inspect(v,TARGET,KEY,UID)
        summary=align(classic=c,target=target,
                      classic_accepted=classic_accepted,
                      v4_media=v4_report,
                      classic_media=classic_report)
        return summary,classic_private,v4_private

    def test_both_real_sdp_generators_can_prepare_without_sending(self):
        r,cm,vm=self.run_alignment()
        self.assertIsNotNone(cm)
        self.assertIsNotNone(vm)
        self.assertIn('AES/KCP',cm.sdp_offer)
        self.assertTrue(r['preparation_python_ipc_v4_possible'])
        self.assertTrue(r['preparation_python_sdk_classique_possible'])
        self.assertEqual(r['rtc_id_egale_dev_id_tuya'],'identifiant_tuya_egal')
        self.assertTrue(r['sdk_classique_et_python_alignes_sur_champs'])
        self.assertTrue(r['config_p2p_objet_present'])
        self.assertTrue(r['type_classique_thing4'])
        for false_flag in (
            'sdk_native_thing4_execute','parite_json_fastjson_validee',
            'parite_signalisation_native_validee','identite_aosu_c9c_prouvee',
            'offre_sdp_envoyee'):
            self.assertFalse(r[false_flag])
        for marker in (
            TARGET,UID,KEY,AES,'PRIVATE_SESSION_ID','PRIVATE_ICE_PASSWORD',
            'PRIVATE_RELAY_USER','PRIVATE_TID','PRIVATE_TRACE_ID'):
            self.assertNotIn(marker,json.dumps(r))
        self.assertEqual(repr(cm),'<PrivateMediaBootstrap redacted>')

    def test_mismatched_rtc_id_is_never_silently_authorized(self):
        r,_,_=self.run_alignment(c=rtc('OTHER_DEVICE'))
        self.assertEqual(r['rtc_id_egale_dev_id_tuya'],'identifiant_tuya_different')
        self.assertFalse(r['sdk_classique_et_python_alignes_sur_champs'])
        self.assertFalse(r['identite_aosu_c9c_prouvee'])

    def test_missing_credentials_blocks_python_builder(self):
        r,cm,_=self.run_alignment(c=rtc(full=False))
        self.assertIsNone(cm)
        self.assertFalse(r['preparation_python_sdk_classique_possible'])
        self.assertFalse(r['sdk_classique_et_python_alignes_sur_champs'])

    def test_type2_must_not_claim_thing4(self):
        r,_,_=self.run_alignment(c=rtc(mode=2))
        self.assertFalse(r['type_classique_thing4'])
        self.assertFalse(r['sdk_classique_et_python_alignes_sur_champs'])

    def test_read_only_manual_service_uses_same_media_function(self):
        src=(BASE/'tuya_rtc_inventory.py').read_text()
        self.assertIn('summarize_thing4_media_alignment_b40(',src)
        self.assertIn('report, _volatile = inspect_rtc_media(',src)
        self.assertIn("selection != 'identite_exacte'",src)
        self.assertIn("'c9c_identite_aosu_tuya_non_prouvee'",src)
        self.assertLess(src.index("selection != 'identite_exacte'"),
                        src.index("run_tuya_mqtt_offer("))
        self.assertNotIn("read('thing.m.rtc.session.init'",src)
        preflight=(BASE/'c9c_sdk_preflight_b37.py').read_text()
        self.assertNotIn('run_tuya_mqtt_offer(',preflight)
        self.assertNotIn('mqtt_publish(',preflight)


if __name__=='__main__':
    unittest.main()
