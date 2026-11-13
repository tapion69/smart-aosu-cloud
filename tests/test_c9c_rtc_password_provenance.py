"""Real RTC media parser regression: standalone Thing-4 channel-0 credentials.

Synthetic cloud envelopes only. No APK, server, camera, MQTT, network or logs.
"""
import ast
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

BASE=Path(__file__).resolve().parents[1]/'custom_components'/'smart_aosu_cloud'
MOD=BASE/'tuya_media_bootstrap.py'
spec=importlib.util.spec_from_file_location('aosu_test_rtc_password_c9c',MOD)
module=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=module
spec.loader.exec_module(module)
inspect=module.inspect_rtc_media
take=module._c9c_rtc_device_password
UID='SYNTHETIC_UID'
ID='SYNTHETIC_TUYA_ID'
LOCAL='123456789abcdefg'
PASSWORD='SYNTHETIC_RTC_CAMERA_PW'


def fixture(password=PASSWORD):
    config={
        'session':{'sessionId':'SYNTHETIC_SESSION',
                   'aesKey':'00112233445566778899aabbccddeeff',
                   'iceUfrag':'SYNTHETIC_UFRAG',
                   'icePassword':'SYNTHETIC_ICE_PWD'},
        'ices':[{'urls':['turn:relay.invalid:3478']}],
        'tcpRelay':{'username':'SYNTHETIC_RELAY_USER',
                    'credential':'SYNTHETIC_CREDENTIAL',
                    'sessionId':'SYNTHETIC_RELAY_SESSION',
                    'urls':['turn:relay.invalid:443']}}
    return {'success':True,'data':{'password':password,
             'p2pSpecifiedType':4,'id':ID,'p2pConfig':config}}


class TestC9CPasswordFromRTC(unittest.TestCase):
    def test_nested_rtc_password_reaches_real_media_object(self):
        raw=fixture()
        old_report,old_private=inspect(raw,ID,LOCAL,UID)
        new_report,private=inspect(raw,ID,LOCAL,UID,standalone_c9c=True)
        self.assertIsNotNone(old_private)
        self.assertIsNotNone(private)
        # This is the existing actual bug: root-only old path dropped the
        # password already returned in the authenticated data envelope.
        self.assertEqual(old_private.device_password,'')
        self.assertEqual(private.device_password,PASSWORD)
        self.assertEqual(take(raw),PASSWORD)
        self.assertTrue(new_report['offre_sdp_aes_kcp_preparee'])
        self.assertEqual(new_report,old_report)
        self.assertNotIn(PASSWORD,json.dumps(new_report))
        self.assertNotIn(ID,repr(private))
        self.assertNotIn(PASSWORD,repr(private))

    def test_session_auth_digest_is_corrected_only_for_c9c(self):
        raw=fixture()
        _,legacy=inspect(raw,ID,LOCAL,UID)
        _,c9c=inspect(raw,ID,LOCAL,UID,standalone_c9c=True)
        self.assertIsNotNone(legacy)
        self.assertIsNotNone(c9c)
        def auth_hash(password):
            return hashlib.md5((password+'||'+LOCAL).encode(),
                               usedforsecurity=False).hexdigest()
        self.assertNotEqual(auth_hash(legacy.device_password),
                            auth_hash(c9c.device_password))
        self.assertEqual(auth_hash(c9c.device_password),
                         auth_hash(PASSWORD))

    def test_empty_nonstring_long_or_ambiguous_passwords_are_rejected(self):
        for pw in ('',None,42,' ', 'X'*2049,'UNSAFE\nVALUE'):
            with self.subTest(pw=repr(pw)[:25]):
                self.assertEqual(take(fixture(pw)), '')
        corrupted=fixture()
        corrupted['password']='WRONG_ROOT_PASSWORD'
        self.assertEqual(take(corrupted),'')
        same=fixture()
        same['password']=PASSWORD
        self.assertEqual(take(same),PASSWORD)

    def test_only_expected_api_envelopes_not_p2p_or_relay(self):
        sample=fixture()
        self.assertEqual(take({'result':sample['data']}),PASSWORD)
        self.assertEqual(take({'data':{'result':sample['data']}}),PASSWORD)
        self.assertEqual(take({'data':{'p2pConfig':{'session':{
            'password':PASSWORD}}}}),'')
        self.assertEqual(take({'data':{'p2pConfig':{'tcpRelay':{
            'password':PASSWORD}}}}),'')
        self.assertEqual(take({'data':{'deviceInfo':{'password':PASSWORD}}}),'')
        self.assertEqual(take({'data':{'other':{'password':PASSWORD}}}),'')

    def test_legacy_c5l_h1l_route_remains_byte_for_byte_equivalent(self):
        raw=fixture()
        raw['password']='LEGACY_ROOT_PASSWORD'
        _,legacy=inspect(raw,ID,LOCAL,UID)
        self.assertEqual(legacy.device_password,'LEGACY_ROOT_PASSWORD')
        inventory=(BASE/'tuya_rtc_inventory.py').read_text('utf-8')
        self.assertIn('standalone_c9c=(standalone_c9c_video_test is True)',
                      inventory)
        self.assertNotIn('standalone_c9c=True',inventory)
        ast.parse(MOD.read_text('utf-8'))
        ast.parse(inventory)

    def test_no_active_routing_or_camera_network_io_in_password_parser(self):
        source=MOD.read_text('utf-8')
        self.assertNotIn('socket.',source)
        self.assertNotIn('requests.',source)
        self.assertNotIn('mqtt_publish(',source)
        self.assertNotIn('print(',source)


if __name__ == '__main__':
    unittest.main()
