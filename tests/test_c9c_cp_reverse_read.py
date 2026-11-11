"""Offline regression tests for read-only CP reverse lookup. No real account."""
import json
import runpy
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = runpy.run_path(str(ROOT / 'custom_components' / 'smart_aosu_cloud' /
                         'c9c_cp_reverse_read.py'))
probe = NS['probe_c9c_reverse_cp']
check = NS['_check_reply']
candidate = NS['_tuya_candidate']

SN = 'FAKE_SN_TEST_ONLY'
AOSU = 'FAKE_AOSU_ID'
TUYA = 'FAKE_TUYA_DEV_ID'
DETAIL = {'errno': 0, 'data': {'list': [{'sn': SN, 'deviceId': AOSU}]}}
GOOD = {'errno': 0, 'data': {'list': [{'coopUUID': TUYA, 'deviceId': AOSU}]}}


class Reply:
    status_code = 200
    content = b'{}'

    def __init__(self, body):
        self.body = body

    def json(self):
        return self.body


class Session:
    def __init__(self, body):
        self.body = body
        self.calls = 0

    def post(self, endpoint, **kwargs):
        self.calls += 1
        assert endpoint == 'https://api-eu.aosulife.com/v1/dev/getListByCoopUUIDList'
        assert kwargs['data'] == [('coopUUID[]', TUYA)]
        assert kwargs['verify'] is True
        assert kwargs['allow_redirects'] is False
        assert kwargs['timeout'] == (8, 20)
        return Reply(self.body)


class Client:
    def __init__(self, body):
        self.session = Session(body)


def cache(devices=None, age=0):
    return {'created': time.monotonic() - age,
            'devices': devices if devices is not None else {TUYA: {'devId': TUYA}}}


class TestReverseIdentity(unittest.TestCase):
    def run_probe(self, body=GOOD, c=None, detail=DETAIL, known=None):
        client = Client(body)
        result = probe(client, detail, SN, c if c is not None else cache(),
                       params={'signed': 'PRIVATE_SIGNING_PARAMETER'},
                       headers={'Auth': 'PRIVATE_HEADER'},
                       known_aosu_device_id=known)
        return client, result

    def test_exact_reverse_binding_only_with_same_aosu_device(self):
        client, result = self.run_probe()
        self.assertEqual(client.session.calls, 1)
        self.assertEqual(result['etat'], 'liaison_exacte_confirmee')
        self.assertTrue(result['liaison_exacte_confirmee'])
        self.assertEqual(result['appels_http'], 1)
        self.assertFalse(result['video_lancee'])
        self.assertEqual(result['commandes_camera'], 0)
        for private in (SN, AOSU, TUYA, 'PRIVATE_SIGNING_PARAMETER', 'PRIVATE_HEADER'):
            self.assertNotIn(private, json.dumps(result))

    def test_reverse_never_confirms_other_camera(self):
        for wrong in (
            {'errno': 0, 'data': {'list': [{'coopUUID': TUYA, 'deviceId': 'OTHER_CAMERA'}]}},
            {'errno': 0, 'data': {'list': [{'coopUUID': 'OTHER_CP', 'deviceId': AOSU}]}},
            {'errno': 0, 'data': {'list': []}},
            {'errno': 0, 'data': {'list': [
                {'coopUUID': TUYA, 'deviceId': AOSU},
                {'coopUUID': TUYA, 'deviceId': 'OTHER_CAMERA'}]}},
            {'errno': 5, 'data': {'list': [{'coopUUID': TUYA, 'deviceId': AOSU}]}},
            {'errno': 0, 'data': {}},
        ):
            with self.subTest(wrong=wrong):
                client, report = self.run_probe(wrong)
                self.assertEqual(client.session.calls, 1)
                self.assertFalse(report['liaison_exacte_confirmee'])
                self.assertNotEqual(report['etat'], 'liaison_exacte_confirmee')

    def test_not_queried_if_tuya_candidate_is_missing_or_ambiguous(self):
        for c in (
            cache(age=700),
            cache(devices={TUYA: {'devId': TUYA}, 'other': {'devId': 'other'}}),
            cache(devices={TUYA: {'devId': 'OTHER'}}),
            cache(devices={TUYA: {'category': 'gw'}}),
            cache(devices={}),
            {'created': time.monotonic(), 'devices': {TUYA: None}},
        ):
            with self.subTest(c=c):
                client, report = self.run_probe(c=c)
                self.assertEqual(client.session.calls, 0)
                self.assertFalse(report['liaison_exacte_confirmee'])
                self.assertEqual(report['appels_http'], 0)

    def test_no_matching_aosu_serial_or_ambiguous_detail(self):
        for detail in (
            {'errno': 0, 'data': {'list': [{'sn': 'OTHER_SN', 'deviceId': AOSU}]}},
            {'errno': 0, 'data': {'list': [
                {'sn': SN, 'deviceId': AOSU}, {'sn': SN, 'deviceId': 'OTHER_DEVICE'}]}},

        ):
            client, report = self.run_probe(detail=detail)
            self.assertEqual(client.session.calls, 0)
            self.assertEqual(report['etat'], 'numero_serie_aosu_non_confirme')

    def test_missing_aosu_device_id_still_runs_readonly_lookup(self):
        # The real beta33 screen showed SN concordant but no deviceId.
        detail={'errno':0,'data':{'sn':SN}}
        client, report=self.run_probe(detail=detail)
        self.assertEqual(client.session.calls, 1)
        self.assertEqual(report['etat'],
                         'reference_cp_resolue_identite_non_confirmee')
        self.assertTrue(report['reference_cp_resolue'])
        self.assertFalse(report['liaison_exacte_confirmee'])
        self.assertEqual(report['source_device_id_aosu'],'aucune')
        self.assertFalse(report['id_aosu_fiche_present'])
        self.assertFalse(report['id_aosu_inventaire_present'])

    def test_sn_matched_aosu_getlist_can_confirm_reversed_id(self):
        detail={'errno':0,'data':{'sn':SN}}
        client,report=self.run_probe(detail=detail,known=AOSU)
        self.assertEqual(client.session.calls,1)
        self.assertTrue(report['liaison_exacte_confirmee'])
        self.assertEqual(report['source_device_id_aosu'],'inventaire_SN')
        self.assertTrue(report['id_aosu_inventaire_present'])
        self.assertFalse(report['id_aosu_fiche_present'])
        # If the two AOSU endpoints contradict one another, don't query.
        client,report=self.run_probe(known='WRONG_AOSU_ID')
        self.assertEqual(client.session.calls,0)
        self.assertEqual(report['etat'],'identifiants_aosu_contradictoires')

    def test_status_not_proof_when_no_aosu_id_or_contradictory_reverse(self):
        missing={'errno':0,'data':{'sn':SN}}
        client,report=self.run_probe(
            body={'errno':0,'data':{'list':[]}},detail=missing)
        self.assertEqual(report['etat'],'reference_non_resolue')
        self.assertFalse(report['reference_cp_resolue'])
        client,report=self.run_probe(
            body={'errno':0,'data':{'list':[{'coopUUID':TUYA,
                                          'deviceId':'SOME_UNKNOWN_AOSU_ID'}]}},
            detail=missing)
        self.assertEqual(report['etat'],
                         'reference_cp_resolue_identite_non_confirmee')
        self.assertFalse(report['liaison_exacte_confirmee'])
        self.assertNotIn('SOME_UNKNOWN_AOSU_ID',json.dumps(report))

    def test_explicit_cp_field_preferred_to_tuya_dev_id(self):
        c = cache({TUYA: {'devId': TUYA, 'cpDeviceId': 'CP_FROM_TUYA'}})
        selected, kind = candidate(c, now=time.monotonic())
        self.assertEqual((selected, kind), ('CP_FROM_TUYA', 'cp_device_id_tuya'))
        c['devices'][TUYA]['deviceInfo'] = {'cpDeviceId': 'WRONG_CP'}
        self.assertEqual(candidate(c, now=time.monotonic())[1],
                         'references_cp_contradictoires')

    def test_hardcoded_readonly_scope(self):
        source = (ROOT / 'custom_components' / 'smart_aosu_cloud' /
                  'c9c_cp_reverse_read.py').read_text()
        self.assertIn('coopUUID[]', source)
        self.assertIn('allow_redirects=False', source)
        self.assertIn('verify=True', source)
        self.assertNotIn('mqtt_publish(', source)
        self.assertNotIn('wake_c9c', source)
        self.assertNotIn('print(', source)


if __name__ == '__main__':
    unittest.main()
