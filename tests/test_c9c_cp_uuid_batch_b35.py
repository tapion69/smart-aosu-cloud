"""C9C UUID source and privacy regression (beta35 discovery, beta36 isolation)."""
import json
import runpy
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'custom_components/smart_aosu_cloud/c9c_cp_reverse_read.py'
N=runpy.run_path(str(SCRIPT))
SN='FAKE_SN_B35'
DID='FAKE_TUYA_DEVICE_ID'
UUID='FAKE_TUYA_UUID'
CPUUID='FAKE_TUYA_CPUUID'
AOSU_ID='FAKE_AOSU_DEVICE_ID'


def inventory():
    return {'created':time.monotonic(),
            'devices':{DID:{'devId':DID}}}


def detail_payload():
    return {'data':{'devId':DID,'uuid':UUID,
                    'deviceInfo':{'cpUuid':CPUUID},
                    'localKey':'PRIVATE_TUYA_KEY'}}


def retained():
    return {'created':time.monotonic(),'target':DID,
            'candidates':N['extract_tuya_detail_cp_candidates'](
                detail_payload(),DID)}


class Response:
    status_code=200
    content=b'{}'
    def __init__(self,body):self._body=body
    def json(self):return self._body


class HTTP:
    def __init__(self,body):
        self.calls=[]
        self.body=body
    def post(self,url,**kwargs):
        self.calls.append((url,kwargs))
        assert url.endswith('/v1/dev/getListByCoopUUIDList')
        assert kwargs['verify'] is True
        assert kwargs['allow_redirects'] is False
        assert kwargs['timeout']==(8,20)
        return Response(self.body)


class Client:
    def __init__(self,body):self.session=HTTP(body)


def reply(rows):
    return {'errno':0,'data':{'list':rows}}


def run(body, *, aosu_id=None, dcache=None, inventory_cache=None):
    client=Client(body)
    result=N['probe_c9c_reverse_cp'](
        client,{'errno':0,'data':{'sn':SN}},SN,
        inventory_cache if inventory_cache is not None else inventory(),
        params={'auth':'PRIVATE_SIGNED_PARAM'},
        headers={'sid':'PRIVATE_SID'},
        known_aosu_device_id=aosu_id,
        tuya_detail_cache=dcache if dcache is not None else retained())
    return client,result


class TestUUIDBatchB35(unittest.TestCase):
    def test_real_uuid_from_same_tuya_device_only(self):
        entries=N['extract_tuya_detail_cp_candidates'](detail_payload(),DID)
        self.assertEqual(entries,(('uuid_tuya',UUID),('cp_uuid_tuya',CPUUID)))
        self.assertEqual(
            N['extract_tuya_detail_cp_candidates'](
                {'data':{'devId':'OTHER_DEVICE','uuid':UUID}},DID),())
        self.assertEqual(
            N['extract_tuya_detail_cp_candidates'](
                {'data':{'uuid':UUID}},DID),())
        self.assertEqual(
            N['extract_tuya_detail_cp_candidates'](
                {'data':{'devId':DID,'productBean':{'uuid':'PRODUCT_UUID'}}},DID),())

    def test_one_uuid_sdk_style_request_and_no_proof_without_aosu_id(self):
        c,r=run(reply([{'coopUUID':CPUUID,'deviceId':AOSU_ID}]))
        self.assertEqual(r['etat'],'reference_cp_resolue_identite_non_confirmee')
        self.assertFalse(r['liaison_exacte_confirmee'])
        self.assertTrue(r['reference_cp_resolue'])
        self.assertEqual(r['type_reference_resolue'],'cp_uuid_tuya')
        self.assertEqual(r['type_reference_testee'],'cp_uuid_tuya')
        self.assertEqual(r['candidats_cp_disponibles'],3)
        self.assertEqual(r['candidats_cp_essayes'],1)
        self.assertEqual(len(c.session.calls),1)
        values=c.session.calls[0][1]['data']
        self.assertEqual(values,[('coopUUID[]',CPUUID)])
        for secret in (SN,DID,UUID,CPUUID,AOSU_ID,'PRIVATE_TUYA_KEY',
                       'PRIVATE_SIGNED_PARAM','PRIVATE_SID'):
            self.assertNotIn(secret,json.dumps(r))

    def test_only_full_aosu_sn_link_can_prove_identity(self):
        c,r=run(reply([{'coopUUID':CPUUID,'deviceId':AOSU_ID}]),aosu_id=AOSU_ID)
        self.assertEqual(r['etat'],'liaison_exacte_confirmee')
        self.assertTrue(r['liaison_exacte_confirmee'])
        self.assertEqual(r['type_reference_resolue'],'cp_uuid_tuya')
        self.assertEqual(r['commandes_camera'],0)
        c,r=run(reply([{'coopUUID':CPUUID,'deviceId':'DIFFERENT_AOSU'}]),
                aosu_id=AOSU_ID)
        self.assertEqual(r['etat'],'autre_appareil_aosu')
        self.assertFalse(r['liaison_exacte_confirmee'])

    def test_multi_answer_and_unknown_reference_fail_closed(self):
        for rows,state in [
            ([{'coopUUID':UUID,'deviceId':AOSU_ID},
              {'coopUUID':CPUUID,'deviceId':AOSU_ID}],
             'reponse_plusieurs_entrees_non_concluante'),
            ([{'coopUUID':'UNKNOWN_CP','deviceId':AOSU_ID}],
             'reference_cp_incoherente'),
            ([], 'reference_non_resolue'),
        ]:
            with self.subTest(state=state):
                c,r=run(reply(rows),aosu_id=AOSU_ID)
                self.assertEqual(r['etat'],state)
                self.assertFalse(r['liaison_exacte_confirmee'])

    def test_expired_or_mismatched_detail_is_never_used(self):
        for detail in [
            {'created':time.monotonic()-800,'target':DID,
             'candidates':(('uuid_tuya',UUID),)},
            {'created':time.monotonic(),'target':'OTHER_DEVICE',
             'candidates':(('uuid_tuya',UUID),)},
            {'created':time.monotonic(),'target':DID,
             'candidates':(('unrecognized_field',UUID),)},
        ]:
            with self.subTest(detail=detail['target']):
                c,r=run(reply([]),dcache=detail)
                self.assertEqual(len(c.session.calls),1)
                self.assertEqual(c.session.calls[0][1]['data'],
                                 [('coopUUID[]',DID)])
                self.assertEqual(r['candidats_cp_essayes'],1)

    def test_fresh_uuid_can_reuse_30min_same_account_inventory(self):
        inv=inventory()
        inv['created']=time.monotonic()-1200
        client,result=run(reply([{'coopUUID':CPUUID,'deviceId':AOSU_ID}]),
                          inventory_cache=inv)
        self.assertEqual(len(client.session.calls),1)
        self.assertEqual(result['candidats_cp_disponibles'],3)
        self.assertEqual(result['candidats_cp_essayes'],1)
        self.assertEqual(result['type_reference_resolue'],'cp_uuid_tuya')
        self.assertFalse(result['liaison_exacte_confirmee'])
        inv['created']=time.monotonic()-1900
        client,result=run(reply([]),inventory_cache=inv)
        self.assertEqual(len(client.session.calls),0)
        self.assertEqual(result['etat'],'inventaire_tuya_expire')

    def test_no_camera_or_secrets_in_source(self):
        src=SCRIPT.read_text()
        self.assertIn("allow_redirects=False",src)
        self.assertIn("verify=True",src)
        for forbidden in ('mqtt_publish(', 'start_video(', 'wake_c9c(', 'print('):
            self.assertNotIn(forbidden,src)


if __name__=='__main__':
    unittest.main()
