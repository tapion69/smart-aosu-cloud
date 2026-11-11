"""Offline tests: single CP lookup, exact SDK response fields, safe telemetry."""
import json
import runpy
import unittest
from pathlib import Path

P=Path(__file__).resolve().parents[1]/'custom_components'/'smart_aosu_cloud'/'c9c_cp_reverse_read.py'
N=runpy.run_path(str(P))
pick=N['_one_sdk_cp_reference']
read=N['_single_sdk_reply']

def parsed(rows):
    return {'errno':0,'data':{'list':rows}}

class TestSDKCPUnique(unittest.TestCase):
    def test_sdk_prioritizes_specific_real_tuya_uuid(self):
        inputs=[('dev_id_tuya','TUYA_REAL_DEV_ID'),
                ('uuid_tuya','TUYA_REAL_UUID')]
        self.assertEqual(pick(inputs),('uuid_tuya','TUYA_REAL_UUID'))
        self.assertEqual(pick([('dev_id_tuya','TUYA_REAL_DEV_ID')]),
                         ('dev_id_tuya','TUYA_REAL_DEV_ID'))
        self.assertEqual(pick(inputs+[('cp_uuid_tuya','TUYA_REAL_CP_UUID')]),
                         ('cp_uuid_tuya','TUYA_REAL_CP_UUID'))
        self.assertIsNone(pick([('untrusted','secret')]))
        self.assertIsNone(pick([('uuid_tuya',' BAD UUID ')]))

    def test_sdk_item_all_identity_fields_missing_as_seen_in_beta35(self):
        # Synthetic shape representing a server reply with entries but without
        # either SDK identity field. Never claim the UUID was resolved.
        status,source,proven,shape=read(
            parsed([{'devModel':'C9C','devType':2,'svcType':'ty'}]),
            'uuid_tuya','TUYA_REAL_UUID',None)
        self.assertEqual(status,'reponse_sans_coop_uuid')
        self.assertFalse(proven)
        self.assertEqual(source,'aucune')
        self.assertEqual(shape['entrees'],1)
        self.assertFalse(shape['coop_uuid_present'])
        self.assertFalse(shape['device_id_present'])
        self.assertTrue(shape['dev_model_present'])
        self.assertTrue(shape['dev_type_present'])
        self.assertTrue(shape['svc_type_present'])
        self.assertNotIn('C9C',json.dumps(shape))

    def test_returned_uuid_without_device_id_is_not_proof(self):
        status,source,proven,shape=read(
            parsed([{'coopUUID':'TUYA_REAL_UUID','deviceId':None}]),
            'uuid_tuya','TUYA_REAL_UUID',None)
        self.assertEqual(status,'coop_uuid_retourne_sans_device_id')
        self.assertEqual(source,'uuid_tuya')
        self.assertFalse(proven)
        self.assertTrue(shape['coop_uuid_egal_demande'])
        self.assertFalse(shape['device_id_present'])

    def test_complete_result_not_proven_without_serial_bound_aosu_id(self):
        body=parsed([{'coopUUID':'TUYA_REAL_UUID',
                      'deviceId':'SECRET_AOSU_DEVICE_ID'}])
        state,source,present,shape=read(
            body,'uuid_tuya','TUYA_REAL_UUID',None)
        self.assertEqual(state,'reference_cp_resolue_identite_non_confirmee')
        self.assertTrue(present)
        self.assertNotIn('SECRET_AOSU_DEVICE_ID',json.dumps(shape))
        state,_,present,_=read(
            body,'uuid_tuya','TUYA_REAL_UUID','SECRET_AOSU_DEVICE_ID')
        self.assertEqual(state,'liaison_exacte_confirmee')
        self.assertTrue(present)
        state,_,present,_=read(
            body,'uuid_tuya','TUYA_REAL_UUID','ANOTHER_CAMERA_ID')
        self.assertEqual(state,'autre_appareil_aosu')
        self.assertTrue(present)

    def test_multiple_or_wrong_item_remains_unproven(self):
        responses=[
            (parsed([{'coopUUID':'TUYA_REAL_UUID','deviceId':'D'},
                     {'coopUUID':'OTHER','deviceId':'D'}]),
             'reponse_plusieurs_entrees_non_concluante'),
            (parsed([{'coopUUID':'OTHER','deviceId':'D'}]),
             'reference_cp_incoherente'),
            (parsed([]), 'reference_non_resolue'),
        ]
        for raw,want in responses:
            with self.subTest(want=want):
                state,source,found,shape=read(
                    raw,'uuid_tuya','TUYA_REAL_UUID',None)
                self.assertEqual(state,want)
                self.assertFalse(found)
                self.assertEqual(source,'aucune')

if __name__=='__main__': unittest.main()
