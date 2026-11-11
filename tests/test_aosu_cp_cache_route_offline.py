"""Offline identity-cache tests: no APK, account, camera or external network."""
import json
import runpy
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
TOOL=runpy.run_path(str(ROOT/'tools'/'aosu_cp_cache_route_offline.py'))
TOPOLOGY=runpy.run_path(str(ROOT/'custom_components'/'smart_aosu_cloud'/'camera_topology.py'))

class Stub:
    def __init__(self,valid=True):self.valid=valid
    def method(self,*_):return b'synthetic' if self.valid else b''
    def calls(self,*_):return self.valid
    def field_access(self,*_):return self.valid

class TestOfflineCPCacheRouting(unittest.TestCase):
    def test_static_facts_never_claim_runtime_identity(self):
        r=TOOL['summarize']({'classes11.dex':Stub(),'classes15.dex':Stub()},17)
        self.assertEqual(len(r['facts']),14)
        self.assertTrue(r['facts']['repository_joins_aosu_tuya_by_cp_id'])
        self.assertTrue(r['facts']['platform_selector_reads_cp_uuid'])
        self.assertEqual(r['diagnostic'],'aosu_cp_cache_route_offline_v4')
        self.assertTrue(all(r['facts'].values()))
        self.assertTrue(r['facts']['platform_event_reads_cp_device_id'])
        self.assertTrue(r['facts']['platform_event_looks_up_aosu_device'])
        self.assertTrue(r['facts']['platform_event_enriches_aosu_device'])
        self.assertEqual(r['dex_count'],17)
        self.assertFalse(r['runtime_device_identity_confirmed'])
        self.assertFalse(r['external_c9c_cp_id_recovered'])
        self.assertEqual(r['network_calls'],0)
        self.assertEqual(r['video_calls'],0)
        self.assertFalse(r['secrets_exported'])
        for secret in ('SECRET_CP_ID','PRIVATE_TOKEN','AOSU_SN'):
            self.assertNotIn(secret,json.dumps(r))
    def test_missing_code_does_not_prove_a_link(self):
        r=TOOL['summarize']({'classes11.dex':Stub(False),'classes15.dex':Stub(False)},17)
        self.assertFalse(any(r['facts'].values()))
        self.assertFalse(r['runtime_device_identity_confirmed'])
    def test_new_sdk_facts_are_not_runtime_identity(self):
        r=TOOL['summarize']({'classes11.dex':Stub(),'classes15.dex':Stub()},17)
        self.assertTrue(r['facts']['platform_selector_reads_cp_uuid'])
        self.assertFalse(r['runtime_device_identity_confirmed'])
        self.assertFalse(r['external_c9c_cp_id_recovered'])
        self.assertFalse(r['secrets_exported'])

    def test_single_thing_device_still_heuristic(self):
        select=TOPOLOGY['select_tuya_standalone_target']
        result=select({'ty':{'productId':'PRODUCT','skills':{'p2pType':4}}},
                      camera_sn='AOSU_SN',camera_coop=None)
        self.assertEqual(result[1],'appareil_tuya_unique_sans_categorie_video')
        self.assertNotEqual(result[1],'identite_exacte')
    def test_only_exact_cp_match_can_be_strong(self):
        select=TOPOLOGY['select_tuya_standalone_target']
        dev={'ty':{'devId':'PRIVATE_CP_ID'}}
        self.assertEqual(select(dev,camera_sn='AOSU_SN',camera_coop='PRIVATE_CP_ID'),
                         ('ty','identite_exacte'))
        self.assertNotEqual(select(dev,camera_sn='AOSU_SN',camera_coop=None)[1],
                            'identite_exacte')
if __name__=='__main__':unittest.main()
