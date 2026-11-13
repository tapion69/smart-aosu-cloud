"""Offline SN-bound AOSU detail UUID fallback; no real API or secrets."""
import ast
import json
import runpy
import time
import types
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'custom_components'/'smart_aosu_cloud'
CP=runpy.run_path(str(BASE/'c9c_cp_reference_b32.py'))
CODE=(BASE/'c9c_ty_detail_hydration.py').read_text(encoding='utf8')
tree=ast.parse(CODE)
funcs=[node for node in tree.body if isinstance(node,ast.FunctionDef)]
namespace={'time':time,'Any':object,
           'extract_c9c_ty_cp_uuid':CP['extract_c9c_ty_cp_uuid']}
exec(compile(ast.Module(body=funcs,type_ignores=[]),'<offline>', 'exec'),
     namespace)
extract=namespace['extract_ty_cp_uuid_from_aosu_detail']
remember=namespace['remember_ty_cp_uuid_from_aosu_detail']
resolve=namespace['resolve_aosu_ty_cp_uuid']

SN='SYNTHETIC_CAMERA_SN'
UUID='SYNTHETIC_CP_UUID'
SID='SYNTHETIC_SESSION_SID'
UID='SYNTHETIC_ACCOUNT_UID'


def detail(sn=SN,uuid=UUID):
    return {'errno':0,
            'data':{'sn':sn, 'cpDeviceInfo':{'cpUuid':uuid}}}


def client():
    return types.SimpleNamespace(
        _sid=SID,_uid=UID,_standalone_c9c_sn=SN,
        _standalone_c9c_ty_cp_uuid=None,
        _standalone_c9c_ty_uuid_detail=None)


class TestC9CDetailHydration(unittest.TestCase):
    def test_exact_sn_and_exact_nested_cp_uuid(self):
        v,source=extract(detail(),SN)
        self.assertEqual(v,UUID)
        self.assertEqual(source,'cp_uuid_detail_sn_verifie')
        self.assertEqual(extract({'errno':0,'data':{
            'list':[detail()['data']]}},SN)[0],UUID)

    def test_missing_cp_uuid_not_approximated_from_other_identifiers(self):
        for row in (
            {'sn':SN,'cpDeviceId':UUID},
            {'sn':SN,'coopUUID':UUID},
            {'sn':SN,'uuid':UUID},
            {'sn':SN,'cpUuid':UUID},
            {'sn':SN,'cpDeviceInfo':{'cpDeviceId':UUID}},
        ):
            with self.subTest(row=row):
                self.assertEqual(
                    extract({'errno':0,'data':row},SN),
                    (None,'cp_uuid_absent_du_detail'))

    def test_reject_different_or_ambiguous_serials(self):
        self.assertEqual(
            extract(detail('DIFFERENT_SN'),SN),
            (None,'numero_serie_contradictoire'))
        self.assertEqual(extract({'errno':0,'data':{
            'list':[detail()['data'],detail('OTHER_SN')['data']]}},SN),
            (None,'numero_serie_contradictoire'))
        self.assertEqual(extract({'errno':0,'data':{
            'cpDeviceInfo':{'cpUuid':UUID}}},SN),
            (None,'numero_serie_absent'))

    def test_reject_duplicate_contradictory_uuids(self):
        p={'errno':0,'data':{'list':[
            {'sn':SN,'cpDeviceInfo':{'cpUuid':UUID}},
            {'sn':SN,'cpDeviceInfo':{'cpUuid':'DIFFERENT_UUID'}}]}}
        self.assertEqual(extract(p,SN),(None,'cp_uuid_contradictoire'))

    def test_session_and_serial_bound_ttl_no_persistence(self):
        c=client()
        source=remember(c,detail(),SN)
        self.assertEqual(source,'cp_uuid_detail_sn_verifie')
        self.assertEqual(resolve(c),(UUID,'detail_sn_session'))
        c._sid='OTHER_SESSION'
        self.assertEqual(resolve(c),(None,'aucune'))
        c._sid=SID
        c._standalone_c9c_sn='OTHER_SN'
        self.assertEqual(resolve(c),(None,'aucune'))
        c._standalone_c9c_sn=SN
        c._standalone_c9c_ty_uuid_detail['created']=time.monotonic()-3601
        self.assertEqual(resolve(c),(None,'aucune'))
        for secret in (UUID,SN,SID,UID):
            self.assertNotIn(secret,str({'source':source}))

    def test_getlist_only_precedence_but_not_a_fake_fallback(self):
        c=client()
        c._standalone_c9c_ty_cp_uuid='GETLIST_CP_UUID'
        self.assertEqual(resolve(c),('GETLIST_CP_UUID','getlist_sn'))
        c._standalone_c9c_ty_cp_uuid=None
        self.assertEqual(resolve(c),(None,'aucune'))

    def test_missing_aosu_session_blocks_even_getlist_identity(self):
        c=client()
        c._standalone_c9c_ty_cp_uuid='OLD_LOGIN_CP_UUID'
        c._sid=None
        self.assertEqual(resolve(c),(None,'aucune'))
        c._sid=SID
        c._uid=None
        self.assertEqual(resolve(c),(None,'aucune'))
        api=(BASE/'api.py').read_text(encoding='utf8')
        self.assertIn('self._standalone_c9c_ty_cp_uuid=None',api)

    def test_failed_detail_invalidates_previous_cached_mapping(self):
        c=client()
        remember(c,detail(),SN)
        self.assertEqual(resolve(c)[1],'detail_sn_session')
        source=remember(c,{'errno':1,'data':detail()['data']},SN)
        self.assertEqual(source,'detail_refuse')
        self.assertEqual(resolve(c),(None,'aucune'))

    def test_updated_routes_are_readonly_and_not_h1l(self):
        api=(BASE/'api.py').read_text(encoding='utf8')
        probe=(BASE/'c9c_detail_probe.py').read_text(encoding='utf8')
        route=(BASE/'tuya_rtc_inventory.py').read_text(encoding='utf8')
        init=(BASE/'__init__.py').read_text(encoding='utf8')
        js=(BASE/'frontend/c9c-autonome-b1.js').read_text(encoding='utf8')
        self.assertIn('remember_ty_cp_uuid_from_aosu_detail(client, parsed, sn)',probe)
        self.assertIn('"non_relancee_beta43"',probe)
        self.assertNotIn('probe_c9c_reverse_cp(',probe)
        self.assertIn('resolve_aosu_ty_cp_uuid(client)[0]',route)
        self.assertIn("'version_diagnostic']='b43'",init)
        self.assertIn("'/smart-aosu/c9c-autonome-b43.js'",init)
        self.assertIn('Carte b43 ; diagnostic serveur',js)
        self.assertIn('cpUuid Ty source détail',js)
        self.assertIn('self._standalone_c9c_ty_uuid_detail=None',api)
        self.assertNotIn('print(',CODE)
        self.assertNotIn('mqtt_publish(',CODE)
        for file in ('api.py','__init__.py','c9c_detail_probe.py',
                     'tuya_rtc_inventory.py'):
            ast.parse((BASE/file).read_text(encoding='utf8'))


if __name__ == '__main__':
    unittest.main()
