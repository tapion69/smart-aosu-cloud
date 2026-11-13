"""Synthetic verification of private TyDeviceInfoSource call-graph audit.

No real APKs, identities, account data, camera traffic or local credentials.
"""
import ast
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'tools'/'aosu_ty_device_enrichment_offline.py').read_text(encoding='utf8')
FUNCS=[x for x in ast.parse(SOURCE).body
       if isinstance(x,ast.FunctionDef) and x.name=='summarize']
NS={'DexIndex':object}
exec(compile(ast.Module(body=FUNCS,type_ignores=[]),'<offline>', 'exec'),NS)
audit=NS['summarize']


class StubDex:
    def __init__(self, missing=()):
        self.missing=set(missing)
        self.seen_calls=[]
        self.seen_fields=[]

    def method(self, cls, method):
        return (cls,method)

    def calls(self, code,cls,method):
        self.seen_calls.append((code,cls,method))
        return (code,cls,method) not in self.missing

    def field_access(self, code,cls,field,opcodes):
        self.seen_fields.append((code,cls,field,opcodes))
        return (code,cls,field) not in self.missing


class TestTySDKBridgeOffline(unittest.TestCase):
    def test_all_eleven_static_markers_and_no_live_claims(self):
        stub=StubDex()
        report=audit(stub,stub,17)
        self.assertEqual(report['dex_count'],17)
        self.assertEqual(len(report['faits']),14)
        self.assertTrue(all(report['faits'].values()))
        self.assertTrue(report['analyse_statique_seulement'])
        for k in ('liaison_c9c_aosu_tuya_prouvee',
                  'execution_sdk_camera_prouvee',
                  'source_cp_uuid_http_prouvee',
                  'video','secrets_retournes','identifiants_retournes'):
            self.assertFalse(report[k])
        self.assertEqual(report['appel_reseau'],0)
        self.assertEqual(report['commandes_camera'],0)
        self.assertEqual(report['commandes_ptz'],0)
        self.assertIn(('/device/mid/TyDeviceInfoSource;', 'OooO0o'),
                      [args[0] for args in stub.seen_calls])
        self.assertNotIn('SYNTHETIC_SERIAL',json.dumps(report))

    def test_no_event_enrichment_means_no_proven_path(self):
        ev='/device/mid/TyDeviceInfoSource$init$1;'
        gz='/model/GzDeviceInfo;'
        missing={((ev,'OooO00o'),gz,'setCpDataInfo')}
        st=StubDex(missing)
        report=audit(st,st,17)
        self.assertFalse(
            report['faits']['tuya_sdk_event_enriches_aosu_device'])
        self.assertTrue(
            report['faits']['android_ty_path_reads_cp_uuid'])
        self.assertFalse(report['liaison_c9c_aosu_tuya_prouvee'])

    def test_field_and_method_namespace_are_not_conflated(self):
        sdk=StubDex({(('/device/mid/TyDeviceInfoSource;','OooOOOO'),
                    '/model/GzDeviceInfo;','cpDeviceId')})
        report=audit(sdk,sdk,17)
        self.assertFalse(report['faits']['tuya_sdk_cp_id_cache_index'])
        self.assertFalse(report['liaison_c9c_aosu_tuya_prouvee'])
        self.assertEqual(set(report.keys()),
                         {'diagnostic','dex_count',
                          'analyse_statique_seulement',
                          'liaison_c9c_aosu_tuya_prouvee',
                          'execution_sdk_camera_prouvee',
                          'source_cp_uuid_http_prouvee',
                          'appel_reseau','video','commandes_camera',
                          'commandes_ptz','secrets_retournes',
                          'identifiants_retournes','faits'})

    def test_tool_does_not_upload_or_debug_dump_apk_bytes(self):
        self.assertIn("ZipFile", SOURCE)
        self.assertIn("classes15.dex", SOURCE)
        self.assertIn("classes16.dex", SOURCE)
        self.assertNotIn('requests.',SOURCE)
        self.assertNotIn('mqtt_publish(',SOURCE)
        self.assertNotIn('subprocess.',SOURCE)
        self.assertNotIn("print(raw",SOURCE)


if __name__ == '__main__':
    unittest.main()
