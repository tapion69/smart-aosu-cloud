"""Synthetic regression: native Thing P2P route references never prove video."""
import ast
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / 'tools' / 'aosu_c9c_native_p2p_route_offline.py').read_text()
TREE = ast.parse(SRC)
SUM = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
           and node.name == 'summarize')
NS = {}
exec(compile(ast.Module(body=[SUM], type_ignores=[]), '<audit>', 'exec'), NS)


class StubDex:
    """Only declared expected method refs. No APK, credentials or network."""
    def __init__(self, missing=()):
        self.missing = set(missing)

    def method(self, cls, name):
        return (cls, name)

    def calls(self, method, cls, name):
        return (method[1], cls, name) not in self.missing


class TestNativeRoute(unittest.TestCase):
    def test_complete_synthetic_method_matrix_does_not_claim_working_video(self):
        report = NS['summarize'](
            {'classes6.dex': StubDex(), 'classes16.dex': StubDex()},
            dex_count=17)
        self.assertEqual(report['checks_present_count'], 17)
        self.assertEqual(report['checks_total_count'], 17)
        self.assertTrue(report['sdk_route_static_confirmed'])
        for name in ('binary_protocol_parity_proven', 'device_identity_proven',
                     'ready_for_camera_send', 'python_native_equivalence_proven',
                     'secrets_exported'):
            self.assertFalse(report[name])
        self.assertEqual(report['camera_commands'], 0)

    def test_missing_native_prerequisite_degrades_evidence(self):
        missing={('innerConnect',
                  '/camera/sdk/api/IThingIPCDevice;', 'getDeviceBean')}
        report=NS['summarize']({
            'classes6.dex': StubDex(missing),
            'classes16.dex': StubDex()
        }, dex_count=17)
        self.assertFalse(report['checks']['native_device_bean'])
        self.assertEqual(report['checks_present_count'], 16)
        self.assertFalse(report['sdk_route_static_confirmed'])
        self.assertFalse(report['ready_for_camera_send'])

    def test_public_report_is_fixed_schema_and_never_embeds_raw_apk_or_ids(self):
        report=NS['summarize']({
            'classes6.dex': StubDex(),
            'classes16.dex': StubDex()
        }, dex_count=17)
        data=json.dumps(report)
        for banned in ('PRIVATE_SN', 'LOCAL_KEY_PRIVATE', 'SESSION_TOKEN_PRIVATE',
                       'PRIVATE_COOP_UUID'):
            self.assertNotIn(banned,data)
        for verb in ('requests.post', 'mqtt_publish', 'startPreview',
                     'client.session', 'openCamera', 'adb shell'):
            self.assertNotIn(verb, SRC)


if __name__ == '__main__':
    unittest.main()
