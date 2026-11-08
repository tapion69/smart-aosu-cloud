"""Offline fake-DEX and safety checks of AOSU SDK literal scanner."""
import ast
import io
import json
from pathlib import Path
import runpy
import struct
import unittest
from zipfile import ZipFile

COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
MOD=runpy.run_path(str(COMP/"c9c_sdk_mqtt_b25.py"))
SCANNER=MOD["_dex_flags"]
SCAN_APK=MOD["_scan_base_apk"]
INIT=(COMP/"__init__.py").read_text(encoding="utf-8")
UI=(COMP/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")


def _synthetic_dex(strings):
    raw=bytearray(112+4*len(strings))
    raw[:8]=b'dex\n035\x00'
    struct.pack_into('<I',raw,36,112)
    struct.pack_into('<II',raw,56,len(strings),112)
    for index,value in enumerate(strings):
        struct.pack_into('<I',raw,112+index*4,len(raw))
        raw+=bytes([len(value)])+value+b'\0'
    return bytes(raw)


class TestSdkMqttB25(unittest.TestCase):
    def test_dex_string_table_only(self):
        sample=_synthetic_dex([b'/api/jarvis/mqtt',b'msid',
                                b'/av/u/',b'com/thingclips/smart/camera/Sdk'])
        flags=SCANNER(sample)
        self.assertTrue(flags["jarvis_mqtt"])
        self.assertTrue(flags["mqtt_session_msid"])
        self.assertTrue(flags["sdk_camera_tuya"])
        self.assertFalse(flags["jarvis_config"])
        self.assertFalse(flags["route_webrtc_out"])
        self.assertIsNone(SCANNER(b'garbage /api/jarvis/mqtt'))

    def test_nested_base_zip(self):
        inner=io.BytesIO()
        with ZipFile(inner,'w') as z:
            z.writestr('classes.dex',_synthetic_dex([b'/api/jarvis/config']))
        count,flags=SCAN_APK(inner.getvalue())
        self.assertEqual(count,1)
        self.assertTrue(flags["jarvis_config"])
        self.assertFalse(flags["jarvis_mqtt"])
        self.assertNotIn("private-data",json.dumps(flags))

    def test_service_is_local_only(self):
        ast.parse(INIT)
        self.assertIn("audit_apk_sdk_c9c,runtime.client",INIT)
        self.assertIn("'analyser_sdk_mqtt_c9c_b25'",INIT)
        self.assertIn("select_standalone_c9c_key(runtime.data)",INIT)
        self.assertIn("this._sdkB25()",UI)
        self.assertNotIn("ptz_maintien",UI)

    def test_known_sha_and_lite_partial(self):
        self.assertEqual(MOD["LITE_SIZE"],1690990)
        self.assertEqual(MOD["ORIGINAL_SIZE"],200265946)
        self.assertEqual(len(MOD["ORIGINAL_SHA"]),64)
        self.assertEqual(len(MOD["LITE_SHA"]),64)
        class Missing: apk_path="/nonexistent/test.apk"
        report=MOD["audit_apk_sdk_c9c"](Missing())
        self.assertEqual(report["etat"],"apk_introuvable")
        self.assertTrue(report["analyse_partielle"])
        self.assertEqual(report["appels_reseau"],0)
        self.assertEqual(report["fichiers_crees"],0)

if __name__=="__main__":
    unittest.main()
