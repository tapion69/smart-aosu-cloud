"""Offline-only SDK/Python matrix: synthetic references, no APK or credentials."""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
spec=importlib.util.spec_from_file_location("sdk_coverage", ROOT/"tools"/"aosu_c9c_sdk_python_coverage.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class FakeDex:
    strings=[]
    def __init__(self,ok):self.ok=ok
    def method(self,*_):return b"method" if self.ok else b""
    def calls(self,*_):return self.ok

class TestCoverage(unittest.TestCase):
    def test_synthetic_sdk_only_never_claims_video(self):
        idx={name:FakeDex(True) for name in m._DEX}
        idx["classes4.dex"].strings=["sigQry"]
        result=m.summarize(idx,{"libThingP2PSDK.so","libThingCameraSDK.so"},
                           {"sends_offer_over_mqtt":True},17)
        self.assertTrue(all(result["sdk_references"].values()))
        self.assertTrue(result["sigqry_in_wifi_dex"])
        self.assertFalse(result["sigqry_literal_in_camera_dex"])
        for key in ("binary_protocol_parity_proven","camera_identity_proven",
                    "sdp_answer_proven","ready_for_camera_send","secret_values_returned"):
            self.assertIs(result[key],False)
        self.assertEqual(result["network_calls"],0)
        self.assertNotIn("PRIVATE_DEVICE_ID",json.dumps(result))
    def test_no_methods_means_no_sdk_claim(self):
        idx={name:FakeDex(False) for name in m._DEX}
        result=m.summarize(idx,set(),{},1)
        self.assertFalse(any(result["sdk_references"].values()))
        self.assertFalse(result["ready_for_camera_send"])
    def test_python_features_from_actual_repository(self):
        result=m._python_flags(ROOT)
        self.assertTrue(result["fabricates_json_aes_crc_frame"])
        self.assertTrue(result["fabricates_aes_kcp_sdp"])
        self.assertTrue(result["uses_static_mqtt_broker"])
        self.assertTrue(result["has_unverified_unique_device_fallback"])
        self.assertTrue(result["sends_offer_over_mqtt"])
        self.assertTrue(result["sends_sigqry_before_offer"])
    def test_invalid_archive_never_exports_content(self):
        with tempfile.TemporaryDirectory() as path:
            f=Path(path)/"faked.apk"
            f.write_text("PRIVATE_DEVICE_ID")
            with self.assertRaises((ValueError, __import__('zipfile').BadZipFile)):
                m.analyze(f,ROOT)

if __name__=="__main__":unittest.main()
