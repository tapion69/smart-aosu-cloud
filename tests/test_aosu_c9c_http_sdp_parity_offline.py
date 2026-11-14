"""Synthetic, offline-only checks of native AOSU SDP/RTC token parity facts.

Never add APK or proprietary .so to the repository or GitHub Actions.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"tools"/"aosu_c9c_http_sdp_parity_offline.py"
spec=importlib.util.spec_from_file_location("c9c_http_parity",SCRIPT)
parity=importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)
COMP=ROOT/"custom_components"/"smart_aosu_cloud"


def fixture_elf()->bytearray:
    data=bytearray(0x11ad00)
    for offset,target in ((0x69ad4,0x43690), *((x,0x413a0) for x in
            (0x69c40,0x69c50,0x69c60,0x69c70))):
        displacement=(target-offset)//4
        struct.pack_into("<I",data,offset,0x94000000|(displacement&0x3ffffff))
    for offset,label in (
        (0x11a8f2,b"audio"),(0x11a8fa,b"video"),(0x118955,b"imm"),
        (0x11a9f3,b"m=%s 9 %s%s\r\n"),
        (0x11a99a,b"v=0\r\no=- %lu 1 IN IP4 127.0.0.1\r\n"
                  b"s=-\r\nt=0 0\r\na=group:BUNDLE%s\r\n"
                  b"a=msid-semantic: WMS %s\r\n"),
        (0x1183c7,b"token"),(0x1183b9,b"udp_token"),
        (0x1183c3,b"tcp_token"),(0x11705a,b"log")):
        data[offset:offset+len(label)+1]=label+b"\0"
    for offset in (0x69c9c,0x69cb4,0x69ccc,0x69ce4):
        struct.pack_into("<I",data,offset,0xb4000000)
    return data


def analyze(elf:bytes|bytearray)->dict:
    return parity.inspect_contract(
        bytes(elf),
        (COMP/"tuya_media_bootstrap.py").read_text(),
        (COMP/"tuya_mqtt_offer.py").read_text(),
        (COMP/"c9c_thing4_http_once.py").read_text(),
        enforce_sha=False)


class TestNativeHttpParity(unittest.TestCase):
    def test_expected_contract_checks_on_synthetic_elf(self):
        result=analyze(fixture_elf())
        self.assertTrue(all(result["native_facts"].values()))
        self.assertTrue(all(result["python_facts"].values()))
        self.assertFalse(result["native_python_sdp_identical_proven"])
        self.assertFalse(result["native_python_token_identical_proven"])
        self.assertFalse(result["native_http_refusal_cause_identified"])
        self.assertEqual(result["network_calls"],0)
        self.assertEqual(result["camera_commands"],0)

    def test_missing_native_token_parse_is_detected(self):
        raw=fixture_elf()
        struct.pack_into("<I",raw,0x69c50,0)
        result=analyze(raw)
        self.assertFalse(result["native_facts"]["sdk_native_token_json_parsing"])
        self.assertTrue(result["native_facts"]["sdk_sdp_media_line_is_dynamic"])

    def test_missing_native_dynamic_sdp_marker_is_detected(self):
        raw=fixture_elf()
        raw[0x11a9f3:0x11a9f8]=b"AAAAA"
        result=analyze(raw)
        self.assertFalse(result["native_facts"]["sdk_sdp_media_line_is_dynamic"])
        self.assertTrue(result["native_facts"]["sdk_native_token_json_parsing"])

    def test_non_matching_elf_is_rejected_before_analysis(self):
        with self.assertRaises(ValueError):
            parity.inspect_contract(
                bytes(fixture_elf()),"","", "",enforce_sha=True)

    def test_raw_native_values_are_not_echoed(self):
        raw=fixture_elf()
        result=analyze(raw)
        self.assertNotIn("AES-SECRET",str(result))
        self.assertNotIn("localhost",str(result))
        self.assertTrue(result["native_facts"]["sdk_native_optional_token_items"])


if __name__=="__main__":
    unittest.main()
