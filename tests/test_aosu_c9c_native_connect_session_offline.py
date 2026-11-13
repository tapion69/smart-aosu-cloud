"""Synthetic ELF-only regressions for AOSU connect_session evidence.

Never reads an APK in GitHub Actions or sends packets to a camera.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from aosu_c9c_native_connect_session_offline import (
    _bl_target, _u32, summarize_native, summarize_java_bridge,
)


def _encode_bl(source: int, destination: int) -> int:
    assert (destination - source) % 4 == 0
    return 0x94000000 | (((destination - source) // 4) & 0x03FFFFFF)


def fake_native() -> bytearray:
    fake = bytearray(0x120040)
    fake[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", fake, 18, 183)  # AArch64
    struct.pack_into("<Q", fake, 40, 0x100)
    struct.pack_into("<HH", fake, 58, 64, 3)
    # .text 0x45000... 0x85000
    struct.pack_into("<I", fake, 0x100 + 64 + 4, 1)
    struct.pack_into("<QQQ", fake, 0x100 + 64 + 16,
                     0x45000, 0x45000, 0x40000)
    # .rodata 0x110000 ... 0x120000
    struct.pack_into("<I", fake, 0x100 + 128 + 4, 1)
    struct.pack_into("<QQQ", fake, 0x100 + 128 + 16,
                     0x110000, 0x110000, 0x10000)
    for call, size in ((0x60A88, 0x60A78),
                       (0x60D84, 0x60D74),
                       (0x6105C, 0x6104C)):
        struct.pack_into("<I", fake, size, 0x52800421)
        struct.pack_into("<I", fake, call, _encode_bl(call, 0x40E20))
    templates = [
        (0x117500, b'{"cmd":"connect","args":{"connect_session":"%s"}}'),
        (0x11759A, b'{"cmd":"connect_v2","args":{"connect_session":"%s"}}'),
        (0x117668, b'{"cmd":"connect_v3","args":{"connect_session":"%s"}}'),
    ]
    for offset, raw in templates:
        fake[offset:offset + len(raw)] = raw
    action = b"thing.m.rtc.session.offer_1.0"
    fake[0x118A1A:0x118A1A + len(action)] = action
    for loc, instruction in ((0x69D48, 0xF0000560),
                             (0x69D4C, 0x91286800)):
        struct.pack_into("<I", fake, loc, instruction)
    for call, dest in ((0x69D50, 0x43C30), (0x69DB0, 0x428F0),
                       (0x69F5C, 0x40680)):
        struct.pack_into("<I", fake, call, _encode_bl(call, dest))
    return fake


class FakeJavaDex:
    """Method-index proxy, not a real or redistributed vendor DEX."""
    def __init__(self, absent=None):
        self.absent = absent
    def method(self, cls, name):
        if (cls, name) == self.absent:
            return b""
        return b"\\x11"
    def calls(self, code, cls, name):
        return name in ("onHttpRequest", "asyncRequest", "setPostData",
                        "setHttpResponse")


class TestAosuNativeConnectSession(unittest.TestCase):
    def test_java_callback_covers_proxy_business_and_native_result(self):
        facts = summarize_java_bridge(FakeJavaDex())
        self.assertEqual(len(facts), 7)
        self.assertTrue(all(facts.values()))

    def test_java_bridge_missing_result_path_not_declared_complete(self):
        absent = ("/p2p/p2psdk/ThingP2PSDK$pdqppqb;", "onSuccess")
        facts = summarize_java_bridge(FakeJavaDex(absent))
        self.assertFalse(facts["java_business_success_returns_to_native"])
        self.assertTrue(facts["java_business_failure_returns_to_native"])

    def test_all_evidence_with_purely_synthetic_elf(self):
        result = summarize_native(bytes(fake_native()))
        self.assertEqual(len(result["facts"]), 7)
        self.assertTrue(all(result["facts"].values()))
        self.assertFalse(result["native_connect_session_equals_mqtt_header_sessionid_proven"])
        self.assertFalse(result["native_offer_http_required_for_c9c_proven"])
        self.assertFalse(result["c9c_runtime_path_confirmed"])
        self.assertEqual(result["network_calls"], 0)
        self.assertEqual(result["camera_commands"], 0)
        self.assertFalse(result["secrets_or_binary_data_returned"])

    def test_must_have_native_random_generator_in_each_connect_mode(self):
        data = fake_native()
        struct.pack_into("<I", data, 0x60D84, 0)
        result = summarize_native(bytes(data))
        self.assertFalse(result["facts"]["local_connect_session_generated_connect_v2"])
        self.assertTrue(result["facts"]["local_connect_session_generated_connect_v3"])

    def test_native_http_action_is_distinct_from_mqtt_header(self):
        data = fake_native()
        data[0x118A1A] = 0
        result = summarize_native(bytes(data))
        self.assertFalse(result["facts"]["native_thing_offer_http_action_present"])
        self.assertFalse(result["native_offer_http_required_for_c9c_proven"])

    def test_native_offer_builder_not_inferred_from_just_string(self):
        data = fake_native()
        struct.pack_into("<I", data, 0x69D4C, 0)
        result = summarize_native(bytes(data))
        self.assertTrue(result["facts"]["native_thing_offer_http_action_present"])
        self.assertFalse(result["facts"]["native_http_offer_action_referenced_in_json_builder"])

    def test_elf_wrong_arch_or_mapping_rejected(self):
        data = fake_native()
        struct.pack_into("<H", data, 18, 62)
        with self.assertRaises(ValueError):
            summarize_native(bytes(data))
        data = fake_native()
        struct.pack_into("<Q", data, 0x100 + 128 + 16, 0x115000)
        with self.assertRaises(ValueError):
            summarize_native(bytes(data))

    def test_signed_bl_decode_works_and_bounds_are_checked(self):
        code = bytearray(0x60A8C)
        code[0x60A88:0x60A8C] = bytes.fromhex("e680ff97")
        self.assertEqual(_bl_target(bytes(code), 0x60A88), 0x40E20)
        self.assertIsNone(_bl_target(b"\0" * 4, 0))
        with self.assertRaises(ValueError):
            _u32(b"", 0)


if __name__ == "__main__":
    unittest.main()
