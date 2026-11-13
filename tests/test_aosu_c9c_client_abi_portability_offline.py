"""Synthetic ELF64 metadata tests only: no vendor APK, camera, account, or network."""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from aosu_c9c_client_abi_portability_offline import _needed, summarize


def fake_elf(needed: list[str], machine: int = 183) -> bytes:
    # Three section headers: null, .dynstr, .dynamic, with no binary code.
    data = bytearray(1800)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, machine)
    struct.pack_into("<Q", data, 40, 0x100)
    struct.pack_into("<H", data, 58, 64)
    struct.pack_into("<H", data, 60, 3)
    strings = bytearray(b"\x00")
    name_offsets = []
    for name in needed:
        name_offsets.append(len(strings))
        strings.extend(name.encode("ascii") + b"\x00")
    data[0x300:0x300 + len(strings)] = strings
    string_header = 0x100 + 64
    struct.pack_into("<I", data, string_header + 4, 3)
    struct.pack_into("<QQ", data, string_header + 24, 0x300, len(strings))
    dynamic_header = 0x100 + 128
    struct.pack_into("<I", data, dynamic_header + 4, 6)
    struct.pack_into("<QQ", data, dynamic_header + 24, 0x500, 16 * (len(needed) + 1))
    struct.pack_into("<I", data, dynamic_header + 40, 1)
    struct.pack_into("<Q", data, dynamic_header + 56, 16)
    for i, offset in enumerate(name_offsets):
        struct.pack_into("<qQ", data, 0x500 + i * 16, 1, offset)
    return bytes(data)


class TestAosuNativeClientAbi(unittest.TestCase):
    def test_android_aarch64_libraries_require_android_runtime(self):
        libs = {
            "libThingP2PSDK.so": fake_elf(["libandroid.so", "liblog.so", "libc.so"]),
            "libThingCameraSDK.so": fake_elf(["liblog.so", "libThingP2PSDK.so"]),
        }
        report = summarize(libs, False)
        self.assertTrue(all(report["facts"][key] for key in (
            "p2p_library_is_aarch64", "camera_library_is_aarch64",
            "p2p_requires_android_libandroid", "p2p_requires_android_liblog",
            "camera_requires_android_liblog", "camera_links_to_thing_p2p")))
        self.assertFalse(report["facts"]["bundle_has_x86_64_native_split"])
        self.assertFalse(report["can_directly_load_apk_libraries_on_ha_x86_64"])
        self.assertFalse(report["independent_thing4_viewer_client_implemented"])
        self.assertFalse(report["p2p_offer_sdp_answer_proven"])
        self.assertEqual(report["network_calls"], 0)
        self.assertFalse(report["secrets_or_binary_data_returned"])

    def test_parse_only_needed_names(self):
        actual, deps = _needed(fake_elf(["libandroid.so", "libThingP2PSDK.so"]))
        self.assertEqual(actual, 183)
        self.assertEqual(deps, {"libandroid.so", "libThingP2PSDK.so"})

    def test_x86_split_alone_does_not_mean_portable(self):
        libs = {
            "libThingP2PSDK.so": fake_elf(["libandroid.so", "liblog.so"]),
            "libThingCameraSDK.so": fake_elf(["liblog.so"]),
        }
        self.assertFalse(summarize(libs, True)["can_directly_load_apk_libraries_on_ha_x86_64"])

    def test_no_vendor_payload_or_names_in_report(self):
        libs = {
            "libThingP2PSDK.so": fake_elf(["libprivate_generated_name.so"]),
            "libThingCameraSDK.so": fake_elf([]),
        }
        text = str(summarize(libs, False))
        self.assertNotIn("libprivate_generated_name", text)
        self.assertNotIn("device_id", text)
        self.assertNotIn("password", text)

    def test_reject_truncated_and_wrong_section_offsets(self):
        with self.assertRaises(ValueError):
            _needed(b"\x7fELF")
        blob = bytearray(fake_elf(["liblog.so"]))
        struct.pack_into("<Q", blob, 40, 0xFFFFF)
        with self.assertRaises(ValueError):
            _needed(bytes(blob))

    def test_nobits_section_has_no_file_backing(self):
        blob = bytearray(fake_elf(["liblog.so"]))
        struct.pack_into("<I", blob, 0x100 + 4, 8)  # .bss / SHT_NOBITS
        struct.pack_into("<QQ", blob, 0x100 + 24, len(blob), 100_000)
        _, found = _needed(bytes(blob))
        self.assertEqual(found, {"liblog.so"})


if __name__ == "__main__":
    unittest.main()
