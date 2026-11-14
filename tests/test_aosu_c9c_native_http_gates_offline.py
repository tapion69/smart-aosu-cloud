"""No-network synthetic AOSU HTTP state-machine checks; no OEM ELF in repo."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import struct
import unittest

SOURCE=(Path(__file__).resolve().parents[1]/"tools"/
        "aosu_c9c_native_http_gates_offline.py")
SPEC=importlib.util.spec_from_file_location("aosu_native_http_gates",SOURCE)
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
WORDS={
  0x69998:0xb94e5808,0x6999c:0x7100051f,
  0x699a0:0x54000061,0x699a4:0x2a1f03e0,
  0x699ac:0xf9593408,0x699b4:0xb4000128,
  0x699d8:0xb94e1e68,0x699dc:0x34000548,
  0x69a84:0xf9401a74,0x69a94:0xb90e1e68,
  0x69a9c:0x52875308,0x69aa0:0xf9071260,
  0x69aa4:0xb90e2a68,0x69aa8:0xf941e688,
  0x69aac:0xb4fff9a8,0x69ad4:0x97ff66ef,
  0x69ad8:0x37fff840,0x69f50:0x528000a1,
  0x69f5c:0x97ff59c9,0x66668:0xb90e5328,
  0x66900:0xb90e5329,0x66c2c:0xb90e533f,
  0x66d4c:0xb90e533f,
}


def fixture()->bytearray:
    data=bytearray(0x6a000)
    for offset,word in WORDS.items():
        struct.pack_into("<I",data,offset,word)
    return data


class GateTests(unittest.TestCase):
    def test_proofs_are_all_present_on_synthetic_code(self):
        d=mod.inspect(fixture(),pinned=False)
        self.assertTrue(all(d["evidence"].values()))
        self.assertTrue(d["http_offer_requires_initialized_native_state"])
        self.assertFalse(d["ha_manual_http_offer_reproduces_native_state"])
        self.assertEqual(d["network_calls"],0)
        self.assertFalse(d["identifiers_returned"])

    def test_missing_state_condition_fails_closed(self):
        b=fixture();struct.pack_into("<I",b,0x69998,0)
        d=mod.inspect(b,pinned=False)
        self.assertFalse(d["evidence"]["rtc_state_must_not_be_one"])
        self.assertFalse(d["http_offer_requires_initialized_native_state"])

    def test_missing_context_jump_fails_closed(self):
        b=fixture();struct.pack_into("<I",b,0x69aac,0)
        self.assertFalse(mod.inspect(b,pinned=False)["evidence"][
            "native_session_context_is_required"])

    def test_timeout_mutation_fails_closed(self):
        b=fixture();struct.pack_into("<I",b,0x69a9c,0x52800008)
        self.assertFalse(mod.inspect(b,pinned=False)["evidence"][
            "native_timeout_is_15000ms"])

    def test_single_flight_mutation_fails_closed(self):
        b=fixture();struct.pack_into("<I",b,0x699dc,0)
        self.assertFalse(mod.inspect(b,pinned=False)["evidence"][
            "single_flight_guard"])

    def test_pinned_build_required_for_real_claims(self):
        with self.assertRaises(ValueError):
            mod.inspect(fixture(),pinned=True)

    def test_offer_queue_missing_fails_closed(self):
        b=fixture();struct.pack_into("<I",b,0x69f5c,0)
        self.assertFalse(mod.inspect(b,pinned=False)["evidence"][
            "native_offer_queued_as_type_five"])

    def test_preconnect_state_is_mutable_not_assumed(self):
        b=fixture();struct.pack_into("<I",b,0x66c2c,0)
        self.assertFalse(mod.inspect(b,pinned=False)["evidence"][
            "preconnect_flag_changes_during_native_state_transitions"])


if __name__=="__main__":
    unittest.main()
