#!/usr/bin/env python3
"""Offline state-gate audit of original AOSU 5.10.12 Thing-4 HTTP offer.

Locally inspect owner-provided APK. No network, native execution, disk ELF
extraction, raw identifiers, tokens, or proprietary binary distribution.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

PINNED_APK_SHA256 = "ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7"
PINNED_ELF_SHA256 = "c9032dcf37f72fc7ad28835a02c4e66a814597380f10c132d042df78969f1745"


def _u32(blob: bytes, at: int) -> int:
    return struct.unpack_from("<I", blob, at)[0]


def _sign(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _bcond(blob: bytes, at: int) -> int | None:
    w = _u32(blob, at)
    return (at + (_sign((w >> 5) & 0x7ffff, 19) << 2)
            if w & 0xff000010 == 0x54000000 else None)


def _cbz(blob: bytes, at: int) -> int | None:
    w = _u32(blob, at)
    return (at + (_sign((w >> 5) & 0x7ffff, 19) << 2)
            if w & 0x7e000000 == 0x34000000 else None)


def _bl(blob: bytes, at: int) -> int | None:
    w = _u32(blob, at)
    return (at + (_sign(w & 0x3ffffff, 26) << 2)
            if w >> 26 == 0b100101 else None)


def inspect(blob: bytes, *, pinned: bool = True) -> dict:
    if len(blob) < 0x69f60 or len(blob) > 5_000_000:
        raise ValueError("elf_incorrect_size")
    if pinned and hashlib.sha256(blob).hexdigest() != PINNED_ELF_SHA256:
        raise ValueError("elf_unknown_build")
    eq = lambda at, word: _u32(blob, at) == word
    gates = {
        "rtc_state_must_not_be_one": (
            eq(0x69998, 0xb94e5808) and eq(0x6999c, 0x7100051f)
            and _bcond(blob, 0x699a0) == 0x699ac
            and eq(0x699a4, 0x2a1f03e0)),
        "existing_transport_state_is_checked": (
            eq(0x699ac, 0xf9593408)
            and _cbz(blob, 0x699b4) == 0x699d8),
        "single_flight_guard": (
            eq(0x699d8, 0xb94e1e68)
            and _cbz(blob, 0x699dc) == 0x69a84
            and eq(0x69a94, 0xb90e1e68)),
        "native_timeout_is_15000ms": (
            eq(0x69a9c, 0x52875308)
            and eq(0x69aa0, 0xf9071260)
            and eq(0x69aa4, 0xb90e2a68)),
        "native_session_context_is_required": (
            eq(0x69a84, 0xf9401a74)
            and eq(0x69aa8, 0xf941e688)
            and _cbz(blob, 0x69aac) == 0x699e0),
        "native_sdp_is_generated_after_gates": (
            _bl(blob, 0x69ad4) == 0x43690
            and eq(0x69ad8, 0x37fff840)),
        "native_offer_queued_as_type_five": (
            eq(0x69f50, 0x528000a1)
            and _bl(blob, 0x69f5c) == 0x40680),
        "preconnect_flag_changes_during_native_state_transitions": (
            eq(0x66668, 0xb90e5328)
            and eq(0x66900, 0xb90e5329)
            and eq(0x66c2c, 0xb90e533f)
            and eq(0x66d4c, 0xb90e533f)),
    }
    return {
        "diagnostic": "aosu_c9c_http_native_state_gates_offline_v1",
        "original_elf_verified": pinned,
        "evidence": gates,
        "http_offer_requires_initialized_native_state": all(gates.values()),
        "ha_manual_http_offer_reproduces_native_state": False,
        "http_is_runtime_selected_for_brother_c9c": "non_demontre",
        "cause_of_cloud_rejection": "non_demontree",
        "network_calls": 0,
        "camera_commands": 0,
        "identifiers_returned": False,
    }


def load_original(apk: Path) -> bytes:
    if apk.stat().st_size > 350_000_000:
        raise ValueError("archive_too_large")
    if hashlib.sha256(apk.read_bytes()).hexdigest() != PINNED_APK_SHA256:
        raise ValueError("original_apk_hash_mismatch")
    with zipfile.ZipFile(apk) as outer:
        member = outer.getinfo("split_config.arm64_v8a.apk")
        if member.file_size > 150_000_000:
            raise ValueError("arm64_split_too_large")
        with zipfile.ZipFile(io.BytesIO(outer.read(member))) as split:
            library = split.getinfo("lib/arm64-v8a/libThingP2PSDK.so")
            if library.file_size > 5_000_000:
                raise ValueError("elf_too_large")
            return split.read(library)


def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("apk", type=Path)
    args = cli.parse_args()
    try:
        print(json.dumps(inspect(load_original(args.apk)), indent=2))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, struct.error):
        print('{"diagnostic":"aosu_c9c_http_native_state_gates_offline_v1","etat":"archive_incompatible"}')
        raise SystemExit(2)


if __name__ == "__main__":
    main()
