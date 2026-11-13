#!/usr/bin/env python3
"""Static, owner-APK-only Thing-4 connect_session and native offer-route audit.

No native execution, camera/network activity, secrets, OEM strings, or binary
contents in the result. This check is pinned to the exact AOSU 5.10.12 APK
SHA-256 and cannot establish the runtime path of a specific C9C.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

from aosu_sdk_route_offline import DexIndex

EXPECTED_APK_SHA256 = (
    "ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7"
)
_MAX_APK_BYTES = 350_000_000
_MAX_ARM64_SPLIT_BYTES = 160_000_000
_MAX_ELF_BYTES = 8_000_000

# AArch64 ELF .text virtual/file mapping for the exact pinned APK build.
# First argument is the call location; second is the preceding size setting.
_NATIVE_RANDOM_CALLS = {
    "connect": (0x60A88, 0x60A78),
    "connect_v2": (0x60D84, 0x60D74),
    "connect_v3": (0x6105C, 0x6104C),
}
_NATIVE_RANDOM_PLT = 0x40E20
_MOV_W1_33 = 0x52800421
_HTTP_OFFER_LITERAL = b"thing.m.rtc.session.offer_1.0"
_CONNECT_SESSION_FIELD = b'"connect_session":"%s"'
_CONNECT_PREFIXES = {
    "connect": b'{"cmd":"connect","args":',
    "connect_v2": b'{"cmd":"connect_v2","args":',
    "connect_v3": b'{"cmd":"connect_v3","args":',
}


def _u32(code: bytes, address: int) -> int:
    if address < 0 or address + 4 > len(code):
        raise ValueError("native_code_out_of_bounds")
    return struct.unpack_from("<I", code, address)[0]


def _bl_target(code: bytes, address: int) -> int | None:
    """Decode AArch64 BL with signed 26-bit immediate, without executing."""
    instruction = _u32(code, address)
    if instruction & 0xFC000000 != 0x94000000:
        return None
    displacement = instruction & 0x03FFFFFF
    if displacement & 0x02000000:
        displacement -= 0x04000000
    return address + displacement * 4


def summarize_native(elf: bytes) -> dict:
    if len(elf) < 0x120000 or elf[:6] != b"\x7fELF\x02\x01":
        raise ValueError("invalid_native_elf")
    if struct.unpack_from("<H", elf, 18)[0] != 183:
        raise ValueError("not_aarch64")
    # Confirm this build maps .text and .rodata virtual addresses to file offsets;
    # the full original APK hash is checked by analyze before using addresses.
    section_table = struct.unpack_from("<Q", elf, 40)[0]
    entry_size, count = struct.unpack_from("<HH", elf, 58)
    if (entry_size != 64 or not 2 <= count <= 400
            or section_table + count * 64 > len(elf)):
        raise ValueError("invalid_elf_sections")
    mapped_text = mapped_rodata = False
    for i in range(count):
        off = section_table + i * 64
        vaddr, fileoff, size = struct.unpack_from("<QQQ", elf, off + 16)
        kind = struct.unpack_from("<I", elf, off + 4)[0]
        if kind != 8 and (fileoff > len(elf) or size > len(elf) - fileoff):
            raise ValueError("invalid_elf_section_bounds")
        if vaddr == fileoff and fileoff <= 0x60A88 < fileoff + size:
            mapped_text = True
        if vaddr == fileoff and fileoff <= 0x118A1A < fileoff + size:
            mapped_rodata = True
    if not mapped_text or not mapped_rodata:
        raise ValueError("expected_original_elf_mapping_missing")

    checked = {}
    for mode, (call_at, size_at) in _NATIVE_RANDOM_CALLS.items():
        checked["local_connect_session_generated_" + mode] = bool(
            _u32(elf, size_at) == _MOV_W1_33
            and _bl_target(elf, call_at) == _NATIVE_RANDOM_PLT
        )
    checked["all_native_connect_templates_have_connect_session"] = all(
        _CONNECT_PREFIXES[mode] in elf
        and _CONNECT_SESSION_FIELD in elf[elf.index(_CONNECT_PREFIXES[mode]):
                                         elf.index(_CONNECT_PREFIXES[mode]) + 350]
        for mode in _CONNECT_PREFIXES
    )
    checked["native_thing_offer_http_action_present"] = (
        elf[0x118A1A:0x118A1A + len(_HTTP_OFFER_LITERAL)] == _HTTP_OFFER_LITERAL
    )
    # At 0x69D48/4C, ADRP x0, page 0x118000; ADD x0,x0,#0xa1a.
    # At 0x69D50 the created action string is handed to cJSON_CreateString.
    checked["native_http_offer_action_referenced_in_json_builder"] = (
        _u32(elf, 0x69D48) == 0xF0000560
        and _u32(elf, 0x69D4C) == 0x91286800
        and _bl_target(elf, 0x69D50) == 0x43C30
    )
    # A cJSON result is then published to a native internal message queue.
    checked["native_http_offer_json_enqueued"] = (
        _bl_target(elf, 0x69DB0) == 0x428F0
        and _bl_target(elf, 0x69F5C) == 0x40680
    )
    return {
        "audit": "aosu_c9c_native_connect_session_offline_v1",
        "owner_apk_build": "AOSU_5.10.12",
        "static_sdk_binary_evidence_only": True,
        "c9c_runtime_path_confirmed": False,
        "native_connect_session_equals_mqtt_header_sessionid_proven": False,
        "native_offer_http_required_for_c9c_proven": False,
        "working_ha_video_proven": False,
        "camera_commands": 0,
        "network_calls": 0,
        "secrets_or_binary_data_returned": False,
        "facts": {k: v is True for k, v in checked.items()},
    }


def summarize_java_bridge(dex: DexIndex) -> dict[str, bool]:
    """Recognize Java HTTP callback/response paths without extracting payloads."""
    callback = dex.method("/p2p/p2psdk/ThingP2PSDK;", "onHttpRequest")
    success = dex.method("/p2p/p2psdk/ThingP2PSDK$pdqppqb;", "onSuccess")
    failure = dex.method("/p2p/p2psdk/ThingP2PSDK$pdqppqb;", "onFailure")
    proxy_success = dex.method("/p2p/p2psdk/ThingP2PSDK$bdpdqbp;", "onSuccess")
    facts = {
        "java_native_http_callback_present": bool(callback),
        "java_http_proxy_route": bool(callback and dex.calls(
            callback, "/p2p/api/IHttpProxy;", "onHttpRequest")),
        "java_http_business_route": bool(callback and dex.calls(
            callback, "/android/network/Business;", "asyncRequest")),
        "java_http_post_body_prepared": bool(callback and dex.calls(
            callback, "/android/network/ThingApiParams;", "setPostData")),
        "java_business_success_returns_to_native": bool(
            success and dex.calls(
                success, "/p2p/p2psdk/ThingP2PSDK;", "setHttpResponse")),
        "java_business_failure_returns_to_native": bool(
            failure and dex.calls(
                failure, "/p2p/p2psdk/ThingP2PSDK;", "setHttpResponse")),
        "java_proxy_success_returns_to_native": bool(
            proxy_success and dex.calls(
                proxy_success, "/p2p/p2psdk/ThingP2PSDK;", "setHttpResponse")),
    }
    return facts


def analyze(apk: Path) -> dict:
    if not apk.is_file() or apk.stat().st_size > _MAX_APK_BYTES:
        raise ValueError("apk_not_available")
    with apk.open("rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != EXPECTED_APK_SHA256:
            raise ValueError("unknown_apk_build")
    with zipfile.ZipFile(apk) as outer:
        info = outer.getinfo("split_config.arm64_v8a.apk")
        if info.file_size > _MAX_ARM64_SPLIT_BYTES:
            raise ValueError("split_oversized")
        with zipfile.ZipFile(io.BytesIO(outer.read(info))) as native:
            lib = native.getinfo("lib/arm64-v8a/libThingP2PSDK.so")
            if lib.file_size > _MAX_ELF_BYTES:
                raise ValueError("elf_oversized")
            result = summarize_native(native.read(lib))
        base_info = outer.getinfo("base.apk")
        if base_info.file_size > 260_000_000:
            raise ValueError("base_apk_oversized")
        with zipfile.ZipFile(io.BytesIO(outer.read(base_info))) as base:
            dex_info = base.getinfo("classes6.dex")
            if dex_info.file_size > 12_000_000:
                raise ValueError("dex_oversized")
            dex = DexIndex(base.read(dex_info))
        result["java_http_bridge_facts"] = summarize_java_bridge(dex)
        return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline inspection of native connect_session contract")
    parser.add_argument("apk", type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.apk)
    except (OSError, ValueError, KeyError, IndexError, struct.error,
            zipfile.BadZipFile):
        result = {"audit": "aosu_c9c_native_connect_session_offline_v1",
                  "state": "unsupported_or_missing_private_apk",
                  "camera_commands": 0, "network_calls": 0,
                  "secrets_or_binary_data_returned": False}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
