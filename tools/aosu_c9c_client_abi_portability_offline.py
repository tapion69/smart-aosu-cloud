#!/usr/bin/env python3
"""Offline AOSU 5.10.12 P2P client ABI portability audit.

Use only the owner's original complete APK locally. Read ELF metadata without
loading native code. Return fixed labels/booleans; no proprietary payload,
tokens, paths, identifiers, binary strings, or media content in the report.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

APK_SHA256 = "ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7"
TARGETS = ("libThingP2PSDK.so", "libThingCameraSDK.so")
MAX_APK = 350_000_000
MAX_SPLIT = 160_000_000
MAX_LIBRARY = 12_000_000


def _section_table(elf: bytes) -> tuple[int, list[dict[str, int]]]:
    """Only ELF64 little-endian section headers. Never execute the ELF."""
    if len(elf) < 64 or elf[:6] != b"\x7fELF\x02\x01":
        raise ValueError("bad_elf64")
    machine = struct.unpack_from("<H", elf, 18)[0]
    shoff = struct.unpack_from("<Q", elf, 40)[0]
    shentsize = struct.unpack_from("<H", elf, 58)[0]
    shnum = struct.unpack_from("<H", elf, 60)[0]
    if shentsize != 64 or not 1 <= shnum <= 192:
        raise ValueError("bad_elf_sections")
    if shoff < 64 or shoff + shnum * shentsize > len(elf):
        raise ValueError("elf_sections_outside_file")
    sections: list[dict[str, int]] = []
    for index in range(shnum):
        off = shoff + index * shentsize
        kind = struct.unpack_from("<I", elf, off + 4)[0]
        start, size = struct.unpack_from("<QQ", elf, off + 24)
        link = struct.unpack_from("<I", elf, off + 40)[0]
        entry_size = struct.unpack_from("<Q", elf, off + 56)[0]
        if start > len(elf) or size > len(elf) - start:
            raise ValueError("elf_section_outside_file")
        sections.append({"kind": kind, "start": start, "size": size,
                         "link": link, "entry_size": entry_size})
    return machine, sections


def _needed(elf: bytes) -> tuple[int, frozenset[str]]:
    """Return only ELF DT_NEEDED library names for internal classification."""
    machine, sections = _section_table(elf)
    names: set[str] = set()
    dynamics = [s for s in sections if s["kind"] == 6]
    if not dynamics:
        raise ValueError("elf_no_dynamic")
    for dynamic in dynamics:
        if dynamic["link"] >= len(sections):
            raise ValueError("elf_bad_dynamic_link")
        strings = sections[dynamic["link"]]
        if strings["kind"] != 3 or strings["size"] > 1_000_000:
            raise ValueError("elf_bad_dynstr")
        table = elf[strings["start"]:strings["start"] + strings["size"]]
        if dynamic["size"] > 400_000 or dynamic["size"] % 16:
            raise ValueError("elf_bad_dynamic_size")
        for index in range(dynamic["size"] // 16):
            tag, value = struct.unpack_from("<qQ", elf,
                                            dynamic["start"] + index * 16)
            if tag == 0:
                break
            if tag != 1:
                continue
            if value >= len(table):
                raise ValueError("elf_bad_needed_name")
            end = table.find(b"\0", value, min(value + 256, len(table)))
            if end < 0:
                raise ValueError("elf_unterminated_needed")
            try:
                names.add(table[value:end].decode("ascii"))
            except UnicodeError as exc:
                raise ValueError("elf_bad_needed_ascii") from exc
    return machine, frozenset(names)


def summarize(libraries: dict[str, bytes], has_x86_split: bool) -> dict:
    p2p_machine, p2p_needed = _needed(libraries["libThingP2PSDK.so"])
    cam_machine, cam_needed = _needed(libraries["libThingCameraSDK.so"])
    facts = {
        "p2p_library_is_aarch64": p2p_machine == 183,
        "camera_library_is_aarch64": cam_machine == 183,
        "p2p_requires_android_libandroid": "libandroid.so" in p2p_needed,
        "p2p_requires_android_liblog": "liblog.so" in p2p_needed,
        "camera_requires_android_liblog": "liblog.so" in cam_needed,
        "camera_links_to_thing_p2p": "libThingP2PSDK.so" in cam_needed,
        "bundle_has_x86_64_native_split": bool(has_x86_split),
    }
    # ABI + Android userspace dependencies prevent direct dlopen on HA x86_64.
    directly_loadable = bool(
        has_x86_split and p2p_machine == 62 and cam_machine == 62
        and "libandroid.so" not in p2p_needed
        and "liblog.so" not in p2p_needed
        and "liblog.so" not in cam_needed
    )
    return {
        "audit": "smart_aosu_client_abi_portability_v1",
        "source": "user_owned_aosu_5_10_12_complete_apk",
        "metadata_only": True,
        "native_library_execution": False,
        "sdk_camera_side_equivalent_to_viewer_client": False,
        "can_directly_load_apk_libraries_on_ha_x86_64": directly_loadable,
        "independent_thing4_viewer_client_implemented": False,
        "p2p_offer_sdp_answer_proven": False,
        "camera_commands": 0,
        "network_calls": 0,
        "secrets_or_binary_data_returned": False,
        "facts": facts,
    }


def analyze(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_APK:
        raise ValueError("invalid_archive")
    with path.open("rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != APK_SHA256:
            raise ValueError("wrong_apk_build")
    with zipfile.ZipFile(path) as outer:
        splits = {item.filename for item in outer.infolist()}
        image = outer.getinfo("split_config.arm64_v8a.apk")
        if image.file_size > MAX_SPLIT:
            raise ValueError("split_too_large")
        with zipfile.ZipFile(io.BytesIO(outer.read(image))) as archive:
            libraries: dict[str, bytes] = {}
            for lib in TARGETS:
                entry = archive.getinfo("lib/arm64-v8a/" + lib)
                if entry.file_size > MAX_LIBRARY:
                    raise ValueError("library_too_large")
                libraries[lib] = archive.read(entry)
    return summarize(libraries, "split_config.x86_64.apk" in splits)


def main() -> None:
    parser = argparse.ArgumentParser(description="AOSU Thing P2P ELF ABI metadata audit")
    parser.add_argument("apk", type=Path, help="Private complete 5.10.12 APK bundle")
    args = parser.parse_args()
    try:
        output = analyze(args.apk)
    except (OSError, ValueError, KeyError, IndexError, struct.error,
            zipfile.BadZipFile):
        output = {"audit": "smart_aosu_client_abi_portability_v1",
                  "state": "private_apk_unavailable_or_unrecognized",
                  "network_calls": 0, "secrets_or_binary_data_returned": False}
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
