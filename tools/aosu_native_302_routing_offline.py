#!/usr/bin/env python3
"""Offline AOSU 5.10.12 proof of Java/native Thing-4 signaling dispatch.

Requires ONLY the user's already-owned complete APK bundle. Never calls
network, starts the SDK, executes the APK, or prints private SDK strings,
camera IDs, tokens, decrypted messages, addresses, P2P packets or keys.

This is an ABI/call-graph audit, NOT a protocol implementation and not
evidence that one particular camera ran the examined branch.
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

_ORIGINAL_SHA256 = "ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7"
_MAX_ARCHIVE_BYTES = 350_000_000
_MAX_NATIVE_BYTES = 8_000_000
_REQUIRED_EXPORTS = {
    "native_mqtt_bridge": "_ZN16ThingSmartP2PSDK22SendMessageThroughMQTTEPcS0_j",
    "native_lan_bridge": "_ZN16ThingSmartP2PSDK21SendMessageThroughLANEPcS0_j",
    "native_connection_v3": "ThingP2PConnect_v3",
    "native_http_callback": "ThingP2PSetHttpResult",
    "native_signaling_callback": "ThingP2PSetSignaling",
}


def _read_elf_dynsyms(raw: bytes) -> set[str]:
    """Read only ELF64 little-endian exported names; no ELF code execution."""
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01":
        raise ValueError("elf_arm64_manquant")
    def u16(n): return struct.unpack_from("<H", raw, n)[0]
    def u32(n): return struct.unpack_from("<I", raw, n)[0]
    def u64(n): return struct.unpack_from("<Q", raw, n)[0]
    if u16(18) != 183:  # EM_AARCH64
        raise ValueError("architecture_native_non_arm64")
    shoff, entsize, shnum = u64(0x28), u16(0x3A), u16(0x3C)
    if not 64 <= entsize <= 256 or not 0 < shnum < 512:
        raise ValueError("sections_elf_invalides")
    if shoff + shnum * entsize > len(raw):
        raise ValueError("sections_elf_debordement")
    sections = []
    for index in range(shnum):
        off = shoff + index * entsize
        sections.append({
            "type": u32(off + 4),
            "offset": u64(off + 0x18),
            "size": u64(off + 0x20),
            "link": u32(off + 0x28),
            "entsize": u64(off + 0x38),
        })
    out = set()
    for section in sections:
        if section["type"] != 11:
            continue
        link, width = section["link"], section["entsize"]
        if link >= len(sections) or width < 24:
            continue
        tab = sections[link]
        if (tab["offset"] + tab["size"] > len(raw)
            or section["offset"] + section["size"] > len(raw)):
            raise ValueError("table_debordement")
        strings = raw[tab["offset"]:tab["offset"]+tab["size"]]
        count = min(50000, section["size"] // width)
        for i in range(count):
            st = section["offset"] + i * width
            nameoff = struct.unpack_from("<I", raw, st)[0]
            if nameoff >= len(strings):
                continue
            end = strings.find(b"\x00", nameoff, min(nameoff+256,len(strings)))
            if end < 0: continue
            # Only exact known function names can escape this method.
            name = strings[nameoff:end]
            for check in _REQUIRED_EXPORTS.values():
                if name == check.encode("ascii"):
                    out.add(check)
    return out


def _check_thing_send302_gate(words: tuple[int, ...]) -> dict:
    """Check the exact 5.10.12 v8 Java boolean branch, not just DEX strings.

    v8 is the 'is by lan' argument in this 11-register instance method.
    Opcode 0x38 is if-eqz, jumping from 44 to 55 when false.  True
    enters IThingHomeCamera.lan302Publish; false enters publish.
    """
    if len(words) != 75:
        return {"branche_lan_verifiee": False,
                "branche_mqtt_verifiee": False}
    branch = (words[44] & 255) == 0x38 and (words[44] >> 8) == 8
    relative = struct.unpack("<h", struct.pack("<H", words[45]))[0]
    return {
        "branche_lan_verifiee": bool(branch and 44 + relative == 55),
        "branche_mqtt_verifiee": bool(branch and 44 + relative == 55),
    }


def summarize(dex: DexIndex, native_exports: set[str]) -> dict:
    native = {name: ref in native_exports
              for name, ref in _REQUIRED_EXPORTS.items()}
    sender = dex.method("/p2p/utils/P2PMQTTServiceManager;",
                        "send302MessageThroughMqtt")
    jni = dex.method("/p2psdk/ThingP2PSDK;",
                     "sendMessageThroughMqtt")
    words = (tuple(struct.unpack_from("<H", sender, i)
                   for i in range(0, len(sender), 2))
             if sender and len(sender) % 2 == 0 else ())
    checked = _check_thing_send302_gate(words)
    facts = {
        "jni_to_java_mqtt_manager": bool(jni and
            dex.calls(jni,"/p2p/utils/IMqttServiceUtils;",
                      "send302MessageThroughMqtt")),
        "sdk_reads_device_bean": bool(sender and
            dex.calls(sender,"/p2p/utils/P2PMQTTServiceManager;",
                      "getDeviceBean")),
        "sdk_reads_pv": bool(sender and
            dex.calls(sender,"/sdk/bean/DeviceBean;","getPv")),
        "sdk_reads_local_key": bool(sender and
            dex.calls(sender,"/sdk/bean/DeviceBean;","getLocalKey")),
        "sdk_has_lan_publish": bool(sender and
            dex.calls(sender,"/android/camera/api/IThingHomeCamera;",
                      "lan302Publish")),
        "sdk_has_mqtt_publish": bool(sender and
            dex.calls(sender,"/android/camera/api/IThingHomeCamera;",
                      "publish")),
        **checked,
        **native,
    }
    return {
        "diagnostic": "aosu_c9c_native_302_routing_offline_v1",
        "code_etendu": "AOSU_5_10_12_ARM64",
        "analyse_statique_uniquement": True,
        "parite_protocole_thing4_prouvee": False,
        "camera_c9c_identifiee": False,
        "offre_native_observee": False,
        "executable_sur_home_assistant_x86_64": False,
        "appels_reseau": 0, "actions_camera": 0,
        "identifiants_et_secrets_retournes": False,
        "faits": {key: value is True for key, value in facts.items()},
    }


def analyze(path: Path) -> dict:
    if path.stat().st_size > _MAX_ARCHIVE_BYTES:
        raise ValueError("archive_trop_grande")
    raw_archive = path.read_bytes()
    if hashlib.sha256(raw_archive).hexdigest() != _ORIGINAL_SHA256:
        raise ValueError("version_apk_non_identique")
    with zipfile.ZipFile(io.BytesIO(raw_archive)) as outer:
        with zipfile.ZipFile(io.BytesIO(outer.read("base.apk"))) as inner:
            info = inner.getinfo("classes6.dex")
            if info.file_size > 25_000_000:
                raise ValueError("dex_trop_grand")
            dex = DexIndex(inner.read("classes6.dex"))
        with zipfile.ZipFile(io.BytesIO(
                outer.read("split_config.arm64_v8a.apk"))) as native:
            matches = [n for n in native.namelist()
                       if n.endswith("/libThingP2PSDK.so")]
            if len(matches) != 1:
                raise ValueError("bibliotheque_p2p_non_trouvee")
            info = native.getinfo(matches[0])
            if info.file_size > _MAX_NATIVE_BYTES:
                raise ValueError("bibliotheque_trop_grande")
            binary = native.read(info)
    return summarize(dex, _read_elf_dynsyms(binary))


def main() -> None:
    cli = argparse.ArgumentParser(description="Audit JNI → LAN/MQTT 302 hors ligne")
    cli.add_argument("apk", type=Path,
                     help="archive APK propriétaire de l'utilisateur, locale uniquement")
    args = cli.parse_args()
    try:
        result = analyze(args.apk)
    except (OSError, ValueError, KeyError, IndexError,
            struct.error, zipfile.BadZipFile):
        result = {
            "diagnostic": "aosu_c9c_native_302_routing_offline_v1",
            "etat": "archive_non_exploitable_ou_version_incompatible",
            "identifiants_et_secrets_retournes": False,
            "appels_reseau": 0,
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
