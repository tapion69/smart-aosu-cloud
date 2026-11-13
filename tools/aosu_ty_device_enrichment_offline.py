#!/usr/bin/env python3
"""Offline audit of AOSU Android TyDeviceInfoSource enrichment chain.

Requires the device owner's complete 5.10.12 APK/APKS only when run locally.
No network traffic or output of identifiers, strings, tokens, serial numbers,
firmware contents, camera commands, keys or proprietary bytecode.
Do not commit the APK or the emitted private DEX data to the public repo.

This is STATIC call-graph evidence, not a trace of a real camera session.
"""
from __future__ import annotations
import argparse
import io
import json
import struct
import zipfile
from pathlib import Path
from aosu_sdk_route_offline import DexIndex


def summarize(d: DexIndex, dex_count: int) -> dict:
    source = "/device/mid/TyDeviceInfoSource;"
    init_event = "/device/mid/TyDeviceInfoSource$init$1;"
    callback = "/device/mid/TyDeviceInfoSource$loadDeviceInfoList$1$1;"
    cache_callback = "/device/mid/TyDeviceInfoSource$getDeviceInfoListCache$1;"
    repo_callback = "/device/impl/DeviceInfoRepoImpl$loadDeviceInfoList$1$1$1;"
    ext = "/device/ext/DeviceInfoExtKt;"
    iot = "/spi/iot/IotDevice;"
    platform_info = "/model/PlatformDeviceInfo;"
    gz_info = "/model/GzDeviceInfo;"
    def m(name, method):
        return d.method(name, method)

    facts = {
        # Platform Ty list retrieval is an IotDevice SDK operation, not an
        # AOSU HTTP getList/getInfoBySn API response.
        "tuya_sdk_async_device_list":
            d.calls(m(source, "OooOO0o"), iot, "Oooo00O"),
        "tuya_sdk_gets_device_list_from_cache":
            d.calls(m(callback, "OooO0OO"), iot, "Oooo0OO"),
        "tuya_sdk_batch_lookup_by_device_set":
            d.calls(m(source, "OooO0o"), iot, "OoooO00"),
        "tuya_sdk_cache_lookup_available":
            d.calls(m(source, "OooO0oo"),
                    "/util/concurrent/ConcurrentHashMap;", "get"),
        "tuya_sdk_cp_id_cache_index":
            d.field_access(m(source, "OooOOOO"), gz_info,
                           "cpDeviceId", (0x54,)) and
            d.calls(m(source, "OooOOOO"),
                    "/util/concurrent/ConcurrentHashMap;", "putAll"),
        "aosu_load_device_list_calls_tuya_source":
            d.calls(m(repo_callback, "OooO00o"), source, "OooOOOo"),
        # The SDK event actually attaches PlatformDeviceInfo to the
        # GzDeviceInfo object after CP-ID lookup.
        "tuya_sdk_event_has_cp_device_id":
            d.field_access(m(init_event, "OooO00o"), platform_info,
                           "cpDeviceId", (0x54,)),
        "tuya_sdk_event_looks_up_aosu_device":
            d.calls(m(init_event, "OooO00o"),
                    "/device/DeviceBusiness;", "getDeviceInfo"),
        "tuya_sdk_event_enriches_aosu_device":
            d.calls(m(init_event, "OooO00o"), gz_info, "setCpDataInfo"),
        # The Android platform-Ty camera path reads the enriched
        # GzDeviceInfo.cpDeviceInfo.cpUuid, not its web-list devId.
        "android_ty_path_reads_nested_cp_device_info":
            d.field_access(m(ext, "OooO0O0"), gz_info,
                           "cpDeviceInfo", (0x54,)),
        "android_ty_path_reads_cp_uuid":
            d.field_access(m(ext, "OooO0O0"), platform_info,
                           "cpUuid", (0x54,)),
    }
    return {
        "diagnostic": "aosu_ty_device_enrichment_static_v1",
        "dex_count": dex_count,
        "analyse_statique_seulement": True,
        "liaison_c9c_aosu_tuya_prouvee": False,
        "execution_sdk_camera_prouvee": False,
        "source_cp_uuid_http_prouvee": False,
        "appel_reseau": 0,
        "video": False,
        "commandes_camera": 0,
        "commandes_ptz": 0,
        "secrets_retournes": False,
        "identifiants_retournes": False,
        "faits": {k: v is True for k, v in facts.items()},
    }


def analyze(path: Path) -> dict:
    if path.stat().st_size > 350_000_000:
        raise ValueError("archive_trop_grande")
    with zipfile.ZipFile(path) as outer:
        if "base.apk" in outer.namelist():
            base = outer.getinfo("base.apk")
            if base.file_size > 300_000_000:
                raise ValueError("base_trop_grande")
            inner = zipfile.ZipFile(io.BytesIO(outer.read("base.apk")))
        else:
            inner = outer
        with inner:
            item = inner.getinfo("classes15.dex")
            if item.file_size > 20_000_000:
                raise ValueError("dex_trop_grand")
            raw = inner.read("classes15.dex")
            num = len([k for k in inner.namelist()
                       if k.startswith("classes") and k.endswith(".dex")])
    return summarize(DexIndex(raw), num)


def main():
    parser = argparse.ArgumentParser(description="Audit statique AOSU/Tuya TyDataInfo bridge")
    parser.add_argument("apk", type=Path, help="APK personnelle locale, jamais envoyée")
    args = parser.parse_args()
    try:
        out = analyze(args.apk)
    except (OSError, KeyError, ValueError, IndexError, struct.error,
            zipfile.BadZipFile):
        out = {
            "diagnostic": "aosu_ty_device_enrichment_static_v1",
            "etat": "archive_non_exploitable",
            "secrets_retournes": False,
        }
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
