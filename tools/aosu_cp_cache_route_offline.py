#!/usr/bin/env python3
"""AOSU 5.10.12 Android CP cache audit, read-only, no identifiers in output."""
from __future__ import annotations
import argparse
import io
import json
import struct
import zipfile
from pathlib import Path
from aosu_sdk_route_offline import DexIndex

_REQUIRED = ('classes11.dex','classes15.dex')

def summarize(dex: dict[str,DexIndex], dex_count: int) -> dict:
    a,d=dex['classes11.dex'],dex['classes15.dex']
    conversion=a.method('/server/UUIDInfoWebDataItem;','OooO0O0')
    business=d.method('/device/impl/DeviceBusinessImpl;','getDeviceInfo')
    repo_get=d.method('/device/impl/DeviceInfoRepoImpl;','getDeviceInfo')
    repo_web=d.method('/device/impl/DeviceInfoRepoImpl;','OoooOO0')
    repo_merge=d.method('/device/impl/DeviceInfoRepoImpl$loadDeviceInfoList$1$1;','OooO00o')
    repo_join=d.method('/device/impl/DeviceInfoRepoImpl$loadDeviceInfoList$1$1$1;','OooO00o')
    sdk_devices=d.method('/device/mid/TyDeviceInfoSource;','OooO0o')
    ty_set=d.method('/device/mid/TyDeviceInfoSource;','OooOOOO')
    ty_get=d.method('/device/mid/TyDeviceInfoSource;','OooO0oo')
    # A Tuya platform event also enriches an AOSU device by its CP ID.
    platform_event=d.method('/device/mid/TyDeviceInfoSource$init$1;','OooO00o')
    # Additional path verified in the full APK: repository-level merge, with
    # an independent cpUuid read. These are bytecode references, not evidence
    # that the user's external C9C exposes any runtime identifier.
    repo_platform_merge=d.method('/device/impl/DeviceInfoRepoImpl;','o000oOoO')
    platform_selector=d.method('/device/ext/DeviceInfoExtKt;','OooO0O0')
    facts={
     'web_coop_uuid_to_cp_id':a.field_access(conversion,'/server/UUIDInfoWebDataItem;','coopUUID',(0x54,)) and a.field_access(conversion,'/model/GzDeviceInfo;','cpDeviceId',(0x5b,)),
     'business_looks_up_data_repository':d.calls(business,'/device/DeviceInfoDataRepo;','getDeviceInfo'),
     'repository_reads_local_device_cache':d.calls(repo_get,'/util/concurrent/ConcurrentHashMap;','get'),
     'device_loader_requests_aosu_web_list':d.calls(repo_web,'/device/service/DeviceWebService;','OooOOOO'),
     'device_loader_invokes_tuya_source':d.calls(repo_merge,'/device/mid/TyDeviceInfoSource;','OooOOO0'),
     'join_reads_cp_id_and_tuya_source':d.field_access(repo_join,'/model/GzDeviceInfo;','cpDeviceId',(0x54,)) and d.calls(repo_join,'/device/mid/TyDeviceInfoSource;','OooOOOo'),
     'tuya_source_uses_sdk_device_interface':d.calls(sdk_devices,'/spi/iot/IotDevice;','OoooO00'),
     'tuya_cache_is_indexed_by_cp_id':d.field_access(ty_set,'/model/GzDeviceInfo;','cpDeviceId',(0x54,)) and d.calls(ty_set,'/util/concurrent/ConcurrentHashMap;','putAll'),
     'tuya_cache_supports_id_lookup':d.calls(ty_get,'/util/concurrent/ConcurrentHashMap;','get'),
     'platform_event_reads_cp_device_id':d.field_access(
          platform_event,'/model/PlatformDeviceInfo;','cpDeviceId',(0x54,)),
     'platform_event_looks_up_aosu_device':d.calls(
          platform_event,'/device/DeviceBusiness;','getDeviceInfo'),
     'platform_event_enriches_aosu_device':d.calls(
          platform_event,'/model/GzDeviceInfo;','setCpDataInfo'),
     'repository_joins_aosu_tuya_by_cp_id':(
          d.field_access(repo_platform_merge,'/model/GzDeviceInfo;','cpDeviceId',(0x54,))
          and d.field_access(repo_platform_merge,'/model/PlatformDeviceInfo;','cpDeviceId',(0x54,))
          and d.calls(repo_platform_merge,'/model/GzDeviceInfo;','setCpDataInfo')),
     'platform_selector_reads_cp_uuid':d.field_access(
          platform_selector,'/model/PlatformDeviceInfo;','cpUuid',(0x54,)),
    }
    return {'diagnostic':'aosu_cp_cache_route_offline_v4','dex_count':dex_count,'static_only':True,'network_calls':0,'video_calls':0,'camera_commands':0,'secrets_exported':False,'runtime_device_identity_confirmed':False,'external_c9c_cp_id_recovered':False,'facts':{k:bool(v) for k,v in facts.items()}}

def analyze(path:Path)->dict:
    if path.stat().st_size>350_000_000:raise ValueError('archive_too_large')
    with zipfile.ZipFile(path) as outer:
        if 'base.apk' in outer.namelist():
            item=outer.getinfo('base.apk')
            if item.file_size>300_000_000:raise ValueError('base_apk_too_large')
            apk=zipfile.ZipFile(io.BytesIO(outer.read('base.apk')))
        else:apk=outer
        with apk:
            names=[n for n in apk.namelist() if n.startswith('classes') and n.endswith('.dex')]
            if any(n not in names for n in _REQUIRED):raise ValueError('full_apk_required')
            if any(apk.getinfo(n).file_size>20_000_000 for n in _REQUIRED):raise ValueError('dex_too_large')
            dex={n:DexIndex(apk.read(n)) for n in _REQUIRED}
        return summarize(dex,len(names))

def main():
    cli=argparse.ArgumentParser(description='AOSU CP cache static audit; no network, no secrets')
    cli.add_argument('apk',type=Path)
    args=cli.parse_args()
    try:print(json.dumps(analyze(args.apk),ensure_ascii=False,indent=2))
    except (OSError,ValueError,IndexError,struct.error,zipfile.BadZipFile):
        print(json.dumps({'diagnostic':'aosu_cp_cache_route_offline_v4','etat':'archive_non_exploitable','secrets_exported':False}))
        raise SystemExit(2)
if __name__=='__main__':main()
