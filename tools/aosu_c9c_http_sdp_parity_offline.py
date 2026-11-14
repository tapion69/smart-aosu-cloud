#!/usr/bin/env python3
"""Offline-only AOSU OEM HTTP offer parity audit.

Run on the ORIGINAL owner-owned AOSU 5.10.12 APKS (nested APK), locally.
No network, camera commands, binary extraction to disk, secrets, or raw values
in output. Pin native ELF SHA to avoid speculative offset matching.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import zipfile

ELF_SHA256="c9032dcf37f72fc7ad28835a02c4e66a814597380f10c132d042df78969f1745"
MAX_APK=350_000_000
MAX_SPLIT=150_000_000
MAX_ELF=5_000_000


def _u32(elf:bytes, at:int)->int:
    return struct.unpack_from("<I",elf,at)[0]


def _bl_target(elf:bytes,at:int)->int|None:
    instruction=_u32(elf,at)
    if (instruction>>26)!=0b100101:
        return None
    offset=instruction & 0x3ffffff
    if offset & 0x2000000:
        offset-=0x4000000
    return at+(offset<<2)


def _literal(elf:bytes,at:int,s:bytes)->bool:
    return elf[at:at+len(s)+1]==s+b"\0"


def inspect_contract(elf:bytes, python_bootstrap:str,
                     python_mqtt:str, python_http:str,
                     *, enforce_sha:bool=True)->dict:
    if len(elf)>MAX_ELF or len(elf)<0x11ac30:
        raise ValueError("native_elf_bad_size")
    if enforce_sha and hashlib.sha256(elf).hexdigest()!=ELF_SHA256:
        raise ValueError("native_elf_unrecognized")
    native={
      "sdk_native_sdp_encoding_called_before_http":_bl_target(elf,0x69ad4)==0x43690,
      "sdk_sdp_supports_multiple_media_kinds":all(
          _literal(elf,address,label) for address,label in (
              (0x11a8f2,b"audio"),(0x11a8fa,b"video"),
              (0x118955,b"imm"))),
      "sdk_sdp_media_line_is_dynamic":
          _literal(elf,0x11a9f3,b"m=%s 9 %s%s\r\n"),
      "sdk_sdp_bundle_is_dynamic":
          _literal(elf,0x11a99a,
                   b"v=0\r\no=- %lu 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
                   b"a=group:BUNDLE%s\r\na=msid-semantic: WMS %s\r\n"),
      "sdk_native_token_json_parsing":all(
          _bl_target(elf,offset)==0x413a0 for offset in
          (0x69c40,0x69c50,0x69c60,0x69c70)),
      "sdk_native_token_fields":all(
          _literal(elf,offset,key) for offset,key in (
              (0x1183c7,b"token"),(0x1183b9,b"udp_token"),
              (0x1183c3,b"tcp_token"),(0x11705a,b"log"))),
      "sdk_native_optional_token_items":all(
          (_u32(elf,offset)&0xff000000) in (0xb4000000,0xb5000000)
          for offset in (0x69c9c,0x69cb4,0x69ccc,0x69ce4)),
    }
    python={
      "python_sdp_is_fixed_one_media":
          "'m=application 9 imm 6001'" in python_bootstrap and
          "'a=group:BUNDLE imm0'" in python_bootstrap,
      "python_token_is_ice_server_list":
          "'token':media.ice_servers" in python_mqtt,
      "python_tcp_token_is_reconstructed":
          "tcp=dict(media.relay)" in python_mqtt,
      "python_http_forwards_only_prepared_tokens":
          '("sdp","token","udp_token","tcp_token","log")' in python_http,
      "python_mqtt_does_not_generate_udp_token":
          "'udp_token':" not in python_mqtt and
          '"udp_token":' not in python_mqtt,
    }
    return {
      "diagnostic":"aosu_c9c_http_sdp_native_parity_offline_v1",
      "verified_oem_binary":bool(enforce_sha),
      "native_facts":native,"python_facts":python,
      "native_python_sdp_identical_proven":False,
      "native_python_token_identical_proven":False,
      "native_http_refusal_cause_identified":False,
      "session_identity_aosu_tuya_proven":False,
      "network_calls":0,"camera_commands":0,"secrets_returned":False,
    }


def read_native_elf(apk:Path)->bytes:
    if not apk.is_file() or apk.stat().st_size>MAX_APK:
        raise ValueError("archive_size")
    with zipfile.ZipFile(apk) as bundle:
        name="split_config.arm64_v8a.apk"
        if name not in bundle.namelist():
            raise ValueError("arm64_split_missing")
        member=bundle.getinfo(name)
        if member.file_size>MAX_SPLIT:
            raise ValueError("arm64_split_too_large")
        with zipfile.ZipFile(io.BytesIO(bundle.read(name))) as split:
            libs=[x for x in split.namelist()
                  if x.endswith("/libThingP2PSDK.so")]
            if len(libs)!=1 or split.getinfo(libs[0]).file_size>MAX_ELF:
                raise ValueError("native_elf_missing")
            return split.read(libs[0])


def main()->None:
    root=Path(__file__).resolve().parents[1]
    arg=argparse.ArgumentParser()
    arg.add_argument("full_apk",type=Path)
    opts=arg.parse_args()
    comp=root/"custom_components"/"smart_aosu_cloud"
    try:
        elf=read_native_elf(opts.full_apk)
        result=inspect_contract(
            elf,(comp/"tuya_media_bootstrap.py").read_text(),
            (comp/"tuya_mqtt_offer.py").read_text(),
            (comp/"c9c_thing4_http_once.py").read_text())
        print(json.dumps(result,sort_keys=True,indent=2))
    except (OSError,ValueError,zipfile.BadZipFile,struct.error):
        print('{"diagnostic":"aosu_c9c_http_sdp_native_parity_offline_v1","etat":"archive_incompatible"}')
        raise SystemExit(2)


if __name__=="__main__":
    main()
