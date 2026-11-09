#!/usr/bin/env python3
"""Static AOSU SDK route audit. APK stays local, no network or secret export."""
from __future__ import annotations
import argparse
import io
import json
import struct
import zipfile
from pathlib import Path


class DexIndex:
    """Minimal DEX index for method invocation and field-access evidence."""

    def __init__(self, raw: bytes):
        if len(raw) < 0x70 or raw[:4] != b"dex\n":
            raise ValueError("invalid_dex")
        self.raw = raw
        u32 = lambda off: struct.unpack_from("<I", raw, off)[0]
        self.strings = []
        for i in range(u32(0x38)):
            pos = u32(u32(0x3C) + i * 4)
            _, pos = self._uleb(pos)
            end = raw.index(b"\0", pos)
            self.strings.append(raw[pos:end].decode("utf-8", "replace"))
        types = [self.strings[u32(u32(0x44) + i * 4)] for i in range(u32(0x40))]
        self.methods = []
        for i in range(u32(0x58)):
            cls, _, name = struct.unpack_from("<HHI", raw, u32(0x5C) + i * 8)
            self.methods.append((types[cls], self.strings[name]))
        self.fields = []
        for i in range(u32(0x50)):
            cls, _, name = struct.unpack_from("<HHI", raw, u32(0x54) + i * 8)
            self.fields.append((types[cls], self.strings[name]))
        self.code = {}
        for i in range(u32(0x60)):
            dataoff = u32(u32(0x64) + i * 32 + 24)
            if not dataoff:
                continue
            cursor = dataoff
            counts = []
            for _ in range(4):
                n, cursor = self._uleb(cursor)
                counts.append(n)
            for n in counts[:2]:
                for _ in range(n):
                    _, cursor = self._uleb(cursor)
                    _, cursor = self._uleb(cursor)
            for n in counts[2:]:
                index = 0
                for _ in range(n):
                    diff, cursor = self._uleb(cursor)
                    index += diff
                    _, cursor = self._uleb(cursor)
                    codeoff, cursor = self._uleb(cursor)
                    if codeoff:
                        size = u32(codeoff + 12)
                        if size <= 100_000 and codeoff + 16 + size * 2 <= len(raw):
                            self.code[index] = raw[codeoff+16:codeoff+16+size*2]

    def _uleb(self, off: int) -> tuple[int, int]:
        num = 0
        for shift in range(0, 35, 7):
            x = self.raw[off]
            off += 1
            num |= (x & 127) << shift
            if x & 128 == 0:
                return num, off
        raise ValueError("uleb_invalid")

    def method(self, cls: str, name: str) -> bytes:
        matching = [i for i, (c, n) in enumerate(self.methods)
                    if c.endswith(cls) and n == name and i in self.code]
        return self.code[matching[0]] if len(matching) == 1 else b""

    @staticmethod
    def referenced(data: bytes, ref: int, allowed: tuple[int, ...]) -> bool:
        needle = struct.pack("<H", ref)
        return any(data[k:k+2] == needle and data[k-2] in allowed
                   for k in range(2, len(data)-1, 2))

    def calls(self, data: bytes, cls: str, name: str) -> bool:
        calls = tuple(range(0x6E,0x73)) + tuple(range(0x74,0x79))
        return any(self.referenced(data,i,calls)
                   for i,(c,n) in enumerate(self.methods)
                   if c.endswith(cls) and n == name)

    def field_access(self, data: bytes, cls: str, name: str,
                     opcodes: tuple[int, ...]) -> bool:
        return any(self.referenced(data,i,opcodes)
                   for i,(c,n) in enumerate(self.fields)
                   if c.endswith(cls) and n == name)


def summarize(indexes: dict[str, DexIndex], dex_count: int) -> dict:
    d16,d11,d6 = (indexes[n] for n in
                  ("classes16.dex","classes11.dex","classes6.dex"))
    resolver=d16.method("/ty/TyDeviceCenter;","Oooo000")
    camera=d16.method("/ty/TyCameraCenter;","Oooo000")
    convert=d11.method("/server/UUIDInfoWebDataItem;","OooO0O0")
    provider=d6.method("/utils/CameraConstant;","getSdkProvider")
    connect=d6.method("/p2p/ThingSmartCameraP2PSync;","innerConnect")
    facts = {
      "aosu_device_lookup": d16.calls(resolver,"/device/DeviceBusiness;","getDeviceInfo"),
      "aosu_cp_device_id_field": d16.field_access(resolver,"/model/GzDeviceInfo;","cpDeviceId",(0x54,)),
      "camera_platform_adapter": d16.calls(camera,"/iot/IotDevice;","Oooo000"),
      "camera_tuya_creation": d16.calls(camera,"/api/IThingIPCCore;","createCameraP2P"),
      "web_coop_uuid": d11.field_access(convert,"/server/UUIDInfoWebDataItem;","coopUUID",(0x54,)),
      "web_maps_to_cp_id": d11.field_access(convert,"/model/GzDeviceInfo;","cpDeviceId",(0x5B,)),
      "provider_uses_skills": d6.calls(provider,"/bean/DeviceBean;","getSkills"),
      "provider_uses_product": d6.calls(provider,"/bean/DeviceBean;","getProductBean"),
      "connect_checks_p2p_type": d6.calls(connect,"/utils/CameraConstant;","getDeviceP2PType"),
    }
    return {"diagnostic":"aosu_sdk_route_offline_v1","dex_count":dex_count,
            "static_only":True,"identity_confirmed":False,
            "video_confirmed":False,"network_calls":0,
            "secrets_exported":False,"facts":facts}


def analyze(path: Path) -> dict:
    if path.stat().st_size > 350_000_000:
        raise ValueError("archive_too_large")
    with zipfile.ZipFile(path) as outer:
        if "base.apk" in outer.namelist():
            inner = zipfile.ZipFile(io.BytesIO(outer.read("base.apk")))
        else:
            inner = outer
        with inner:
            names = [n for n in inner.namelist()
                     if n.startswith("classes") and n.endswith(".dex")]
            req = ("classes6.dex","classes11.dex","classes16.dex")
            if any(name not in names for name in req):
                raise ValueError("full_apk_required")
            indexes = {name: DexIndex(inner.read(name)) for name in req}
    return summarize(indexes,len(names))


def main() -> None:
    cli=argparse.ArgumentParser(description="Private offline AOSU SDK route audit")
    cli.add_argument("apk",type=Path,help="Your local full APK/APKS; never uploaded")
    args=cli.parse_args()
    try:
        print(json.dumps(analyze(args.apk),ensure_ascii=False,indent=2))
    except (OSError,ValueError,struct.error,zipfile.BadZipFile):
        print('{"diagnostic":"aosu_sdk_route_offline_v1","etat":"archive_non_exploitable"}')
        raise SystemExit(2)


if __name__=="__main__":
    main()
