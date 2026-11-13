#!/usr/bin/env python3
"""Read-only AOSU 5.10.12 DEX audit: Thing P2P type-4 session initialization.

Runs ONLY with the user's privately held complete APK; nothing is uploaded,
decrypted, executed, sent to a device, or printed except fixed boolean checks.
This is static SDK evidence, never proof of successful camera operation.
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

_SHA256 = "ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7"
_METHOD_INVOKES = {*range(0x6e, 0x73), *range(0x74, 0x79)}


def _words(code: bytes) -> tuple[int, ...]:
    return (struct.unpack(f'<{len(code)//2}H', code)
            if code and len(code) % 2 == 0 else ())


def _method_call(dex: DexIndex, words: tuple[int, ...], off: int,
                 class_suffix: str, method: str,
                 regs: tuple[int, ...] | None = None) -> bool:
    if off < 0 or off + 2 >= len(words) or words[off] & 0xff not in _METHOD_INVOKES:
        return False
    idx = words[off + 1]
    if idx >= len(dex.methods):
        return False
    cls, name = dex.methods[idx]
    if not cls.endswith(class_suffix) or name != method:
        return False
    if regs is not None:
        header, rword = words[off], words[off + 2]
        if header & 0xff not in range(0x6e, 0x73):
            return False
        size = header >> 12
        actual = (rword & 0xf, (rword >> 4) & 0xf,
                  (rword >> 8) & 0xf, (rword >> 12) & 0xf,
                  (header >> 8) & 0xf)[:size]
        return actual == regs
    return True


def _type4_gate(words: tuple[int, ...]) -> bool:
    """v5=p2pSpecifiedType; v6=4; if-ne v5,v6 skips type-4 path to 164."""
    return (len(words) > 219 and words[133] == 0x4612
            and words[134] == 0x6533 and words[135] == 30
            and words[163] == 0x3828)


def _type2_gate(words: tuple[int, ...]) -> bool:
    return (len(words) > 219 and words[164] == 0x2612
            and words[165] == 0x6533 and words[166] == 54)


def _method_words(dex: DexIndex, index: int, cls: str, name: str) -> tuple[int, ...]:
    # Method indexes and offsets are pinned to the exact archive SHA-256 above.
    if index >= len(dex.methods) or not (dex.methods[index][0].endswith(cls)
            and dex.methods[index][1] == name):
        return ()
    return _words(dex.code.get(index, b''))


def summarize(dex: DexIndex) -> dict:
    p = _method_words(dex, 5931, '/p2p/ThingSmartCameraP2PSync;', 'processCameraInfo')
    c = _method_words(dex, 3998, '/ipccamerasdk/IPCThingP2PCamera;', 'connect')
    init = _method_words(dex, 4030, '/ipccamerasdk/IPCThingP2PCamera;', 'initNativeOnce')
    preview = _method_words(dex, 4099, '/ipccamerasdk/IPCThingP2PCamera;', 'startPreview')
    create = _method_words(dex, 4003, '/ipccamerasdk/IPCThingP2PCamera;', 'createDevice')
    call = lambda words, off, cls, method, regs=None: _method_call(
        dex, words, off, cls, method, regs)
    facts = {
        'type4_gate_exact': _type4_gate(p),
        'type4_uses_camera_info_id': (
            call(p, 126, '/bean/CameraInfoBean;', 'getP2pSpecifiedType', (11,))
            and call(p, 136, '/bean/CameraInfoBean;', 'getId', (11,))
            and call(p, 140, '/bean/ConfigCameraBean;', 'setP2pId', (0, 5))),
        'type4_uses_camera_info_token_and_skill': (
            call(p, 149, '/bean/CameraInfoBean;', 'getP2PConfigStr', (11,))
            and call(p, 153, '/bean/ConfigCameraBean;', 'setToken', (0, 5))
            and call(p, 156, '/bean/CameraInfoBean;', 'getSkill', (11,))
            and call(p, 160, '/bean/ConfigCameraBean;', 'setSkill', (0, 5))),
        'type2_uses_distinct_config': (
            _type2_gate(p)
            and call(p, 167, '/bean/CameraInfoBean;', 'getP2pId', (11,))
            and call(p, 188, '/bean/CameraInfoBean;', 'getP2PConfigInitStr', (11,))),
        'full_camera_info_serialized_to_config_json': (
            call(p, 308, '/alibaba/fastjson/JSON;', 'toJSONString', (11,))
            and len(p) > 312 and p[311] == 0x090c
            and call(p, 312, '/bean/ConfigCameraBean;', 'setConfigJson', (0, 9))),
        'engine_receives_config_before_connect': (
            call(c, 263, '/bean/ConfigCameraBean;', 'getConfigJson', (3,))
            and call(c, 279, '/api/ThingCameraInterface;', 'setCameraConfig')
            and call(c, 302, '/api/ThingCameraInterface;', 'connect')
            and call(c, 335, '/api/ThingCameraInterface;', 'connect')
            and call(c, 360, '/api/ThingCameraInterface;', 'connect')
            and len({c[303], c[336], c[361]}) == 3),
        'native_initialization_present': (
            call(create, 96, '/IPCThingP2PCamera;', 'initNativeOnce')
            and call(init, 26, '/p2p/api/IThingP2P;', 'init')
            and call(init, 68, '/api/ThingCameraEngineInterface;', 'initP2PModule')),
        'preview_is_separate_phase': call(
            preview, 157, '/api/ThingCameraInterface;', 'startPreview'),
    }
    return {
        'audit': 'aosu_c9c_type4_route_offline_v1',
        'apk_build': 'AOSU_5.10.12',
        'static_apk_evidence_only': True,
        'camera_runtime_route_confirmed': False,
        'video_confirmed': False,
        'native_client_implemented_in_ha': False,
        'network_calls': 0, 'camera_commands': 0,
        'user_secrets_or_ids_exported': False,
        'facts': {k: bool(v) for k, v in facts.items()},
    }


def analyze(apk: Path) -> dict:
    if apk.stat().st_size > 350_000_000:
        raise ValueError('archive_trop_grande')
    with apk.open('rb') as f:
        if hashlib.file_digest(f, 'sha256').hexdigest() != _SHA256:
            raise ValueError('archive_differente')
    with zipfile.ZipFile(apk) as outer:
        base = outer.getinfo('base.apk')
        if base.file_size > 260_000_000:
            raise ValueError('base_trop_grande')
        with zipfile.ZipFile(io.BytesIO(outer.read('base.apk'))) as inner:
            info = inner.getinfo('classes6.dex')
            if info.file_size > 12_000_000:
                raise ValueError('dex_trop_grand')
            return summarize(DexIndex(inner.read('classes6.dex')))


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Audit hors ligne du parcours P2P type 4')
    parser.add_argument('apk', type=Path)
    args = parser.parse_args()
    try:
        result = analyze(args.apk)
    except (OSError, ValueError, IndexError, KeyError, struct.error,
            zipfile.BadZipFile):
        result = {'audit': 'aosu_c9c_type4_route_offline_v1',
                  'etat': 'apk_non_valide', 'network_calls': 0,
                  'user_secrets_or_ids_exported': False}
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
