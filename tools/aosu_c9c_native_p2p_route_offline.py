#!/usr/bin/env python3
"""Static, read-only AOSU 5.10.12 native P2P prerequisite audit.

Works offline on a user-owned APK/APKS. Reports only fixed booleans and
counts; never loads or executes proprietary code and never exports bytecode,
identifiers, endpoint data, passwords, tokens, local keys or device details.
This is method-reference evidence, NOT native protocol/wire parity.
"""
from __future__ import annotations

import argparse
import io
import json
import struct
import zipfile
from pathlib import Path

from aosu_sdk_route_offline import DexIndex

_FILES = ('classes6.dex', 'classes16.dex')
_NATIVE = '/camera/middleware/p2p/ThingSmartCameraP2PSync;'


def summarize(indexes: dict[str, DexIndex], *, dex_count: int) -> dict:
    six, sixteen = (indexes[name] for name in _FILES)
    connect = six.method(_NATIVE, 'innerConnect')
    prepare = six.method(_NATIVE, 'processCameraInfo')
    request = six.method(_NATIVE, 'requestCameraConfig')
    camera = sixteen.method('/mid/iot/ty/TyCameraCenter;', 'Oooo000')
    type_logic = six.method('/camera/ipccamerasdk/utils/CameraConstant;',
                            'getDeviceP2PType')
    checks = {
        'native_home_proxy': six.calls(
            connect, '/camera/sdk/ThingIPCSdk;', 'getHomeProxy'),
        'native_device_bean': six.calls(
            connect, '/camera/sdk/api/IThingIPCDevice;', 'getDeviceBean'),
        'native_skills': six.calls(
            connect, '/sdk/bean/DeviceBean;', 'getSkills'),
        'native_p2p_type': six.calls(
            connect, '/camera/ipccamerasdk/utils/CameraConstant;',
            'getDeviceP2PType'),
        'native_p2p_type_from_skills': six.calls(
            type_logic, '/util/Map;', 'get'),
        'native_requests_camera_config': six.calls(
            connect, _NATIVE, 'requestCameraConfig'),
        'native_camera_business': six.calls(
            request, '/ipccamerasdk/business/CameraBusiness;',
            'requestCameraInfo'),
        'native_p2p_policy': six.calls(
            connect, '/ipccamerasdk/bean/CameraInfoBean;', 'getP2pPolicy'),
        'native_session_tid': six.calls(
            connect, '/ipccamerasdk/bean/CameraInfoBean;', 'getSessionTid'),
        'native_client_tid': six.calls(
            connect, _NATIVE, 'getClientTid'),
        'native_p2p_config': six.calls(
            prepare, '/ipccamerasdk/bean/CameraInfoBean;',
            'getP2PConfigStr'),
        'native_p2p_id': six.calls(
            prepare, '/ipccamerasdk/bean/CameraInfoBean;', 'getP2pId'),
        'native_local_key': six.calls(
            prepare, '/sdk/bean/DeviceBean;', 'getLocalKey'),
        'native_config_skill': six.calls(
            prepare, '/ipccamerasdk/bean/ConfigCameraBean;', 'setSkill'),
        'native_config_trace': six.calls(
            prepare, '/ipccamerasdk/bean/ConfigCameraBean;',
            'setClientTraceId'),
        'native_ipc_creation': six.calls(
            prepare, _NATIVE, 'createDeviceIPC'),
        'aosu_ty_camera_core_creates_p2p': sixteen.calls(
            camera, '/camera/sdk/api/IThingIPCCore;', 'createCameraP2P'),
    }
    all_confirmed = all(checks.values())
    return {
        'diagnostic': 'aosu_c9c_native_p2p_route_offline_v1',
        'dex_count': dex_count,
        'static_only': True,
        'network_calls': 0, 'camera_commands': 0, 'video_calls': 0,
        'secrets_exported': False,
        'checks': {key: bool(value) for key, value in checks.items()},
        'checks_present_count': sum(bool(value) for value in checks.values()),
        'checks_total_count': len(checks),
        'sdk_route_static_confirmed': all_confirmed,
        'binary_protocol_parity_proven': False,
        'device_identity_proven': False,
        'ready_for_camera_send': False,
        'python_native_equivalence_proven': False,
    }


def analyze(apks: Path) -> dict:
    if apks.stat().st_size > 350_000_000:
        raise ValueError('archive_too_large')
    with zipfile.ZipFile(apks) as outer:
        if 'base.apk' in outer.namelist():
            info = outer.getinfo('base.apk')
            if info.file_size > 300_000_000:
                raise ValueError('base_apk_too_large')
            inner = zipfile.ZipFile(io.BytesIO(outer.read('base.apk')))
        else:
            inner = outer
        with inner:
            names = [name for name in inner.namelist()
                     if name.startswith('classes') and name.endswith('.dex')]
            if any(name not in names for name in _FILES):
                raise ValueError('full_apk_required')
            if any(inner.getinfo(name).file_size > 20_000_000
                   for name in _FILES):
                raise ValueError('dex_too_large')
            indexes = {name: DexIndex(inner.read(name)) for name in _FILES}
    return summarize(indexes, dex_count=len(names))


def main() -> None:
    parser = argparse.ArgumentParser(
        description='Static AOSU P2P SDK prerequisites, private offline APK')
    parser.add_argument('apk', type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args.apk)
        print(json.dumps(report, ensure_ascii=False, indent=2))
    except (OSError, ValueError, IndexError, KeyError, struct.error,
            zipfile.BadZipFile):
        print(json.dumps({
            'diagnostic': 'aosu_c9c_native_p2p_route_offline_v1',
            'etat': 'archive_non_exploitable', 'secrets_exported': False
        }))
        raise SystemExit(2)


if __name__ == '__main__':
    main()
