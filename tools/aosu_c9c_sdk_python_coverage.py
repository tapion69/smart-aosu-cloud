#!/usr/bin/env python3
"""Offline matrix of AOSU 5.10.12 SDK camera requirements vs Python HA.

No account, network, APK contents, names or identifiers in the report.
No native vendor binary is copied or redistributed. Static references prove
only code paths, never execution, delivery of an SDP or protocol parity.
"""
from __future__ import annotations
import argparse
import ast
import io
import json
import struct
import zipfile
from pathlib import Path
from aosu_sdk_route_offline import DexIndex

_DEX=("classes4.dex","classes5.dex","classes6.dex","classes16.dex")
_LIMIT=30_000_000

def _source(path:Path)->str:
    # Static local source code only; strictly bound bytes.
    if not path.is_file() or path.stat().st_size>300_000:raise ValueError("python_source_unavailable")
    return path.read_text(encoding="utf-8")

def _method_source(src:str,name:str)->str:
    tree=ast.parse(src)
    functions=[x for x in tree.body if isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name==name]
    return ast.get_source_segment(src,functions[0]) if len(functions)==1 else ""

def _python_flags(root:Path)->dict[str,bool]:
    package=root/"custom_components"/"smart_aosu_cloud"
    offer=_source(package/"tuya_mqtt_offer.py")
    signaling=_source(package/"tuya_mqtt_signaling.py")
    media=_source(package/"tuya_media_bootstrap.py")
    topology=_source(package/"camera_topology.py")
    frame=_method_source(offer,"_signal_frame")
    probe=_method_source(offer,"_probe")
    sdp=_method_source(media,"inspect_rtc_media")
    match=_method_source(topology,"select_tuya_standalone_target")
    return {
        "fabricates_json_aes_crc_frame":bool(frame) and all(s in frame for s in
            ("json.dumps","struct.pack","zlib.crc32","_encrypt")),
        "fabricates_aes_kcp_sdp":bool(sdp) and all(s in sdp for s in
            ("AES/KCP","a=ice-ufrag","a=ice-pwd")),
        "sends_sigqry_before_offer":bool(probe) and all(s in probe for s in
            ("'sigQry'","22,","302,")) and probe.find("'sigQry'")<probe.find("302,"),
        "uses_static_mqtt_broker":all(s in signaling for s in ("_BROKER = 'm1.tuyaeu.com'","_PORT = 8883")),
        "has_unverified_unique_device_fallback":bool(match) and "appareil_tuya_unique_sans_categorie_video" in match,
        "sends_offer_over_mqtt":bool(probe) and "_send_once(" in probe,
    }

def summarize(indexes:dict[str,DexIndex], native_libs:set[str],
              python_flags:dict[str,bool], dex_count:int)->dict:
    d4,d5,d6,d16=(indexes[name] for name in _DEX)
    connect=d6.method("/middleware/p2p/ThingSmartCameraP2PSync;","innerConnect")
    provider=d6.method("/ipccamerasdk/utils/CameraConstant;","getSdkProvider")
    tycamera=d16.method("/ty/TyCameraCenter;","Oooo000")
    mqtt=d5.method("/sdk/mqtt/bqbppdq;","initMqttConfig")
    sdk={
        "camera_p2p_factory":d16.calls(tycamera,"/api/IThingIPCCore;","createCameraP2P"),
        "provider_uses_product_category":d6.calls(provider,"/bean/DeviceBean;","getProductBean") and
            d6.calls(provider,"/bean/ProductBean;","getCategory"),
        "provider_uses_skills":d6.calls(provider,"/bean/DeviceBean;","getSkills"),
        "inner_connect_p2p_policy":d6.calls(connect,"/bean/CameraInfoBean;","getP2pPolicy"),
        "inner_connect_session_tid":d6.calls(connect,"/bean/CameraInfoBean;","getSessionTid"),
        "inner_connect_client_tid":d6.calls(connect,"/p2p/ThingSmartCameraP2PSync;","getClientTid"),
        "inner_connect_ipc_config":d6.calls(connect,"/p2p/ThingSmartCameraP2PSync;","getIPCConfigInfo"),
        "inner_connect_lan_check":d6.calls(connect,"/p2p/ThingSmartCameraP2PSync;","checkLanConnect"),
        "inner_connect_local_state":d6.calls(connect,"/bean/DeviceBean;","isLocalDevice"),
        "mqtt_uses_dynamic_base_config":d5.calls(mqtt,"/bean/MqttConnectConfig;","getUid")
            or d5.calls(mqtt,"/bean/Domain;","getMobileMqttsUrl"),
        "native_thing_p2p_present":"libThingP2PSDK.so" in native_libs,
        "native_thing_camera_present":"libThingCameraSDK.so" in native_libs,
    }
    wifi_sigqry=sum("sigQry" in s for s in d4.strings)
    camera_sigqry=sum("sigQry" in s for s in d6.strings)
    # Literal lookup only; a dynamically generated native string is possible.
    return {
        "audit":"aosu_c9c_sdk_python_coverage_v1",
        "sdk_version":"5.10.12",
        "static_only":True,
        "dex_count":dex_count,
        "sdk_references":{k:bool(v) for k,v in sdk.items()},
        "python_features":{k:bool(v) for k,v in python_flags.items()},
        "sigqry_in_wifi_dex":wifi_sigqry>0,
        "sigqry_literal_in_camera_dex":camera_sigqry>0,
        "binary_protocol_parity_proven":False,
        "camera_identity_proven":False,
        "sdp_answer_proven":False,
        "ready_for_camera_send":False,
        "network_calls":0,
        "camera_commands":0,
        "secret_values_returned":False,
    }

def analyze(apks:Path,repository:Path)->dict:
    if not apks.is_file() or apks.stat().st_size>350_000_000:raise ValueError("archive_unavailable")
    with zipfile.ZipFile(apks) as outer:
        name="base.apk"
        if name not in outer.namelist():raise ValueError("full_apks_required")
        entry=outer.getinfo(name)
        if entry.file_size>240_000_000:raise ValueError("base_too_large")
        base=outer.read(name)
        with zipfile.ZipFile(io.BytesIO(base)) as inner:
            filenames=[x for x in inner.namelist() if x.startswith("classes") and x.endswith(".dex")]
            if any(n not in filenames for n in _DEX):raise ValueError("complete_apk_required")
            for n in _DEX:
                if inner.getinfo(n).file_size>_LIMIT:raise ValueError("dex_too_large")
            indexes={n:DexIndex(inner.read(n)) for n in _DEX}
        lib="split_config.arm64_v8a.apk"
        if lib not in outer.namelist():raise ValueError("arm64_split_missing")
        info=outer.getinfo(lib)
        if info.file_size>160_000_000:raise ValueError("arm64_too_large")
        with zipfile.ZipFile(io.BytesIO(outer.read(lib))) as native:
            libs={x.rsplit("/",1)[-1] for x in native.namelist()
                  if x.startswith("lib/arm64-v8a/") and x.endswith(".so")}
    return summarize(indexes,libs,_python_flags(repository),len(filenames))

def main():
    cli=argparse.ArgumentParser(description="Offline AOSU SDK/Python coverage, no network or secrets")
    cli.add_argument("full_apks",type=Path)
    cli.add_argument("--repository",type=Path,default=Path(__file__).resolve().parents[1])
    args=cli.parse_args()
    try:print(json.dumps(analyze(args.full_apks,args.repository),indent=2,ensure_ascii=False))
    except (OSError,ValueError,struct.error,zipfile.BadZipFile,IndexError,UnicodeError,SyntaxError):
        print('{"audit":"aosu_c9c_sdk_python_coverage_v1","etat":"analyse_indisponible","secret_values_returned":false}')
        raise SystemExit(2)

if __name__=="__main__":main()
