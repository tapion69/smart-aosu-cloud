"""Private, offline-only media bootstrap validation for the OEM Tuya RTC response.

No network calls, device commands, MQTT, streaming, filesystem writes or secret
export. Compare the Tuya IPC `p2pConfig` structure to the independent native
AES/KCP reference and build an SDP offer *only in volatile memory*.

Reference: https://github.com/roquerodrigo/tuya-ipc-p2p-sdk/
The AOSU OEM API is independently verified only through its read-only result;
compatibility with an AOSU C5L media transport remains to be demonstrated.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
import time


@dataclass(repr=False)
class PrivateMediaBootstrap:
    device_id: str = field(repr=False)
    owner_uid: str = field(repr=False)
    session_id: str = field(repr=False)
    local_key: str = field(repr=False)
    aes_key: bytes = field(repr=False)
    ice_ufrag: str = field(repr=False)
    ice_password: str = field(repr=False)
    relay: dict = field(repr=False)
    sdp_offer: str = field(repr=False)
    ice_servers: list = field(default_factory=list, repr=False)
    log_config: dict = field(default_factory=dict, repr=False)
    trace_id: str = field(default='', repr=False)
    device_password: str = field(default='', repr=False)
    moto_id: str = field(default='', repr=False)  # C9C manual opt-in only
    created_at: float = field(default_factory=time.monotonic, repr=False)

    def is_fresh(self) -> bool:
        """Media credentials can be consumed only immediately after fetching RTC."""
        return time.monotonic() - self.created_at < 90

    def __repr__(self) -> str:
        return '<PrivateMediaBootstrap redacted>'


def _first_dict(node: Any, key: str, depth: int=0) -> dict | None:
    if depth > 7: return None
    if isinstance(node, dict):
        found = node.get(key)
        if isinstance(found, dict): return found
        for val in list(node.values())[:100]:
            got = _first_dict(val, key, depth+1)
            if got is not None: return got
    elif isinstance(node, list):
        for val in node[:100]:
            got = _first_dict(val, key, depth+1)
            if got is not None: return got
    return None


def _is_str(node:dict,key:str)->bool:
    v=node.get(key)
    return isinstance(v,str) and bool(v) and len(v)<=8192


def _nonempty_list_of_str(value:object)->bool:
    return isinstance(value,list) and bool(value) and len(value)<=20 and all(
        isinstance(v,str) and bool(v) and len(v)<=400 for v in value)


def _hex_media_key(value:object)->bytes | None:
    if not isinstance(value,str) or len(value)!=32:
        return None
    try: key=bytes.fromhex(value)
    except ValueError: return None
    return key if len(key)==16 else None


def inspect_rtc_media(raw:Any, device_id:str, local_key:str, uid:str) -> tuple[dict,PrivateMediaBootstrap|None]:
    """Classify fixed known fields and optionally build a media offer in RAM.

    A successful RTC read is *not* a completed P2P media handshake. Never treat
    a matching field shape as evidence of working video or local connectivity.
    """
    report={'analyse':'rtc_media_bootstrap_b16',
            'source_comparaison':'tuya_ipc_p2p_sdk_AOSU_non_valide',
            'appel_reseau_supplementaire':0,'commande_camera':0,'session_video_creee':False,
            'secrets_retournes':False,
            'p2p_config_present':False,'session_p2p_structuree':False,
            'session_id_structure_present':False,'cle_aes_128_valide':False,
            'ice_credentials_complets':False,'serveurs_ice_structure_present':False,
            'relais_tcp_structure_present':False,'relais_tcp_identifiants_presents':False,
            'relais_tcp_adresse_presente':False,
            'cle_locale_presente':bool(isinstance(local_key,str) and local_key),
            'offre_sdp_aes_kcp_preparee':False,
            'signalisation_mqtt_etablie':False}
    p2p=_first_dict(raw,'p2pConfig')
    if p2p is None:
        # AOSU's API may use an alternative schema: report only fixed-path
        # presence flags, never values or arbitrary keys.
        report['session_ailleurs_presente']=_first_dict(raw,'session') is not None
        report['tcp_relay_ailleurs_present']=_first_dict(raw,'tcpRelay') is not None
        report['ice_servers_ailleurs_presents']=_first_dict(raw,'iceServers') is not None
        report['etat']='schema_p2p_config_non_trouve'
        return report,None
    report['p2p_config_present']=True
    session=p2p.get('session')
    if not isinstance(session,dict):
        report['etat']='session_p2p_absente'
        return report,None
    report['session_p2p_structuree']=True
    report['session_id_structure_present']=_is_str(session,'sessionId')
    aes=_hex_media_key(session.get('aesKey'))
    report['cle_aes_128_valide']=aes is not None
    report['ice_credentials_complets']=_is_str(session,'iceUfrag') and _is_str(session,'icePassword')
    ices=p2p.get('ices')
    report['serveurs_ice_structure_present']=isinstance(ices,list) and bool(ices) and len(ices)<=30
    relay=p2p.get('tcpRelay')
    if isinstance(relay,dict):
        report['relais_tcp_structure_present']=True
        report['relais_tcp_identifiants_presents']=all(_is_str(relay,key)
            for key in ('username','credential','sessionId'))
        report['relais_tcp_adresse_presente']=any(
            _nonempty_list_of_str(relay.get(k)) for k in ('urls','urlsEx'))
    ready=(report['session_id_structure_present'] and report['cle_aes_128_valide']
           and report['ice_credentials_complets'] and report['relais_tcp_identifiants_presents']
           and report['relais_tcp_adresse_presente'] and report['cle_locale_presente']
           and isinstance(device_id,str) and bool(device_id)
           and isinstance(uid,str) and bool(uid))
    if not ready:
        report['etat']='configuration_media_partielle_ou_schema_different'
        return report,None
    # Construct the reference AES/KCP SDP locally using *server-provided* keys.
    # Never include the actual offer in diagnostics, logs or a service response.
    session_id=session['sessionId']
    lines=(
        'v=0', f'o=- {int(time.time())} 1 IN IP4 127.0.0.1', 's=-', 't=0 0',
        'a=group:BUNDLE imm0',f'a=msid-semantic: WMS {session_id}',
        'm=application 9 imm 6001','c=IN IP4 0.0.0.0',
        'a=rtcp:9 IN IP4 0.0.0.0',f'a=ice-ufrag:{session["iceUfrag"]}',
        f'a=ice-pwd:{session["icePassword"]}','a=ice-options:trickle',
        f'a=aes-key:{aes.hex()}','a=mid:imm0','a=rtpmap:6001 AES/KCP 330',
        f'a=ssrc:0 cname:{uid}','')
    private=PrivateMediaBootstrap(
        device_id=device_id,owner_uid=uid,session_id=session_id,
        local_key=local_key,aes_key=aes,ice_ufrag=session['iceUfrag'],
        ice_password=session['icePassword'],relay=dict(relay),
        sdp_offer='\r\n'.join(lines),
        ice_servers=list(ices) if isinstance(ices,list) else [],
        log_config=dict(p2p.get('log')) if isinstance(p2p.get('log'),dict) else {},
        trace_id=session.get('traceId','') if isinstance(session.get('traceId'),str) else '',
        device_password=raw.get('password','') if isinstance(raw,dict) and isinstance(raw.get('password',''),str) else '')
    report['offre_sdp_aes_kcp_preparee']=True
    report['etat']='offre_locale_preparee_non_envoyee'
    return report,private
