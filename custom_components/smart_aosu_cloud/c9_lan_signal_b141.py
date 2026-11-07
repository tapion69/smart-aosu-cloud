"""B141: one opt-in C9 LAN offer with *fresh* OEM RTC tokens, never replayed.

The server response is kept in memory for one request. If the model does not
match the authenticated personal PCAP, fail closed: do not guess any token.
No media/UDP/STUN/PTZ, no secret or endpoint returned in HA diagnostics.
"""
from __future__ import annotations
import copy
import ipaddress
import re
import secrets
import socket
import threading
import time
from pathlib import Path
from typing import Any

from .c9_lan_signal_b122 import ( _find_offer_from_capture, _host_template_from_capture,
    _fresh_offer, _new_host_candidate, _session_offer_with_candidate,
)
from .c9_capture_selector_b142 import capture_camera_id_b142
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_probe_b103 import _validate_target
from .h1l_local_status_b108 import _cache_state
from .tuya_media_bootstrap import _first_dict
from .tuya_rtc_inventory import run_tuya_oem_inventory


def _safe_json_tree(obj:object,depth:int=0) -> bool:
    """Bound RAM and encode-able content from a fresh server response."""
    if depth>6:return False
    if obj is None or isinstance(obj,bool):return True
    if type(obj) is int:return -(2**62)<=obj<2**62
    if isinstance(obj,str):return len(obj)<=8192
    if isinstance(obj,list):return len(obj)<=32 and all(_safe_json_tree(x,depth+1) for x in obj)
    if isinstance(obj,dict):
        return len(obj)<=64 and all(isinstance(k,str) and len(k)<=80
             and _safe_json_tree(v,depth+1) for k,v in obj.items())
    return False


def _replace_sdp_credentials(sdp:str,*,ufrag:str,pwd:str,aes:str) -> str:
    if not isinstance(sdp,str) or not 60<=len(sdp)<=65536:
        raise ValueError('sdp_structure_invalide')
    if not all(isinstance(x,str) and x and '\n' not in x and '\r' not in x for x in (ufrag,pwd,aes)):
        raise ValueError('rtc_ice_aes_incomplets')
    if len(ufrag)>128 or len(pwd)>256 or not re.fullmatch(r'[0-9a-fA-F]{32}',aes):
        raise ValueError('rtc_ice_aes_incomplets')
    output=[];counts={'ufrag':0,'pwd':0,'aes':0}
    for line in sdp.splitlines():
        for prefix,key,replacement in (('a=ice-ufrag:','ufrag',ufrag),('a=ice-pwd:','pwd',pwd),('a=aes-key:','aes',aes)):
            if line.startswith(prefix):line=prefix+replacement;counts[key]+=1;break
        output.append(line)
    if any(n!=1 for n in counts.values()):raise ValueError('sdp_structure_invalide')
    return '\r\n'.join(output)+'\r\n'


def _merge_fresh_rtc_b125(template:dict, prepared:dict, rtc:dict) -> tuple[dict,str]:
    """Return one private offer and ICE ufrag from freshly retrieved C9 RTC.

    Do NOT emit the old PCAP token/tcp_token or invent credentials. Require
    source and target to use the known media bootstrap schema.
    """
    source=template.get('msg')
    dest=prepared.get('msg')
    if not isinstance(source,dict) or not isinstance(dest,dict):
        raise ValueError('capture_schema_tokens_absent')
    captured_ices=source.get('token')
    captured_tcp=source.get('tcp_token')
    if not isinstance(captured_ices,list) or not isinstance(captured_tcp,dict):
        raise ValueError('capture_schema_tokens_absent')
    p2p=_first_dict(rtc,'p2pConfig')
    if not isinstance(p2p,dict):raise ValueError('rtc_p2p_config_absente')
    session=p2p.get('session')
    ices=p2p.get('ices')
    relay=p2p.get('tcpRelay')
    if not isinstance(session,dict):raise ValueError('rtc_session_absente')
    if not isinstance(ices,list) or not ices or len(ices)>30 or not _safe_json_tree(ices):
        raise ValueError('rtc_token_ice_incompatible')
    if not isinstance(relay,dict) or not _safe_json_tree(relay):
        raise ValueError('rtc_tcp_token_incompatible')
    # These fields are required by the already used C5L RTC media bootstrap.
    if not all(isinstance(relay.get(k),str) and 1<=len(relay[k])<=8192 for k in ('username','credential','sessionId')):
        raise ValueError('rtc_tcp_token_incomplet')
    if not (isinstance(relay.get('urls'),list) and relay['urls']
         or isinstance(relay.get('urlsEx'),list) and relay['urlsEx']):
        raise ValueError('rtc_tcp_token_incomplet')
    ufrag=session.get('iceUfrag');pwd=session.get('icePassword');aes=session.get('aesKey')
    if not all(isinstance(v,str) for v in (ufrag,pwd,aes)):
        raise ValueError('rtc_ice_aes_incomplets')
    # Compare essential type shape, not old values or old credentials.
    if bool(captured_ices) != bool(ices):raise ValueError('rtc_schema_tokens_differente')
    if not all(k in relay and type(relay[k]) is type(captured_tcp[k])
               for k in ('username','credential') if k in captured_tcp):
        raise ValueError('rtc_schema_tokens_differente')
    if not all(k in captured_tcp for k in ('username','credential')):
        raise ValueError('capture_schema_tokens_absent')
    sid=prepared.get('header',{}).get('sessionid')
    if not isinstance(sid,str) or not sid:
        raise ValueError('session_locale_absente')
    # A fresh, station-scoped rendezvous for the TCP relay token; never use a
    # cached PCAP token or a stale server rendezvous identifier.
    fresh_relay=copy.deepcopy(relay)
    fresh_relay['sessionId']=sid
    out=copy.deepcopy(prepared)
    out['msg']['token']=copy.deepcopy(ices)
    out['msg']['tcp_token']=fresh_relay
    current_sdp=out['msg'].get('sdp')
    if not isinstance(current_sdp,str):raise ValueError('sdp_structure_invalide')
    out['msg']['sdp']=_replace_sdp_credentials(current_sdp,ufrag=ufrag,pwd=pwd,aes=aes)
    return out,ufrag


_CAMERA_LOCKS={1:threading.Lock(),2:threading.Lock()}
from .c9_context_b141 import CAPTURES

def essai_negociation_lan_c9_b141(coordinator: Any,*,config_dir:str|Path,
    nom_capture:object,ip_station:object,camera_numero:object,
    confirmation_capture_personnelle:bool,confirmation_camera_candidate:bool,
    autoriser_offre_lan_active:bool,autoriser_configuration_rtc:bool,
    autoriser_reconstitution_oem:bool=False,confirmation_envoi_mot_de_passe:bool=False,
    session_handler=None, session_context_factory=None)->dict:
    report={'diagnostic':'aosu_negociation_live_c9_b141',
        'offres_0x20_envoyees':0,'candidats_0x20_envoyes':0,
        'offres_mqtt_envoyees':0,'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
        'stun_envoye':False,'kcp_demarre':False,'donnees_privees_retournees':False,
        'identifiants_retournes':False,'secrets_retournes':False,
        'session_capture_rejouee':False,'jetons_capture_rejoues':False,
        'jetons_rtc_recents_prepares':False,'configuration_rtc_demandee':False,
        'confirmation_active':autoriser_offre_lan_active is True}
    if not all(x is True for x in (confirmation_capture_personnelle,
                   confirmation_camera_candidate,autoriser_offre_lan_active,
                   autoriser_configuration_rtc)):
        return {**report,'etat':'quatre_autorisations_requises'}
    if type(camera_numero) is not int or camera_numero not in CAPTURES or nom_capture!=CAPTURES[camera_numero]:
        return {**report,'etat':'capture_c9_numero_2_requise'}
    try:ip=_validate_target(ip_station)
    except ValueError:return {**report,'etat':'ip_station_invalide'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**report,'etat':'direct_c5l_en_cours'}
    if controller is not None and callable(getattr(controller,'status',None)):
        try:
            if controller.status().get('direct_actif') is True:
                return {**report,'etat':'direct_c5l_en_cours'}
        except (AttributeError,TypeError):return {**report,'etat':'etat_direct_c5l_inconnu'}
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    capture=(root/str(nom_capture)).resolve()
    if capture.parent!=root or not capture.is_file():return {**report,'etat':'capture_absente'}
    client=getattr(coordinator,'client',None)
    state=_cache_state(client,time.monotonic());report['cache_oem_avant']=state
    if state!='cache_utilisable':
        if autoriser_reconstitution_oem is not True or confirmation_envoi_mot_de_passe is not True:
            return {**report,'etat':'cache_oem_ou_autorisation_absent'}
        try:
            inv=run_tuya_oem_inventory(client,confirmation_envoi_mot_de_passe=True,
              tester_rtc=False,tester_mqtt=False,tester_offre_mqtt=False,
              tester_relais_tcp=False,tester_kcp=False,tester_media=False)
        except Exception:return {**report,'etat':'erreur_reconstitution_oem'}
        report['appels_http_oem']=inv.get('appel_reseau',0)
        report['mot_de_passe_envoye']=inv.get('mot_de_passe_envoye') is True
        if inv.get('etat')!='inventaire_termine' or _cache_state(client,time.monotonic())!='cache_utilisable':
            return {**report,'etat':'inventaire_oem_indisponible'}
    data=getattr(coordinator,'data',None)
    if not isinstance(data,dict):return {**report,'etat':'inventaire_absent'}
    stations=[row for row in data.values() if isinstance(row,dict)
             and row.get('model')=='H1L' and row.get('is_camera') is False]
    if len(stations)!=1:return {**report,'etat':'station_ambigue'}
    station_matches=[(did,obj) for did,obj in client._tuya_oem_inventory_cache['devices'].items()
        if isinstance(obj,dict) and _match_name(obj,stations[0].get('name'))]
    if len(station_matches)!=1:return {**report,'etat':'station_ambigue'}
    station_id,station=station_matches[0]
    local=station.get('localKey')
    if not isinstance(local,str) or len(local.encode('utf-8'))!=16:
        return {**report,'etat':'cle_station_invalide'}
    try:
        camera_id=capture_camera_id_b142(data,client,
            client._tuya_oem_inventory_cache['devices'],capture,ip,station_id,local.encode('utf-8'))
    except (ValueError,TypeError,KeyError,OSError,IndexError):
        return {**report,'etat':'identite_camera_capture_non_concordante'}
    active_lock=_CAMERA_LOCKS[camera_numero]
    if not active_lock.acquire(blocking=False):return {**report,'etat':'essai_deja_en_cours'}
    try:
        try:
            template=_find_offer_from_capture(capture,ip,local.encode('utf-8'))
            host_template=_host_template_from_capture(capture,ip,local.encode('utf-8'))
        except (ValueError,OSError,TypeError,KeyError):
            return {**report,'etat':'capture_non_exploitable'}
        if template is None or host_template is None:
            return {**report,'etat':'capture_offre_ou_candidat_absent'}
        receiver=template.get('header',{}).get('to')
        if receiver!=station_id:return {**report,'etat':'destinataire_station_non_confirme'}
        # Reuse the existing Tuya RTC rate limiter; get exactly one new config.
        from .tuya_rtc_inventory import _LOCK as OEM_LOCK,_LAST_RTC
        if not OEM_LOCK.acquire(blocking=False):
            return {**report,'etat':'autre_action_oem_en_cours'}
        try:
            now=time.monotonic()
            from .uid_token_probe import _ready_identity,_apk_preflight
            from .tuya_uid_gateway import TuyaAuthSession,do_oem_read,OEMGatewayError
            session=getattr(client,'_tuya_oem_session',None)
            if not isinstance(session,TuyaAuthSession) or not session.uid:
                return {**report,'etat':'session_oem_absente'}
            ready=_ready_identity(client)
            if ready is None:return {**report,'etat':'profil_oem_absent'}
            _,install_id=ready
            _,parsed=_apk_preflight(client.apk_path)
            if parsed is None:return {**report,'etat':'apk_oem_invalide'}
            identity,signer=parsed
            report['configuration_rtc_demandee']=True
            report['appels_http_rtc']=1
            try:
                rtc,status=do_oem_read(identity,signer,'sha256_material',session,
                   action='thing.m.rtc.config.get',form_data={'devId':camera_id},
                   ttid=f'sdk_international@{identity.app_id}',device_id=install_id,
                   endpoint='https://a1.tuyaeu.com/api.json')
            except (OEMGatewayError,ValueError,OSError):
                return {**report,'etat':'rtc_api_erreur'}
            if not isinstance(status,dict) or status.get('serveur_accepte') is not True or status.get('rejet_explicite'):
                return {**report,'etat':'rtc_refusee'}
        finally:OEM_LOCK.release()
        if not isinstance(rtc,dict):return {**report,'etat':'rtc_structure_incompatible'}
        # The following body runs immediately after the RTC call; never persist
        # the RTC result, copy its secrets into a log, or reuse it on retry.
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                probe.connect((ip,6668))  # no UDP packet sent
                local_ip=probe.getsockname()[0]
            if not ipaddress.ip_address(local_ip).is_private:
                return {**report,'etat':'ip_locale_non_privee'}
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp_bound:
                udp_bound.bind((local_ip,0))
                port=udp_bound.getsockname()[1]
                fresh_sid=f'{station_id}{int(time.time())}{secrets.token_hex(4)}'
                offer,_unused_sdp=_fresh_offer(template,allowed_ids={station_id,camera_id},
                    session_id=fresh_sid,local_port=port)
                offer['header']['from']=session.uid
                offer,ufrag=_merge_fresh_rtc_b125(template,offer,rtc)
                report['jetons_rtc_recents_prepares']=True
                new_candidate=_new_host_candidate(host_template,offer,ip=local_ip,
                        port=port,ufrag=ufrag)
                # Validate a fresh RTC auth profile before consuming the
                # 15-minute active-LAN cooldown. Fail-closed preflight does
                # not send 0x20, so it must not be counted as an active try.
                # B133: explicit per-session factory may validate ephemeral RTC
                # credentials before any network offer is transmitted. Existing
                # callers use the unmodified B125 behavior.
                if session_context_factory is not None:
                    runner=session_context_factory(rtc,client,station_id,camera_id)
                    if not callable(runner):
                        raise ValueError('auth_rtc_profil_invalide')
                else:
                    runner=session_handler if session_handler is not None else _session_offer_with_candidate
                # Only sessions that actually enter their active handler
                # consume the LAN retry interval.
                result=runner(ip,local.encode('utf-8'),offer,new_candidate,udp_bound)
                report.update(result)
                report['jetons_rtc_recents_prepares']=True
                report['jetons_capture_rejoues']=False
                report['requetes_video_envoyees']=0
                report['commandes_ptz_envoyees']=0
                return {**report,'etat':result.get('etat','negociation_terminee')}
        except ValueError as e:
            allowed={'capture_schema_tokens_absent','rtc_p2p_config_absente','rtc_session_absente',
                     'rtc_token_ice_incompatible','rtc_tcp_token_incompatible',
                     'rtc_tcp_token_incomplet','rtc_ice_aes_incomplets',
                     'rtc_schema_tokens_differente','sdp_structure_invalide',
                     'session_locale_absente','sdp_prerequis_absents',
                     'auth_rtc_password_absent','auth_rtc_profil_invalide',
                     'auth_rtc_cle_camera_absente','auth_schema_identites_non_conforme',
                     'auth_rtc_cle_station_absente','auth_cle_camera_present_politique_refus'}
            return {**report,'etat':str(e) if str(e) in allowed else 'rtc_ou_offre_non_compatible'}
        except (OSError,TimeoutError):return {**report,'etat':'erreur_transport_locale'}
        except Exception:return {**report,'etat':'erreur_interne_sans_details'}
    finally:active_lock.release()
