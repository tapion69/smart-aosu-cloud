"""B144 — C9/H1L direct using CURRENT AOSU/OEM inventory and fresh RTC; NO PCAP.

The profile and SDP offered here are experimental (inferred from authenticated B137/B138
observations and Tuya IMM protocol). Do not auto-start. No sensitive values in results.
Legacy PCAP analyzers stay available as separate diagnostic actions.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import struct
import threading
import time
import uuid
from typing import Any

from .c9_h1l_identity_structure_b99 import _match_name
from .c9_lan_signal_b141 import _merge_fresh_rtc_b125
from .c9_kcp_auth_rtc_b133 import _HEADER, _MAX_PW
from .c9_kcp_direct_b141 import _session_kcp_b141, _EXPECTED
from .c9_kcp_auth_identity_b132 import _ID_META
from .h1l_local_probe_b103 import _validate_target
from .h1l_local_status_b108 import _cache_state
from .tuya_rtc_inventory import run_tuya_oem_inventory
from .tuya_channel0_probe import _command

_LOCKS={1:threading.Lock(),2:threading.Lock()}


def _camera_rows(data:dict) -> list[tuple[str,dict]]:
    """Order is AOSU's serial-index ordering, not Tuya's arbitrary response order."""
    rows=[(key,row) for key,row in data.items() if isinstance(row,dict)
          and row.get('model')=='C9C3CA11' and row.get('is_camera') is True]
    return rows


def _snapshot(coordinator:Any,camera_numero:int,ip_station:str)->tuple[str,str,dict,str]:
    """Check one H1L and unambiguous AOSU -> OEM mapping, without any capture."""
    if type(camera_numero) is not int or camera_numero not in (1,2):
        raise ValueError('numero_camera_invalide')
    _validate_target(ip_station)
    data=getattr(coordinator,'data',None)
    client=getattr(coordinator,'client',None)
    cache=getattr(client,'_tuya_oem_inventory_cache',None)
    devices=cache.get('devices') if isinstance(cache,dict) else None
    if not isinstance(data,dict) or not isinstance(devices,dict):
        raise ValueError('inventaire_oem_absent')
    stations=[(key,row) for key,row in data.items() if isinstance(row,dict)
         and row.get('model')=='H1L' and row.get('is_camera') is False]
    if len(stations)!=1:raise ValueError('station_h1l_ambigue')
    station_row_id,station_row=stations[0]
    cams=[(key,row) for key,row in _camera_rows(data)
          if row.get('via_device')==station_row_id]
    if len(cams)!=2:raise ValueError('deux_c9_h1l_introuvables')
    # Serial index from AOSU is only an ordering aid; every identity is also
    # checked by unique AOSU/Tuya name pairing and the via_device relation.
    serial=getattr(client,'_device_sn_index',{})
    if isinstance(serial,dict) and all(k in serial for k,_ in cams):
        cams.sort(key=lambda item: str(serial[item[0]][0]))
    target_row=cams[camera_numero-1][1]
    def unique_oem(row:dict)->str:
        name=row.get('name')
        if not isinstance(name,str) or not name.strip():
            raise ValueError('nom_aosu_c9_absent')
        matches=[did for did,obj in devices.items()
            if isinstance(did,str) and isinstance(obj,dict) and _match_name(obj,name)]
        if len(matches)!=1:raise ValueError('correspondance_oem_c9_ambigue')
        return matches[0]
    sid=unique_oem(station_row)
    camera_ids=[unique_oem(row) for _,row in cams]
    if sid in camera_ids or len(set(camera_ids))!=2:
        raise ValueError('correspondance_oem_c9_ambigue')
    cid=camera_ids[camera_numero-1]
    station=devices[sid];camera=devices[cid]
    local=station.get('localKey')
    if not isinstance(local,str) or len(local.encode('utf-8'))!=16:
        raise ValueError('cle_station_h1l_absente')
    if camera.get('localKey') not in (None,''):
        # Do not silently substitute the station key for a separate camera key.
        raise ValueError('cle_locale_c9_specifique_non_prise_en_charge')
    # In authenticated protocol traces the C9 auth extension was a 20-byte
    # OEM camera reference. Require one and only one distinct current value;
    # otherwise decline rather than guessing / leaking an identifier.
    refs=set()
    for name in _ID_META:
        value=camera.get(name)
        if isinstance(value,str) and len(value.encode('utf-8'))==20 and all(
                32<=x<=126 for x in value.encode('utf-8')):
            refs.add(value)
    if len(refs)!=1:raise ValueError('reference_oem_c9_20_octets_ambigue')
    meta=next(iter(refs))
    if not 1<=len(sid.encode('utf-8'))<=32 or any(b<32 or b>126 for b in sid.encode('utf-8')):
        raise ValueError('identifiant_station_format_invalide')
    return sid,cid,devices,meta


def _auth_new(rtc:dict,sid:str,cid:str,devices:dict,meta:str)->bytes:
    """Derived with the *current* RTC password; no recorded ciphertext or MD5."""
    station=devices.get(sid)
    camera=devices.get(cid)
    if not isinstance(station,dict) or not isinstance(camera,dict):
        raise ValueError('identite_oem_modifiee')
    if camera.get('localKey') not in (None,''):
        raise ValueError('cle_locale_c9_specifique_non_prise_en_charge')
    local=station.get('localKey')
    password=rtc.get('password') if isinstance(rtc,dict) else None
    if not isinstance(local,str) or len(local.encode('utf-8'))!=16:
        raise ValueError('cle_station_h1l_absente')
    if not isinstance(password,str) or not 1<=len(password)<=_MAX_PW:
        raise ValueError('auth_rtc_password_absent')
    md5=hashlib.md5((password+'||'+local).encode('utf-8'),usedforsecurity=False).hexdigest().encode('ascii')
    body=bytearray(288)
    body[:5]=b'admin';body[32:64]=md5
    body[96:128]=sid.encode('utf-8').ljust(32,b'\0')
    body[160:192]=meta.encode('utf-8').ljust(32,b'\0')
    result=_HEADER+bytes(body)
    assert len(result)==296
    return result


def _new_commands(meta:str,profile:str='standard')->tuple[bytes,...]:
    """Allowlisted protocol constants from authenticated C9 #2 B151 audit, no PCAP data.

    This matches one authenticated H1L C9 #2 profile (5/5 commands).
    Camera #1 remains unverified without captured SDP; do not claim universal support.
    """
    if profile!='standard':raise ValueError('profil_non_pris_en_charge')
    ref=meta.encode('utf-8')
    if len(ref)!=20 or any(x<32 or x>126 for x in ref):
        raise ValueError('reference_oem_invalide')
    prefix=ref.ljust(32,b'\0')
    # B152: *authenticated* H1L/C9 #2 PCAP, audited in B151 with the
    # recorded SDP media key and validated camera OEM identity.  These are
    # protocol constants ONLY, not old session credentials or camera IDs.
    # Capture #1 (camera 1) has no matching recorded SDP, so this profile is
    # still an experimental cross-camera hypothesis for its firmware.
    payloads=[b'\x00\x00\x01\x00', prefix+bytes(36)]
    for idx,val in ((68,4),(64,4),(68,4)):
        payload=bytearray(72);payload[:32]=prefix;payload[idx]=val
        payloads.append(bytes(payload))
    commands=tuple(_command(kind,sub,payload) for (kind,sub,size),payload in zip(_EXPECTED,payloads))
    for i,cmd in enumerate(commands):
        kind,sub,size=_EXPECTED[i]
        if len(cmd)!=20+size or struct.unpack_from('<IIIII',cmd)!=(0x12345678,kind,0,sub,size):
            raise ValueError('commandes_video_profil_invalide')
    return commands


def _template(sid:str,uid:str,nonce_sid:str,local_ip:str,port:int)->dict:
    """Known Tuya IMM LAN offer structure; no historical offer or user capture."""
    if not isinstance(uid,str) or not 1<=len(uid)<=256:
        raise ValueError('identite_compte_absente')
    if ipaddress.ip_address(local_ip).version!=4 or not ipaddress.ip_address(local_ip).is_private:
        raise ValueError('adresse_locale_non_privee')
    sdp='\r\n'.join((
        'v=0',f'o=- {int(time.time())} 1 IN IP4 127.0.0.1','s=-','t=0 0',
        'a=group:BUNDLE 0',f'a=msid-semantic: WMS {nonce_sid}',
        'm=application 9 imm 6001','c=IN IP4 0.0.0.0','a=mid:0',
        'a=rtpmap:6001 AES/KCP 330','a=ice-options:trickle',
        'a=ice-ufrag:PENDING','a=ice-pwd:PENDING',
        'a=aes-key:'+('00'*16),'a=sendrecv',''))
    return {
      'header':{'from':uid,'to':sid,'moto_id':'','path':'lan','type':'offer',
                'is_pre':0,'p2p_skill':1635,'security_level':3,
                'sessionid':nonce_sid,'trace_id':f'{uuid.uuid4().hex}_{sid}_{int(time.time()*1000)}'},
      'msg':{'sdp':sdp,'preconnect':True,
             'token':[{'urls':['stun:placeholder.invalid']}],
             'tcp_token':{'username':'PENDING','credential':'PENDING',
                          'sessionId':nonce_sid,'urls':['tcp4:placeholder.invalid:1443']}}}


def _fresh_messages(sid:str,uid:str,rtc:dict,local_ip:str,port:int)->tuple[dict,dict]:
    nonce_sid=f'{sid}{int(time.time())}{secrets.token_hex(4)}'
    t=_template(sid,uid,nonce_sid,local_ip,port)
    offer,ufrag=_merge_fresh_rtc_b125(t,t,rtc)
    # The placeholders are never transmitted. RTC merge must remove them.
    if 'placeholder.invalid' in str(offer) or 'PENDING' in str(offer):
        raise ValueError('rtc_jetons_non_remplaces')
    candidate={
      'header':{'from':uid,'to':sid,'moto_id':'','path':'lan','type':'candidate',
         'is_pre':0,'p2p_skill':1635,'security_level':3,
         'sessionid':nonce_sid,'trace_id':f'{uuid.uuid4().hex}_{sid}_{int(time.time()*1000)}'},
      'msg':{'ice':{'candidate':
               f'candidate:{secrets.token_hex(4)} 1 udp 2122260223 {local_ip} {port} typ host generation 0 ufrag {ufrag}',
               'sdpMid':'0','sdpMLineIndex':0,'sessionId':nonce_sid,'ufrag':ufrag}}}
    return offer,candidate


def _ensure_oem(coordinator,allowed:bool,permission_password:bool)->dict:
    client=getattr(coordinator,'client',None)
    state=_cache_state(client,time.monotonic())
    report={'cache_oem_avant':state,'appels_http_oem':0}
    if state=='cache_utilisable':return report
    if not allowed or not permission_password:
        raise ValueError('cache_oem_ou_autorisation_absent')
    inv=run_tuya_oem_inventory(client,confirmation_envoi_mot_de_passe=True,
        tester_rtc=False,tester_mqtt=False,tester_offre_mqtt=False,
        tester_relais_tcp=False,tester_kcp=False,tester_media=False)
    report['appels_http_oem']=inv.get('appel_reseau',0)
    if inv.get('etat')!='inventaire_termine' or _cache_state(client,time.monotonic())!='cache_utilisable':
        raise ValueError('inventaire_oem_indisponible')
    return report


def audit_preparation_sans_capture_b144(coordinator:Any,*,camera_numero:int,ip_station:str,
        autoriser_reconstitution_oem:bool=False,confirmation_envoi_mot_de_passe:bool=False)->dict:
    report={'diagnostic':'aosu_preparation_sans_pcap_b144','aucun_pcap_necessaire':True,
      'lecture_seule_lan':True,'offres_0x20_envoyees':0,'kcp_envoyes':0,
      'secrets_retournes':False,'identifiants_retournes':False,
      'profil_capture_requis':False,'schema_rtc_live_teste':False,
      'demarrage_camera_confirme':False}
    try:
        report.update(_ensure_oem(coordinator,autoriser_reconstitution_oem,confirmation_envoi_mot_de_passe))
        sid,cid,devices,meta=_snapshot(coordinator,camera_numero,ip_station)
        cmds=_new_commands(meta)
        report.update({'identite_oem_c9_unique':True,'cle_station_valide':True,
          'reference_oem_c9_identifiee':True,'commandes_reconstruites':len(cmds),
          'tailles_commandes':[len(x) for x in cmds],
          'etat':'pret_pour_essai_sans_capture'})
    except ValueError as exc:
        report['etat']=str(exc)[:90]
    except Exception:report['etat']='erreur_interne_masquee'
    return report


def direct_sans_capture_b144(coordinator:Any,*,camera_numero:int,ip_station:str,
        autoriser_reconstitution_oem:bool,confirmation_envoi_mot_de_passe:bool,
        autoriser_direct_c9_b144:bool,preview,stop_event)->dict:
    report={'diagnostic':'aosu_direct_c9_sans_capture_b144','etat':'autorisations_manquantes',
      'profil_capture_requis':False,'capture_rejouee':False,'jetons_capture_rejoues':False,
      'offres_0x20_envoyees':0,'kcp_media_authenticated_passif':0,
      'secrets_retournes':False,'identifiants_retournes':False,'commandes_ptz_envoyees':0}
    if autoriser_direct_c9_b144 is not True or not confirmation_envoi_mot_de_passe:
        return report
    if stop_event is None or preview is None or not getattr(preview,'_opened',False):
        return {**report,'etat':'decodeur_non_prepare'}
    try:
        report.update(_ensure_oem(coordinator,autoriser_reconstitution_oem,confirmation_envoi_mot_de_passe))
        sid,cid,devices,meta=_snapshot(coordinator,camera_numero,ip_station)
        commands=_new_commands(meta)
        report['profil_commandes_video']='b152_c9_2_capture_authentifiee'
    except ValueError as exc:return {**report,'etat':str(exc)[:90]}
    except Exception:return {**report,'etat':'erreur_inventaire_oem'}
    if stop_event.is_set():return {**report,'etat':'session_annulee'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**report,'etat':'direct_c5l_en_cours'}
    lock=_LOCKS[camera_numero]
    if not lock.acquire(blocking=False):return {**report,'etat':'negociation_camera_deja_en_cours'}
    try:
        from .uid_token_probe import _ready_identity,_apk_preflight
        from .tuya_uid_gateway import TuyaAuthSession,do_oem_read,OEMGatewayError
        from .tuya_rtc_inventory import _LOCK as OEM_LOCK
        client=getattr(coordinator,'client',None)
        session=getattr(client,'_tuya_oem_session',None)
        ready=_ready_identity(client)
        if not isinstance(session,TuyaAuthSession) or not session.uid or ready is None:
            return {**report,'etat':'session_oem_absente'}
        _,install_id=ready
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**report,'etat':'apk_oem_invalide'}
        identity,signer=parsed
        if stop_event.is_set():return {**report,'etat':'session_annulee'}
        if not OEM_LOCK.acquire(blocking=False):return {**report,'etat':'autre_action_oem_en_cours'}
        try:
            report['appels_http_rtc']=1
            rtc,status=do_oem_read(identity,signer,'sha256_material',session,
               action='thing.m.rtc.config.get',form_data={'devId':cid},
               ttid=f'sdk_international@{identity.app_id}',device_id=install_id,
               endpoint='https://a1.tuyaeu.com/api.json')
        except (OEMGatewayError,OSError,ValueError):
            return {**report,'etat':'rtc_api_erreur'}
        finally:OEM_LOCK.release()
        if not isinstance(status,dict) or status.get('serveur_accepte') is not True or status.get('rejet_explicite'):
            return {**report,'etat':'rtc_refusee'}
        if not isinstance(rtc,dict):return {**report,'etat':'rtc_structure_incompatible'}
        try:auth=_auth_new(rtc,sid,cid,devices,meta)
        except ValueError as exc:return {**report,'etat':str(exc)[:90]}
        # The RTC response's password, session and relay token remain in this
        # function's memory only; no log or persistent config stores them.
        ip=_validate_target(ip_station)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as route:
            route.connect((ip,6668))  # chooses local interface, no UDP send
            local_ip=route.getsockname()[0]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            udp.bind((local_ip,0))
            try:offer,candidate=_fresh_messages(sid,session.uid,rtc,local_ip,udp.getsockname()[1])
            except ValueError as exc:return {**report,'etat':str(exc)[:90]}
            if stop_event.is_set():return {**report,'etat':'session_annulee'}
            # Never send packets or credentials derived from a prior capture.
            result=_session_kcp_b141(ip,devices[sid]['localKey'].encode('utf-8'),
                offer,candidate,udp,auth,commands,preview,stop_event)
        # Keep result structural; no raw content or user identifiers.
        if isinstance(result,dict):report.update(result)
        report.update({'diagnostic':'aosu_direct_c9_sans_capture_b144',
                       'profil_capture_requis':False,'capture_rejouee':False,
                       'secrets_retournes':False,'identifiants_retournes':False})
        return report
    except ValueError as exc:return {**report,'etat':str(exc)[:90]}
    except (OSError,TimeoutError):return {**report,'etat':'erreur_reseau_ou_timeout'}
    except Exception:return {**report,'etat':'erreur_interne_masquee'}
    finally:lock.release()
