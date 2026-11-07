"""B120: bounded one-shot LAN signal classification for owned H1L.

This deliberately stops at authenticated 0x20 SDP answer; no UDP/KCP or
video/PTZ commands. All old credentials copied from a verified user PCAP are
replaced by *fresh* session/ICE/media material, and no secrets are returned.

The PCAP must come from the C9 the user explicitly selected. Camera identity
is only a 4-name bijection, not a cryptographically verified serial mapping.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import threading
import time
import uuid

from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_auth_b104 import _pack, _read_response
from .h1l_local_probe_b103 import _validate_target
from .h1l_local_status_b107 import _session_key, _read_status_frame, _SafeStatusProtocolError
from .h1l_local_status_b108 import _cache_state
from .h1l_pcap_offline_b111 import (
    _NAME, _read_pcap, _frames_from_segments, _verify_and_decode,
)
from .tuya_rtc_inventory import run_tuya_oem_inventory
from .c9_ice_stun_b118 import sdp_ice_credentials
from .h1l_pcap_offline_b111 import _field_values_b117

_LOCK = threading.Lock()
_NEXT = {}
_COOLDOWN = 900


def _json_payload(blob: bytes) -> dict | None:
    """Decode authenticated plaintext only; never return it to HA services."""
    if not isinstance(blob, bytes) or not blob or len(blob)>65536:
        return None
    for offset in (0, 15):
        if offset and blob[:3] not in (b'3.3', b'3.4', b'3.5'):
            continue
        raw=blob[offset:].strip(b'\x00\r\n\t ')
        if not raw.startswith(b'{'):
            continue
        try:
            value=json.loads(raw.decode('utf-8'))
            if isinstance(value, dict):return value
        except (UnicodeError, ValueError):
            pass
    return None


def _find_offer_from_capture(path: Path, station_ip: str, key: bytes) -> dict | None:
    """Require authenticated prior offer, not just an untrusted PCAP string."""
    analysis=_read_pcap(path,station_ip)
    for flow in analysis['flows'].values():
        outbound=_frames_from_segments(flow['client'])
        incoming=_frames_from_segments(flow['station'])
        if not outbound or not incoming:continue
        starts=[x for x in outbound if x[0]==3]
        challenges=[x for x in incoming if x[0]==4]
        finishes=[x for x in outbound if x[0]==5]
        if not starts or not challenges or not finishes:continue
        nonce=_verify_and_decode(starts[0],key,False)
        challenge=_verify_and_decode(challenges[0],key,True)
        finish=_verify_and_decode(finishes[0],key,False)
        if (nonce is None or challenge is None or finish is None or
            len(nonce)!=16 or len(challenge)!=48 or len(finish)!=32):continue
        remote_nonce,proof=challenge[:16],challenge[16:]
        if not (hmac.compare_digest(proof,hmac.new(key,nonce,hashlib.sha256).digest())
                and hmac.compare_digest(finish,hmac.new(key,remote_nonce,hashlib.sha256).digest())):continue
        derived=_session_key(key,nonce,remote_nonce)
        for frame in outbound:
            if frame[0]!=0x20:continue
            plaintext=_verify_and_decode(frame,derived,False)
            if plaintext is None:continue
            data=_json_payload(plaintext)
            if (isinstance(data,dict) and isinstance(data.get('header'),dict)
                    and data['header'].get('type')=='offer'
                    and isinstance(data.get('msg'),dict)):
                return data
    return None


def _walk_sdp(node:object, callback, depth:int=0) -> tuple[object,int]:
    """Replace only SDP strings, preserving any other typed envelope fields."""
    if depth>7:raise ValueError('profondeur_invalide')
    count=0
    if isinstance(node,dict):
        result={}
        for name,value in list(node.items())[:80]:
            if name in ('auth','password','token','tcp_token','udp_token'):
                # Captured credentials from old sessions must never be sent.
                continue
            if name=='sdp':
                if not isinstance(value,str):raise ValueError('sdp_absent')
                result[name]=callback(value);count+=1
            elif isinstance(value,(dict,list)):
                result[name],n=_walk_sdp(value,callback,depth+1);count+=n
            elif name in ('sessionId','session_id','sessionid') and isinstance(value,(str,int)):
                result[name]=callback.session_id
            elif name=='port' and isinstance(value,(str,int)):
                result[name]=callback.local_port
            elif name=='topic' and isinstance(value,str):
                if not 1<=len(value)<=1024:raise ValueError('topic_capture_invalide')
                result[name]=value.replace(callback.old_sid,callback.session_id) if callback.old_sid else value
            else:result[name]=value
        return result,count
    if isinstance(node,list):
        output=[]
        for value in node[:40]:
            if isinstance(value,(dict,list)):
                item,n=_walk_sdp(value,callback,depth+1);count+=n;output.append(item)
            else:output.append(value)
        return output,count
    return node,count


class _FreshSDP:
    def __init__(self,session_id:str,local_port:int,old_sid:str):
        self.session_id=session_id
        self.local_port=local_port
        self.old_sid=old_sid
        self.ufrag=secrets.token_urlsafe(12)
        self.pwd=secrets.token_urlsafe(24)
        self.media_key=os.urandom(16).hex()

    def __call__(self,old:str)->str:
        if not 50 <= len(old) <= 65536:raise ValueError('sdp_invalide')
        lines=old.splitlines()
        have={'ufrag':0,'pwd':0,'aes':0,'media':0}
        output=[]
        for line in lines[:300]:
            if line.startswith('a=ice-ufrag:'):
                output.append('a=ice-ufrag:'+self.ufrag);have['ufrag']+=1
            elif line.startswith('a=ice-pwd:'):
                output.append('a=ice-pwd:'+self.pwd);have['pwd']+=1
            elif line.startswith('a=aes-key:'):
                output.append('a=aes-key:'+self.media_key);have['aes']+=1
            elif line.startswith('a=msid-semantic:'):
                output.append('a=msid-semantic: WMS '+self.session_id)
            elif line.startswith('o='):
                output.append('o=- '+str(int(time.time()))+' 1 IN IP4 127.0.0.1')
            else:output.append(line)
            if line.startswith('m=application '):have['media']+=1
        if any(have[field]!=1 for field in ('ufrag','pwd','aes','media')):
            raise ValueError('sdp_prerequis_absents')
        return '\r\n'.join(output)+'\r\n'


def _fresh_offer(original:dict, *, allowed_ids:set[str], session_id:str, local_port:int) -> tuple[dict, _FreshSDP]:
    """Never replay captured ICE/auth. Station target must match owned inventory."""
    if not isinstance(original,dict):raise ValueError('offre_invalide')
    header=original.get('header');msg=original.get('msg')
    if not isinstance(header,dict) or not isinstance(msg,dict):raise ValueError('offre_invalide')
    if header.get('type')!='offer' or header.get('path')!='lan':
        raise ValueError('offre_lan_absente')
    target=header.get('to')
    if not isinstance(target,str) or target not in allowed_ids:
        raise ValueError('cible_capture_non_confirmee')
    if not isinstance(local_port,int) or not 1<=local_port<=65535:
        raise ValueError('port_local_invalide')
    # Deep-copy only authenticated, personally captured offer structure.
    prepared=copy.deepcopy(original)
    prepared['header']['sessionid']=session_id
    prepared['header']['trace_id']=f'{uuid.uuid4().hex}_{int(time.time()*1000)}'
    if 'sessionId' in prepared['header']:
        prepared['header']['sessionId']=session_id
    old_sid=header.get('sessionid')
    sdp_builder=_FreshSDP(session_id,local_port,old_sid if isinstance(old_sid,str) else '')
    prepared['msg'],count=_walk_sdp(prepared['msg'],sdp_builder)
    if count!=1:raise ValueError('sdp_unique_requis')
    # Cloud/relay tokens captured days ago are NEVER replayed. LAN host ICE
    # negotiation uses a fresh local port instead. An unchanged topic can
    # indicate the chosen C9; accept it only from the authenticated capture.
    for key in ('auth','password','token','tcp_token','udp_token'):
        prepared['header'].pop(key,None)
    return prepared,sdp_builder


def _signal_response_summary(payload: bytes, expected_sid: str) -> dict:
    """Safe structural classification: no message content/IDs/SDP disclosed."""
    out={'forme':'vide' if not payload else 'non_json',
         'header_type':'absent','message_type':'absent',
         'sdp_ice_valide':False,'candidate_present':False,
         'session_id_present':False,'session_id_identique':False,
         'session_id_emplacement':'absent'}
    if not payload:return out
    obj=_json_payload(payload)
    if not isinstance(obj,dict):return out
    out['forme']='json'
    header=obj.get('header')
    msg=obj.get('msg')
    if isinstance(header,dict):
        tp=header.get('type')
        out['header_type']=tp if tp in ('offer','answer','candidate','ack','error','stop') else 'autre'
    if isinstance(msg,dict):
        out['message_type']='objet'
        sdp_values=_field_values_b117(msg,'sdp')
        out['sdp_ice_valide']=any(sdp_ice_credentials(sdp) is not None for _,sdp in sdp_values)
        out['candidate_present']=bool(_field_values_b117(msg,'candidate'))
    # Distinguish header/messaging session IDs, as captured answers may put
    # sessionId under msg rather than header. Never return either ID.
    head_ids=[]; nested_ids=[]
    if isinstance(header,dict):
        head_ids=[v for k,v in header.items() if k in ('sessionid','sessionId','session_id') and isinstance(v,str)]
    if isinstance(msg,dict):
        nested_ids=[v for _,v in _field_values_b117(msg,'sessionId') if isinstance(v,str)]
        nested_ids.extend(v for _,v in _field_values_b117(msg,'sessionid') if isinstance(v,str))
        nested_ids.extend(v for _,v in _field_values_b117(msg,'session_id') if isinstance(v,str))
    all_ids=head_ids+nested_ids
    out['session_id_present']=bool(all_ids)
    out['session_id_identique']=any(hmac.compare_digest(v,expected_sid) for v in all_ids if len(v)<512)
    out['session_id_emplacement']=('entete_et_message' if head_ids and nested_ids else
                                   'entete' if head_ids else 'message' if nested_ids else 'absent')
    return out


def _session_offer_once(ip: str, key: bytes, offer:dict) -> dict:
    """Only 1 active offer; inspect replies safely before any ICE transmission."""
    report={'tcp_authentifie':False,'lecture_0x10_authentifiee':False,
            'offres_0x20_envoyees':0,'reponses_0x20_authentifiees':0,
            'reponse_sdp_recue':False,'session_id_reponse_identique':False,
            'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
            'stun_envoye':False,'kcp_demarre':False,
            'reponses_0x20_vides':0,'reponses_0x20_json':0,
            'reponses_0x20_non_json':0,'reponses_0x20_sdp_ice':0,
            'reponses_0x20_candidate':0,'reponses_0x08':0,
            'reponses_0x09':0,'autres_reponses_0x20':0,
            'premiere_reponse_0x20':'aucune',
            'premier_type_0x20':'absent','premier_emplacement_session':'absent',
            'session_id_observe':False,'duree_attente_max_s':12}
    client_nonce=os.urandom(16)
    seq=(int.from_bytes(os.urandom(4),'big') & 0x7fffffff) or 1
    try:
        with socket.create_connection((ip,6668),timeout=3) as sock:
            sock.settimeout(3)
            sock.sendall(_pack(key,seq,3,client_nonce))
            cmd,answer=_read_response(sock,key)
            if cmd!=4 or len(answer)!=48:
                return {**report,'etat':'challenge_invalide'}
            remote_nonce,proof=answer[:16],answer[16:]
            if not hmac.compare_digest(proof,hmac.new(key,client_nonce,hashlib.sha256).digest()):
                return {**report,'etat':'preuve_challenge_invalide'}
            session_key=_session_key(key,client_nonce,remote_nonce)
            sock.sendall(_pack(key,seq+1,5,hmac.new(key,remote_nonce,hashlib.sha256).digest()))
            sock.sendall(_pack(session_key,seq+2,0x10,b'{}'))
            for _ in range(4):
                code,payload=_read_status_frame(sock,session_key,initial_key=key)
                if code==0x10:
                    report['tcp_authentifie']=True
                    report['lecture_0x10_authentifiee']=True
                    break
                if code not in (0x08,0x09):
                    return {**report,'etat':'reponse_lecture_inattendue'}
            if not report['lecture_0x10_authentifiee']:
                return {**report,'etat':'lecture_locale_non_confirmee'}
            plaintext=json.dumps(offer,separators=(',',':'),ensure_ascii=False).encode('utf-8')
            if not 64<=len(plaintext)<=8192:
                return {**report,'etat':'offre_trop_grande_ou_invalide'}
            sock.sendall(_pack(session_key,seq+3,0x20,plaintext))
            report['offres_0x20_envoyees']=1
            deadline=time.monotonic()+12
            received=0
            sdp_seen=False
            expected_sid=offer['header']['sessionid']
            while time.monotonic()<deadline and received<32:
                sock.settimeout(min(2,max(.1,deadline-time.monotonic())))
                try:code,plain=_read_status_frame(sock,session_key,initial_key=key)
                except socket.timeout:continue
                received+=1
                if code==0x08:report['reponses_0x08']+=1;continue
                if code==0x09:report['reponses_0x09']+=1;continue
                if code!=0x20:
                    return {**report,'etat':'reponse_protocole_inattendue'}
                report['reponses_0x20_authentifiees']+=1
                shape=_signal_response_summary(plain,expected_sid)
                group=shape['forme']
                if group=='vide':report['reponses_0x20_vides']+=1
                elif group=='json':report['reponses_0x20_json']+=1
                else:report['reponses_0x20_non_json']+=1
                if report['reponses_0x20_authentifiees']==1:
                    report['premiere_reponse_0x20']=group
                    report['premier_type_0x20']=shape['header_type']
                    report['premier_emplacement_session']=shape['session_id_emplacement']
                if shape['candidate_present']:report['reponses_0x20_candidate']+=1
                if shape['sdp_ice_valide']:
                    report['reponses_0x20_sdp_ice']+=1
                    report['reponse_sdp_recue']=True
                    sdp_seen=True
                if shape['session_id_present']:report['session_id_observe']=True
                if shape['session_id_identique']:
                    report['session_id_reponse_identique']=True
                if group=='json' and not shape['sdp_ice_valide'] and not shape['candidate_present']:
                    report['autres_reponses_0x20']+=1
                if sdp_seen and report['session_id_reponse_identique']:
                    return {**report,'etat':'reponse_sdp_lan_recue'}
            return {**report,'etat':('reponse_sdp_ou_session_incomplete' if sdp_seen
                                  else 'delai_reponse_sdp')}
    except _SafeStatusProtocolError as error:
        safe={'etat':'refus_tuya_0x20' if error.code=='code_reponse_non_zero' else 'reponse_authentification_invalide',
              'cause_protocole':error.code}
        if error.code=='code_reponse_non_zero':
            safe['code_retour_tuya']=error.return_code
        return {**report,**safe}
    except (OSError,TimeoutError):
        return {**report,'etat':'erreur_reseau_ou_timeout'}
    except ValueError:
        return {**report,'etat':'trame_hmac_ou_format_invalide'}
    except Exception:
        return {**report,'etat':'erreur_interne_non_detaillee'}

def essai_negociation_lan_c9_b120(coordinator, *, config_dir:str|Path,
                                   nom_capture:object, ip_station:object,
                                   camera_numero:object,
                                   confirmation_capture_personnelle:bool,
                                   confirmation_camera_candidate:bool,
                                   autoriser_offre_lan_active:bool,
                                   autoriser_reconstitution_oem:bool=False,
                                   confirmation_envoi_mot_de_passe:bool=False)->dict:
    """Explicit, rate-limited user test, fails closed on an ambiguous template."""
    result={'diagnostic':'aosu_essai_negociation_lan_b120',
            'offres_0x20_envoyees':0,'offres_mqtt_envoyees':0,
            'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
            'donnees_privees_retournees':False,'identifiants_retournes':False,
            'session_capture_rejouee':False,'nouvelle_session_preparee':False,
            'confirmation_active':autoriser_offre_lan_active is True}
    if not(all((confirmation_capture_personnelle is True,
                confirmation_camera_candidate is True,
                autoriser_offre_lan_active is True))):
        return {**result,'etat':'trois_confirmations_requises'}
    if camera_numero != 2 or type(camera_numero) is not int:
        return {**result,'etat':'seule_c9_numero_2_avec_capture_verifiee_autorisee'}
    if not isinstance(nom_capture,str) or nom_capture!='c9_camera_2_reference.pcap':
        return {**result,'etat':'capture_c9_2_attendue'}
    try:ip=_validate_target(ip_station)
    except ValueError:return {**result,'etat':'ip_station_invalide'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**result,'etat':'direct_c5l_en_cours'}
    if controller is not None and callable(getattr(controller,'status',None)):
        try:
            if controller.status().get('direct_actif') is True:
                return {**result,'etat':'direct_c5l_en_cours'}
        except (AttributeError,TypeError):
            return {**result,'etat':'etat_direct_c5l_indisponible'}
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    capture=(root/nom_capture).resolve()
    if capture.parent!=root or not capture.is_file():
        return {**result,'etat':'capture_absente'}
    client=getattr(coordinator,'client',None)
    state=_cache_state(client,time.monotonic())
    result['cache_oem_avant']=state
    if state!='cache_utilisable':
        if autoriser_reconstitution_oem is not True or confirmation_envoi_mot_de_passe is not True:
            return {**result,'etat':'cache_oem_ou_autorisation_absent'}
        try:inv=run_tuya_oem_inventory(client,confirmation_envoi_mot_de_passe=True,
            tester_rtc=False,tester_mqtt=False,tester_offre_mqtt=False,
            tester_relais_tcp=False,tester_kcp=False,tester_media=False)
        except Exception:
            return {**result,'etat':'erreur_reconstitution_oem_non_detaillee'}
        result['appels_http_oem']=inv.get('appel_reseau',0)
        result['mot_de_passe_envoye']=inv.get('mot_de_passe_envoye') is True
        if inv.get('etat')!='inventaire_termine' or _cache_state(client,time.monotonic())!='cache_utilisable':
            return {**result,'etat':'inventaire_oem_non_disponible'}
    data=getattr(coordinator,'data',None)
    if not isinstance(data,dict):return {**result,'etat':'inventaire_aosu_absent'}
    camera_candidate,paired=_candidate(data,client,2)
    if camera_candidate is None:return {**result,'etat':'identite_camera_non_selectable'}
    stations=[v for v in data.values() if isinstance(v,dict) and v.get('model')=='H1L' and v.get('is_camera') is False]
    if len(stations)!=1:return {**result,'etat':'h1l_ambigue'}
    station_matches=[(did,d) for did,d in client._tuya_oem_inventory_cache['devices'].items()
        if isinstance(d,dict) and _match_name(d,stations[0].get('name'))]
    if len(station_matches)!=1:return {**result,'etat':'station_candidate_ambigue'}
    station_did,station=station_matches[0]
    local=station.get('localKey')
    if not isinstance(local,str) or len(local.encode('utf-8'))!=16:
        return {**result,'etat':'cle_station_invalide'}
    if not _LOCK.acquire(blocking=False):return {**result,'etat':'essai_deja_en_cours'}
    try:
        tick=time.monotonic()
        if _NEXT.get(ip,0)>tick:
            return {**result,'etat':'temporisation_active','secondes_restantes':int(_NEXT[ip]-tick)+1}
        key=local.encode('utf-8')
        try:template=_find_offer_from_capture(capture,ip,key)
        except Exception:return {**result,'etat':'capture_non_exploitable'}
        if template is None:return {**result,'etat':'offre_0x20_authentifiee_absente'}
        # The payload and destination are never returned. Require known account IDs.
        allowed={camera_candidate,station_did}
        try:
            # Tuya session IDs conventionally start with the actual offer target.
            # The latter must still pass _fresh_offer's owned-device check.
            receiver=template.get('header',{}).get('to')
            if not isinstance(receiver,str) or receiver not in allowed:
                return {**result,'etat':'cible_capture_non_confirmee'}
            fresh_id=f'{receiver}{int(time.time())}{secrets.token_hex(4)}'
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp_probe:
                udp_probe.connect((ip,6668))  # UDP connect sends NO datagrams.
                local_ip=udp_probe.getsockname()[0]
            if not ipaddress.ip_address(local_ip).is_private:
                return {**result,'etat':'adresse_locale_non_privee'}
            udp_bound=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            try:
                udp_bound.bind((local_ip,0))
                port=udp_bound.getsockname()[1]
                offer,private_sdp=_fresh_offer(template,allowed_ids=allowed,session_id=fresh_id,local_port=port)
                account=getattr(client,'_tuya_oem_session',None)
                uid=getattr(account,'uid',None)
                if not isinstance(uid,str) or not uid:
                    return {**result,'etat':'compte_uid_absent'}
                offer['header']['from']=uid
                result['nouvelle_session_preparee']=True
                # One active offer per 15 minutes; keep UDP local port reserved.
                _NEXT[ip]=tick+_COOLDOWN
                diagnostic=_session_offer_once(ip,key,offer)
                result.update(diagnostic)
                result['requetes_video_envoyees']=0
                result['commandes_ptz_envoyees']=0
                return result
            finally:udp_bound.close()
        except ValueError as error:
            permitted={'offre_invalide','offre_lan_absente','cible_capture_non_confirmee',
                       'port_local_invalide','sdp_invalide','sdp_prerequis_absents',
                       'sdp_unique_requis','topic_capture_invalide','profondeur_invalide','sdp_absent'}
            code=str(error)
            return {**result,'etat':code if code in permitted else 'erreur_protocole_ou_format'}
        except (OSError,TimeoutError):
            return {**result,'etat':'erreur_reseau_ou_protocole_local'}
        except Exception:
            return {**result,'etat':'erreur_interne_non_detaillee'}
    finally:_LOCK.release()
