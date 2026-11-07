"""B132: offline matches of captured C9 KCP auth extensions to owned identities.

Only safe *categories* of exact matches are returned: never the matched IDs,
block content, MD5 digests, credentials, session keys, or fingerprints.
There are no extra network calls beyond the optional existing OEM B131 refresh.
No active UDP/TCP/MQTT/SDP/STUN/KCP/video/PTZ is transmitted.
"""
from __future__ import annotations
import hmac
from pathlib import Path
from typing import Any

from .c9_kcp_auth_audit_b131 import audit_details_auth_kcp_c9_b131,_record_first_auth
from .c9_rtc_candidate_b101 import _candidate
from .c9_video_preflight_b123 import _authenticated_transcript
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_probe_b103 import _validate_target

_MAX_ID=128
_ID_META=('devId','deviceId','device_id','id','uuid','cpDeviceId',
         'cpUuid','gwId','parentId','subDeviceId','nodeId','p2pId',
         'sn','serial','serialNumber','uid')


def _safely_comparable(value:object)->str|None:
    if not isinstance(value,str) or not 1<=len(value)<=_MAX_ID:return None
    if any(ord(c)<32 for c in value):return None
    return value


def _append(index:list[tuple[str,str]], seen:set[tuple[str,str]], role:str, value:object)->None:
    value=_safely_comparable(value)
    if value is not None and (role,value) not in seen:
        index.append((role,value));seen.add((role,value))


def _references(*,offer:dict,uid:object,station_id:str,camera_id:object,
                devices:dict)->list[tuple[str,str]]:
    """Return bounded role/value pairs *only in RAM*, for exact comparison."""
    index=[];seen=set()
    head=offer.get('header',{})
    msg=offer.get('msg',{})
    if not isinstance(head,dict):head={}
    if not isinstance(msg,dict):msg={}
    for role,value in [
        ('uid_compte_actuel',uid),('uid_compte_capture',head.get('from')),
        ('id_station_actuel',station_id),('id_station_capture',head.get('to')),
        ('id_camera_actuel',camera_id),('session_capture',head.get('sessionid')),
        ('session_msg_capture',msg.get('sessionId'))]:
        _append(index,seen,role,value)
    for did,dev in list(devices.items())[:64]:
        if not isinstance(dev,dict):continue
        role=('ref_oem_station' if did==station_id else
              'ref_oem_camera' if did==camera_id else 'ref_oem_autre_equipement')
        _append(index,seen,role,did)
        for key in _ID_META:
            value=dev.get(key)
            if isinstance(value,(list,dict)):continue
            metarole=('meta_oem_station' if did==station_id else
                      'meta_oem_camera' if did==camera_id else 'meta_oem_autre_equipement')
            _append(index,seen,metarole,value)
    return index[:1000]


def _classify_extras(plain:bytes,references:list[tuple[str,str]])->dict:
    """Does not return identifiable material, only allowed stable role names."""
    out={'blocs_identifiants':[], 'sources_comparees':len(references),
         'comparaison_identite_effectuee':False,
         'blocs_reconnus_comme_identifiants':0,
         'auth_schema_reconstructible':False,
         'donnees_privees_retournees':False,'identifiants_retournes':False,
         'secrets_retournes':False}
    if not isinstance(plain,bytes) or len(plain)!=296 or plain[:8]!=bytes.fromhex('7856341201000000'):
        return out
    body=plain[8:]
    for block in (3,5):
        raw=body[block*32:(block+1)*32]
        used=raw.rstrip(b'\0')
        if not used or len(used)>32 or not all(32<=b<=126 for b in used):
            out['blocs_identifiants'].append({'bloc':block,'format':'non_ascii',
                       'correspondances':[], 'correspondance_exacte':False})
            continue
        roles=set()
        for role,value in references:
            encoded=value.encode('utf-8')
            if len(encoded)==len(used) and hmac.compare_digest(used,encoded):
                roles.add(role)
        found=sorted(roles)
        out['blocs_identifiants'].append({'bloc':block,'format':'ascii_imprimable',
                  'correspondances':found,'correspondance_exacte':bool(found)})
        if found:out['blocs_reconnus_comme_identifiants']+=1
    out['comparaison_identite_effectuee']=True
    return out


def audit_correspondances_auth_c9_b132(coordinator:Any,*,config_dir,nom_capture,
    ip_station,camera_numero,confirmation_capture_personnelle,
    confirmation_camera_candidate,autoriser_reconstitution_oem=False,
    confirmation_envoi_mot_de_passe=False)->dict:
    report={'diagnostic':'aosu_audit_correspondances_auth_c9_b132',
       'analyse_hors_ligne':True,'offres_0x20_envoyees':0,'stun_envoyes':0,
       'kcp_envoyes':0,'kcp_auth_push_envoyes':0,'requetes_video_envoyees':0,
       'commandes_ptz_envoyees':0,'secrets_retournes':False,
       'identifiants_retournes':False,'donnees_privees_retournees':False,
       'auth_schema_reconstructible':False}
    if confirmation_capture_personnelle is not True or confirmation_camera_candidate is not True:
        return {**report,'etat':'confirmation_capture_requise'}
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_details_auth_kcp_c9_b131(coordinator,config_dir=config_dir,
       nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
       confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
       autoriser_reconstitution_oem=autoriser_reconstitution_oem,
       confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for field in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye',
        'auth_longueur_clair','auth_md5_verification_effectuee',
        'auth_md5_correspondance','capture_autre_c9_analysee',
        'md5_capture_identique_autre_c9','blocs_identiques_autre_c9'):
        if field in pre:report[field]=pre[field]
    if pre.get('etat')!='details_auth_c9_anonymises' or pre.get('auth_structure_confirmee') is not True:
        return {**report,'etat':pre.get('etat','auth_b131_non_confirmee')}
    try:
        ip=_validate_target(ip_station)
        root=(Path(config_dir)/'smart_aosu_traces').resolve()
        path=(root/nom_capture).resolve()
        if path.parent!=root:return {**report,'etat':'chemin_capture_invalide'}
        client=getattr(coordinator,'client',None)
        cache=getattr(client,'_tuya_oem_inventory_cache',{})
        devices=cache.get('devices',{}) if isinstance(cache,dict) else {}
        data=getattr(coordinator,'data',None)
        if not isinstance(devices,dict) or not isinstance(data,dict):
            return {**report,'etat':'inventaire_absent'}
        stations=[v for v in data.values() if isinstance(v,dict) and
             v.get('model')=='H1L' and v.get('is_camera') is False]
        if len(stations)!=1:return {**report,'etat':'station_ambigue'}
        matches=[(did,dev) for did,dev in list(devices.items())[:64] if
             isinstance(dev,dict) and _match_name(dev,stations[0].get('name'))]
        if len(matches)!=1:return {**report,'etat':'station_ambigue'}
        station_id,dev=matches[0]
        key=dev.get('localKey')
        if not isinstance(key,str) or len(key.encode('utf-8'))!=16:
            return {**report,'etat':'cle_locale_station_invalide'}
        plain=_record_first_auth(path,ip,key.encode('utf-8'),station_id)
        if plain is None:return {**report,'etat':'auth_capture_absente'}
        offer,_,_=_authenticated_transcript(path,ip,key.encode('utf-8'))
        if not isinstance(offer,dict):return {**report,'etat':'offre_capture_absente'}
        camera_id,_=_candidate(data,client,2)
        uid=getattr(getattr(client,'_tuya_oem_session',None),'uid',None)
        refs=_references(offer=offer,uid=uid,station_id=station_id,
                         camera_id=camera_id,devices=devices)
        checks=_classify_extras(plain,refs)
        return {**report,**checks,'camera_identifiee_dans_inventaire':camera_id is not None,
                'uid_compte_disponible':isinstance(uid,str) and bool(uid),
                'etat':'correspondances_identifiants_anonymisees'}
    except (OSError,TypeError,ValueError,KeyError,IndexError,UnicodeError):
        return {**report,'etat':'analyse_identites_inexploitable'}
    except Exception:
        return {**report,'etat':'erreur_interne_masquee'}
