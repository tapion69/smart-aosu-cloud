"""B131: read-only, redacted investigation of C9 296-byte KCP auth.

This module NEVER returns plaintext, digests, device ids, keys, passwords or
raw packets. It does not send TCP, STUN, KCP, SDP, PTZ or video commands.
The pre-existing B130 *active* authentication gate is deliberately unchanged.
"""
from __future__ import annotations
import hashlib
import hmac
from pathlib import Path
import struct
from typing import Any

from .c9_kcp_auth_profile_b130 import audit_auth_kcp_c9_b130
from .c9_kcp_bootstrap_b128 import _client_first_six_kcp
from .c9_video_preflight_b123 import _authenticated_transcript
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_probe_b103 import _validate_target
from .tuya_channel0_probe import _record_decrypt,_parse_answer_key,_CONTROL_MAGIC

MAX_CAPTURE=32*1024*1024
OTHER_CAPTURE='c9_camera_1_reference.pcap'


def _record_first_auth(path:Path,ip:str,station_key:bytes,station_id:str)->bytes|None:
    if not path.is_file() or path.stat().st_size>MAX_CAPTURE:return None
    offer,_,_=_authenticated_transcript(path,ip,station_key)
    if not isinstance(offer,dict) or offer.get('header',{}).get('to')!=station_id:return None
    msg=offer.get('msg')
    if not isinstance(msg,dict):return None
    key=_parse_answer_key(msg.get('sdp'))
    if key is None:return None
    packets=_client_first_six_kcp(path,ip)
    if len(packets)!=6:return None
    packet=packets[0]
    if len(packet)!=364 or not hmac.compare_digest(
        hmac.new(key,packet[:-20],hashlib.sha1).digest(),packet[-20:]):return None
    plain=_record_decrypt(key,packet[24:-20])
    if len(plain)!=296 or plain[:8]!=struct.pack('<II',_CONTROL_MAGIC,1):return None
    return plain


def _block_class(raw:bytes)->str:
    if raw==bytes(len(raw)):return 'zero'
    used=raw.rstrip(b'\0')
    if used and all(c in b'0123456789abcdefABCDEF' for c in used) and len(used)>=16:return 'ascii_hex'
    if used and all(32<=c<=126 for c in used):return 'ascii_imprimable'
    return 'binaire_ou_mixte'


def _secret_candidates(devices:dict, account_password:str|None)->list[tuple[str,bytes]]:
    # Generate digests only in RAM. No secret, id or credential persisted.
    found=[]
    if not isinstance(devices,dict):return found
    for did,dev in list(devices.items())[:64]:
        if not isinstance(dev,dict):continue
        local=dev.get('localKey')
        if not isinstance(local,str) or len(local.encode('utf-8'))!=16:continue
        for password in (dev.get('password'),account_password):
            if not isinstance(password,str) or not 1<=len(password)<=2048:continue
            digest=hashlib.md5((password+'||'+local).encode('utf-8'),usedforsecurity=False).hexdigest().encode()
            found.append((str(did),digest))
    return found


def _describe_auth_plain(plain:bytes,devices:dict,station_id:str,
                         account_password:str|None,other:bytes|None=None)->dict:
    """Only structural statistics; no values or reversible fingerprints."""
    out={'auth_structure_confirmee':False,'auth_longueur_clair':len(plain),
         'auth_blobs_supplementaires':[],
         'auth_md5_verification_effectuee':False,
         'auth_md5_comparaisons_effectuees':0,
         'auth_md5_correspondance':'non_testee',
         'capture_autre_c9_analysee':False,
         'md5_capture_identique_autre_c9':None,
         'blocs_identiques_autre_c9':[],
         'auth_schema_reconstructible':False,
         'donnees_privees_retournees':False,'secrets_retournes':False,
         'identifiants_retournes':False}
    if len(plain)!=296 or plain[:8]!=struct.pack('<II',_CONTROL_MAGIC,1):return out
    body=plain[8:]
    if body[:5]!=b'admin' or body[5:32]!=bytes(27):return out
    digest=body[32:64]
    if not (len(digest)==32 and all(c in b'0123456789abcdefABCDEF' for c in digest)):
        return out
    out['auth_structure_confirmee']=True
    for index in range(2,9):
        block=body[index*32:(index+1)*32]
        if not any(block):continue
        # Deliberately avoid byte snippets, hex, prefixes, digest, fingerprints.
        out['auth_blobs_supplementaires'].append({
           'bloc':index,'classe':_block_class(block),
           'octets_non_nuls':sum(bool(c) for c in block),
           'remplissage_zero_final':len(block.rstrip(b'\0'))<len(block),
           'taille_utile_max':len(block.rstrip(b'\0'))})
    candidates=_secret_candidates(devices,account_password)
    out['auth_md5_comparaisons_effectuees']=len(candidates)
    out['auth_md5_verification_effectuee']=bool(candidates)
    if candidates:
        match_roles=set('station' if did==station_id else 'autre_equipement' for did,value in candidates
                        if hmac.compare_digest(value.lower(),digest.lower()))
        out['auth_md5_correspondance']=('aucune' if not match_roles else
              'plusieurs_roles' if len(match_roles)>1 else next(iter(match_roles)))
    if isinstance(other,bytes) and len(other)==296 and other[:8]==plain[:8]:
        out['capture_autre_c9_analysee']=True
        body2=other[8:]
        out['md5_capture_identique_autre_c9']=hmac.compare_digest(digest,body2[32:64])
        out['blocs_identiques_autre_c9']=[{'bloc':i,'identique':
              hmac.compare_digest(body[i*32:(i+1)*32],body2[i*32:(i+1)*32])}
              for i in range(2,9) if any(body[i*32:(i+1)*32]) or any(body2[i*32:(i+1)*32])]
    # Deliberately false: this is an investigation, NEVER an auth constructor.
    return out


def audit_details_auth_kcp_c9_b131(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
        confirmation_capture_personnelle,confirmation_camera_candidate,
        autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    base={'diagnostic':'aosu_audit_details_auth_kcp_c9_b131','analyse_hors_ligne':True,
          'offres_0x20_envoyees':0,'stun_envoyes':0,'kcp_auth_push_envoyes':0,
          'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
          'aucun_secret_retourne':True,'auth_schema_reconstructible':False}
    if confirmation_capture_personnelle is not True or confirmation_camera_candidate is not True:
        return {**base,'etat':'confirmation_capture_requise'}
    if camera_numero!=2 or type(camera_numero) is not int or nom_capture!='c9_camera_2_reference.pcap':
        return {**base,'etat':'capture_c9_numero_2_requise'}
    pre=audit_auth_kcp_c9_b130(coordinator,config_dir=config_dir,
      nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
      confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
      autoriser_reconstitution_oem=autoriser_reconstitution_oem,
      confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for field in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if field in pre:base[field]=pre[field]
    if pre.get('auth_enregistrements_verifies')!=1:
        return {**base,'etat':pre.get('etat','auth_capture_non_confirmee')}
    try:
        ip=_validate_target(ip_station)
        root=(Path(config_dir)/'smart_aosu_traces').resolve()
        path=(root/nom_capture).resolve()
        if path.parent!=root:return {**base,'etat':'capture_chemin_invalide'}
        client=getattr(coordinator,'client',None)
        cache=getattr(client,'_tuya_oem_inventory_cache',{})
        devices=cache.get('devices',{}) if isinstance(cache,dict) else {}
        if not isinstance(devices,dict):return {**base,'etat':'inventaire_oem_absent'}
        data=getattr(coordinator,'data',None)
        if not isinstance(data,dict):return {**base,'etat':'inventaire_ha_absent'}
        stations=[v for v in data.values() if isinstance(v,dict) and
                  v.get('model')=='H1L' and v.get('is_camera') is False]
        if len(stations)!=1:return {**base,'etat':'station_ambigue'}
        matches=[(did,dev) for did,dev in list(devices.items())[:64]
                 if isinstance(dev,dict) and _match_name(dev,stations[0].get('name'))]
        if len(matches)!=1:return {**base,'etat':'station_ambigue'}
        station_id,station=matches[0]
        key=station.get('localKey')
        if not isinstance(key,str) or len(key.encode('utf-8'))!=16:
            return {**base,'etat':'cle_station_absente'}
        plain=_record_first_auth(path,ip,key.encode(),station_id)
        if plain is None:return {**base,'etat':'auth_capture_invalide'}
        otherpath=(root/OTHER_CAPTURE).resolve()
        other=None
        if otherpath.parent==root and otherpath.is_file():
            try:other=_record_first_auth(otherpath,ip,key.encode(),station_id)
            except (OSError,ValueError,TypeError,KeyError,IndexError,UnicodeError,struct.error):pass
        account_password=getattr(client,'password',None)
        detail=_describe_auth_plain(plain,devices,station_id,account_password,other)
        return {**base,**detail,'etat':'details_auth_c9_anonymises'}
    except (OSError,ValueError,TypeError,KeyError,IndexError,UnicodeError,struct.error):
        return {**base,'etat':'details_auth_c9_inexploitables'}
    except Exception:return {**base,'etat':'erreur_interne_masquee'}
