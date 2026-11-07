"""B104: opt-in Tuya 3.4 LAN handshake with the *station candidate* key.

Test ONLY the identity challenge, never read DPs, open media, or move a camera.
The OEM cached station key stays in RAM and is never returned, logged or saved.
The station match is initially name-based (not a serial proof); success only
proves that the peer at the supplied LAN IP knows the candidate OEM local key.
"""
from __future__ import annotations

import hmac
import hashlib
import os
import socket
import struct
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_probe_b103 import _validate_target

_PREFIX=b'\x00\x00\x55\xaa'
_SUFFIX=b'\x00\x00\xaa\x55'
_LOCK=threading.Lock()
_LAST:dict[str,float]={}
_COOLDOWN=300


def _aes_encrypt(key:bytes, plain:bytes)->bytes:
    padding=PKCS7(128).padder()
    data=padding.update(plain)+padding.finalize()
    context=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    return context.update(data)+context.finalize()


def _aes_decrypt(key:bytes, data:bytes)->bytes:
    context=Cipher(algorithms.AES(key),modes.ECB()).decryptor()
    plain=context.update(data)+context.finalize()
    unpad=PKCS7(128).unpadder()
    return unpad.update(plain)+unpad.finalize()


def _pack(key:bytes, seq:int, command:int, plain:bytes)->bytes:
    payload=_aes_encrypt(key,plain)
    head=_PREFIX+struct.pack('>III',seq,command,len(payload)+36)
    frame=head+payload
    return frame+hmac.new(key,frame,hashlib.sha256).digest()+_SUFFIX


def _exact(sock:Any, size:int)->bytes:
    parts=bytearray()
    while len(parts)<size:
        chunk=sock.recv(size-len(parts))
        if not chunk:raise ValueError('socket_ferme')
        parts.extend(chunk)
    return bytes(parts)


def _read_response(sock:Any,key:bytes)->tuple[int,bytes]:
    head=_exact(sock,16)
    if head[:4]!=_PREFIX:raise ValueError('reponse_invalide')
    seq,command,length=struct.unpack('>III',head[4:16])
    if not 40<=length<=512:raise ValueError('taille_invalide')
    body=_exact(sock,length)
    if body[-4:]!=_SUFFIX:raise ValueError('signature_invalide')
    digest=hmac.new(key,head+body[:-36],hashlib.sha256).digest()
    if not hmac.compare_digest(digest,body[-36:-4]):raise ValueError('hmac_invalide')
    # Device -> client responses carry the 4-byte clear retcode. It is
    # included in the authenticated HMAC, not in the AES ciphertext.
    if len(body)<4+16+36 or (len(body)-4-36)%16:raise ValueError('structure_invalide')
    if int.from_bytes(body[:4],'big')!=0:raise ValueError('retcode_non_zero')
    return command,_aes_decrypt(key,body[4:-36])


def _local_handshake(ip:str,key:bytes)->dict:
    """Send only 0x03 and 0x05; never send Tuya 0x07/0x10 or media."""
    report={'tcp_connecte':False,'reponse_authentifiee':False,
            'confirmation_session_envoyee':False,'trames_tuya_envoyees':0,
            'commandes_camera_envoyees':0,'media_demarre':False,
            'secret_retourne':False,'etat_auth':'non_lance'}
    nonce=os.urandom(16)
    seq=int.from_bytes(os.urandom(4),'big')&0x7fffffff
    try:
        with socket.create_connection((ip,6668),timeout=2.5) as sock:
            report['tcp_connecte']=True
            sock.settimeout(2.5)
            sock.sendall(_pack(key,seq,3,nonce))
            report['trames_tuya_envoyees']=1
            command,payload=_read_response(sock,key)
            if command!=4 or len(payload)!=48:
                report['etat_auth']='reponse_challenge_inattendue'
                return report
            device_nonce,proof=payload[:16],payload[16:]
            expected=hmac.new(key,nonce,hashlib.sha256).digest()
            if not hmac.compare_digest(proof,expected):
                report['etat_auth']='preuve_challenge_invalide'
                return report
            report['reponse_authentifiee']=True
            finish=hmac.new(key,device_nonce,hashlib.sha256).digest()
            sock.sendall(_pack(key,(seq+1)&0x7fffffff,5,finish))
            report['trames_tuya_envoyees']=2
            report['confirmation_session_envoyee']=True
            report['etat_auth']='challenge_et_fin_tuya34_envoyes'
    except (OSError,TimeoutError):
        report['etat_auth']='erreur_connexion_ou_delai'
    except Exception:
        # No exception text is returned, since even framework exceptions can
        # inadvertently carry confidential socket or frame contents.
        report['etat_auth']='reponse_protocole_invalide'
    return report


def audit_local_station_auth_b104(coordinator:Any, *, ip_station:object,
                                  confirm_identity:bool,confirm_handshake:bool,
                                  now:float|None=None)->dict:
    base={'diagnostic':'aosu_h1l_auth_locale_b104','appels_http':0,
          'mot_de_passe_envoye':False,'rtc_demande':False,
          'offre_mqtt_envoyee':False,'session_video_creee':False,
          'commandes_camera_envoyees':0,'commandes_ptz_envoyees':0,
          'cle_locale_retournee':False,'identifiants_retournes':False,
          'correspondance_serie_aosu_tuya_prouvee':False,
          'consentement_candidat':confirm_identity is True,
          'consentement_auth_locale':confirm_handshake is True}
    try:ip=_validate_target(ip_station)
    except ValueError:return {**base,'etat':'adresse_lan_invalide'}
    if confirm_identity is not True or confirm_handshake is not True:
        return {**base,'etat':'confirmation_double_requise'}
    controller=getattr(coordinator,'live_controller',None)
    if getattr(controller,'running',False):
        return {**base,'etat':'direct_c5l_en_cours'}
    if controller is not None and callable(getattr(controller,'status',None)):
        try:
            if controller.status().get('direct_actif') is True:
                return {**base,'etat':'direct_c5l_en_cours'}
        except (AttributeError, TypeError):
            return {**base,'etat':'etat_direct_c5l_indisponible'}
    client=getattr(coordinator,'client',None)
    cache=getattr(client,'_tuya_oem_inventory_cache',None)
    session=getattr(client,'_tuya_oem_session',None)
    tick=time.monotonic() if now is None else now
    if (not isinstance(cache,dict) or not isinstance(cache.get('devices'),dict)
            or session is None or not getattr(session,'uid',None)
            or cache.get('session_uid')!=session.uid
            or type(cache.get('created')) not in (int,float)
            or not 0<=tick-cache['created']<600
            or type(getattr(session,'acquired_at',None)) not in (int,float)
            or not 0<=tick-session.acquired_at<1200):
        return {**base,'etat':'cache_oem_ou_session_absente_expiree'}
    data=getattr(coordinator,'data',None)
    if not isinstance(data,dict):return {**base,'etat':'inventaire_aosu_absent'}
    # Cross-check the full four-name bijection and the two C9 -> H1L links.
    c9_id,matched=_candidate(data,client,1)
    if c9_id is None:
        return {**base,'etat':'identification_noms_non_coherente'}
    stations=[row for row in data.values() if isinstance(row,dict)
              and row.get('model')=='H1L' and row.get('is_camera') is False]
    if len(stations)!=1 or not isinstance(stations[0].get('name'),str):
        return {**base,'etat':'station_aosu_non_unique'}
    oem=cache['devices']
    matched_ids=[did for did,obj in oem.items() if _match_name(obj,stations[0]['name'])]
    if len(matched_ids)!=1 or matched_ids[0]==c9_id:
        return {**base,'etat':'station_tuya_nom_ambigu'}
    item=oem[matched_ids[0]]
    key_val=item.get('localKey')
    if not isinstance(key_val,str) or len(key_val.encode('utf-8'))!=16:
        return {**base,'etat':'cle_locale_station_absente_ou_format_invalide',
                'cle_locale_station_presente':bool(key_val)}
    remaining=_LAST.get(ip,0)-tick
    if remaining>0:
        return {**base,'etat':'limitation_locale',
                'secondes_restantes':int(remaining+0.999)}
    if not _LOCK.acquire(blocking=False):
        return {**base,'etat':'test_local_deja_en_cours'}
    try:
        remaining=_LAST.get(ip,0)-tick
        if remaining>0:
            return {**base,'etat':'limitation_locale',
                    'secondes_restantes':int(remaining+0.999)}
        _LAST[ip]=tick+_COOLDOWN
        network=_local_handshake(ip,key_val.encode('utf-8'))
    finally:
        _LOCK.release()
    return {**base,**network,
            'ip_station':ip,'port_tcp':6668,
            'station_candidate_nom_unique':True,
            'station_candidate_cle_locale_presente':True,
            'correspondance_cryptographique_avec_cle_station_candidate':
                network['reponse_authentifiee'],
            'etat':'auth_challenge_verifiee' if network['reponse_authentifiee']
                   else 'auth_challenge_non_verifiee',
            'note':'Une validation cryptographique prouve que le pair LAN connait la cle '
                   'du candidat Tuya station. Les noms ne prouvent pas le SN AOSU.'}
