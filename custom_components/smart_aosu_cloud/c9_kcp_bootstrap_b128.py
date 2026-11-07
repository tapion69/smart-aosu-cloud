"""B128 — inspect the *six initial phone-originated KCP pushes* in an operator-supplied C9 capture.

No UDP/TCP/offer/media commands are issued. OEM inventory may be refreshed only
with explicit consent. Private cryptographic payloads are used solely in RAM,
never written or returned. This prevents guessing that the C5L's control
commands are interchangeable with the H1L/C9 commands.
"""
from __future__ import annotations
import hmac
import hashlib
import ipaddress
from pathlib import Path
import socket
import struct
import time
from typing import Any
from .c9_video_preflight_b123 import audit_preparation_video_c9_b123, _authenticated_transcript
from .h1l_local_probe_b103 import _validate_target
from .c9_h1l_identity_structure_b99 import _match_name
from .tuya_channel0_probe import _parse_answer_key, _record_decrypt, _CONTROL_MAGIC

_MAX_CAPTURE=32*1024*1024

def _client_first_six_kcp(path:Path,station_ip:str)->list[bytes]:
    """Return first 6 client control PUSH packet bytes; nothing persisted."""
    if path.stat().st_size>_MAX_CAPTURE:raise ValueError('capture_trop_grande')
    blob=path.read_bytes()
    endian,nano={b'\xd4\xc3\xb2\xa1':('<',False),b'\xa1\xb2\xc3\xd4':('>',False),
      b'\x4d\x3c\xb2\xa1':('<',True),b'\xa1\xb2\x3c\x4d':('>',True)}[blob[:4]]
    if len(blob)<24:raise ValueError('capture_invalide')
    network=struct.unpack_from(endian+'I',blob,20)[0]
    if network not in (1,101):raise ValueError('format_pcap_invalide')
    packets=[];offset=24
    while offset+16<=len(blob):
        seconds,fraction,length,original=struct.unpack_from(endian+'IIII',blob,offset)
        offset+=16
        if length>131072 or offset+length>len(blob):raise ValueError('paquet_invalide')
        frame=blob[offset:offset+length];offset+=length
        if network==1:
            if len(frame)<14 or frame[12:14]!=b'\x08\x00':continue
            frame=frame[14:]
        if len(frame)<28 or frame[0]>>4!=4 or frame[9]!=17:continue
        ihl=(frame[0]&15)*4
        if ihl<20 or len(frame)<ihl+8:continue
        if struct.unpack_from('!H',frame,6)[0]&0x3fff:continue
        src=socket.inet_ntoa(frame[12:16]);dest=socket.inet_ntoa(frame[16:20])
        if dest!=station_ip or src==station_ip:continue
        payload=frame[ihl+8:]
        if len(payload)<44 or payload[4]!=0x51:continue
        conv,cmd,frag,window,stamp,seq,una,size=struct.unpack_from('<IBBHIIII',payload)
        if conv!=0 or frag!=0 or size+44!=len(payload) or size<32 or size>1376:continue
        packets.append((seconds+fraction/(1e9 if nano else 1e6),seq,payload))
    packets.sort(key=lambda r:(r[0],r[1]))
    unique={}
    for _,seq,payload in packets:
        if seq in range(6) and seq not in unique:unique[seq]=payload
    return [unique[i] for i in range(6) if i in unique]

def _audit_startup_packets(packets:list[bytes],key:bytes)->dict:
    out={'kcp_controle_client_six_trames':len(packets),
         'kcp_sequences_consecutives':False,'kcp_hmac_valides':0,
         'kcp_enregistrements_aes_dechiffres':0,'kcp_commandes_structure_connue':0,
         'kcp_types_sanitises':[],'kcp_tailles_premieres_trames':[],
         'payloads_bruts_retournes':False,'secrets_retournes':False}
    if len(key)!=16 or len(packets)!=6:return out
    seqs=[]
    for p in packets:
        if len(p)<44:continue
        conv,cmd,frag,wnd,stamp,seq,una,n=struct.unpack_from('<IBBHIIII',p)
        if conv!=0 or cmd!=0x51 or n+44!=len(p):continue
        seqs.append(seq);out['kcp_tailles_premieres_trames'].append(len(p))
        if not hmac.compare_digest(hmac.new(key,p[:-20],hashlib.sha1).digest(),p[-20:]):continue
        out['kcp_hmac_valides']+=1
        try:plain=_record_decrypt(key,p[24:-20])
        except ValueError:continue
        out['kcp_enregistrements_aes_dechiffres']+=1
        if len(plain)<8 or struct.unpack_from('<I',plain)[0]!=_CONTROL_MAGIC:continue
        out['kcp_commandes_structure_connue']+=1
        kind=struct.unpack_from('<I',plain,4)[0]
        # Only known categorical class, not raw/decrypted command data.
        out['kcp_types_sanitises'].append('auth' if kind==1 else 'commande' if kind in (0,2,0x10003,0x10004,0x10005) else 'autre')
    out['kcp_sequences_consecutives']=seqs==list(range(6))
    return out

def audit_bootstrap_kcp_c9_b128(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
     confirmation_capture_personnelle,confirmation_camera_candidate,
     autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    base={'diagnostic':'aosu_audit_bootstrap_kcp_c9_b128','analyse_hors_ligne':True,
        'offres_0x20_envoyees':0,'offres_mqtt_envoyees':0,'stun_envoyes':0,'kcp_envoyes':0,
        'requetes_video_envoyees':0,'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
        'aucun_secret_retourne':True,'aucune_capture_modifiee':True}
    status=audit_preparation_video_c9_b123(coordinator,config_dir=config_dir,
        nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
        confirmation_capture_personnelle=confirmation_capture_personnelle,
        confirmation_camera_candidate=confirmation_camera_candidate,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for field in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if field in status:base[field]=status[field]
    if status.get('etat')!='comparaison_preparation_capture_terminee':
        return {**base,'etat':status.get('etat','audit_preparation_non_valide')}
    try:
        ip=_validate_target(ip_station)
        root=(Path(config_dir)/'smart_aosu_traces').resolve();path=(root/str(nom_capture)).resolve()
        if path.parent!=root or not path.is_file():return {**base,'etat':'capture_absente'}
        client=getattr(coordinator,'client',None)
        devices=getattr(client,'_tuya_oem_inventory_cache',{}).get('devices',{})
        data=getattr(coordinator,'data',{})
        stations=[v for v in data.values() if isinstance(v,dict)
             and v.get('model')=='H1L' and v.get('is_camera') is False]
        if len(stations)!=1 or not isinstance(devices,dict):return {**base,'etat':'station_ambigue'}
        matching=[dev for dev in devices.values() if isinstance(dev,dict) and _match_name(dev,stations[0].get('name'))]
        if len(matching)!=1:return {**base,'etat':'station_ambigue'}
        local=matching[0].get('localKey')
        if not isinstance(local,str) or len(local.encode())!=16:return {**base,'etat':'cle_station_absente'}
        offer,_,_=_authenticated_transcript(path,ip,local.encode())
        if not isinstance(offer,dict):return {**base,'etat':'offre_capture_inexploitable'}
        message=offer.get('msg',{})
        if not isinstance(message,dict):return {**base,'etat':'sdp_capture_absente'}
        key=_parse_answer_key(message.get('sdp'))
        if key is None:return {**base,'etat':'cle_media_offre_invalide'}
        packets=_client_first_six_kcp(path,ip)
        results=_audit_startup_packets(packets,key)
        if results['kcp_enregistrements_aes_dechiffres']==6 and results['kcp_commandes_structure_connue']==6:
            state='six_commandes_kcp_structure_validee'
        elif results['kcp_hmac_valides']==6:
            state='kcp_hmac_valides_commandes_a_etudier'
        elif len(packets)!=6:
            state='capture_six_kcp_incomplete'
        else:state='kcp_authentification_ou_cle_non_conforme'
        return {**base,**results,'etat':state}
    except (ValueError,TypeError,KeyError,IndexError,OSError,UnicodeError):
        return {**base,'etat':'analyse_kcp_non_exploitable'}
