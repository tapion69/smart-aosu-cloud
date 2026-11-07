"""B153 — Offline comparison with *successful* captured C9 #2 station replies.

Requires existing owner-supplied PCAP only in a local development environment;
never necessary for playback, and never shipped in the ZIP.  No network I/O,
no ciphertext, keys, raw payloads or device IDs in the service response.
"""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import socket
import struct
from pathlib import Path
from typing import Any

from .c9_captureless_b144 import _snapshot, _ensure_oem
from .c9_kcp_bootstrap_b128 import _client_first_six_kcp
from .c9_kcp_auth_rtc_b133 import _unique_meta
from .c9_kcp_command_fields_b136 import _decrypt_six
from .c9_control_response_b149 import inspect_reply_b149
from .h1l_pcap_offline_b111 import _read_pcap, _frames_from_segments, _verify_and_decode
from .h1l_local_status_b107 import _session_key
from .c9_lan_signal_b122 import _json_payload, _signal_response_summary
from .tuya_channel0_probe import _parse_answer_key, _record_decrypt
from .c9_kcp_auth_b130 import _answer_media_key

_CAPTURE='c9_camera_2_reference.pcap'


def _station_kcp_key_evidence(path:Path,ip:str,keys:list[bytes])->list[int]:
    """Count inbound captured KCP HMAC matches for candidate SDP answer keys.

    This never connects to a camera and never returns keys or raw packets.
    A successful HMAC-SHA1 over a station-originated KCP frame binds an SDP
    candidate to the actual captured media session. It is *not* a heuristic
    about the order or number of TCP SDP replies.
    """
    if not 1<=len(keys)<=8 or any(not isinstance(k,bytes) or len(k)!=16 for k in keys):
        raise ValueError('cles_candidates_invalides')
    blob=path.read_bytes()
    if not 24<=len(blob)<=32*1024*1024:
        raise ValueError('capture_invalide')
    signatures={b'\xd4\xc3\xb2\xa1':('<',False),
      b'\xa1\xb2\xc3\xd4':('>',False),
      b'\x4d\x3c\xb2\xa1':('<',True),
      b'\xa1\xb2\x3c\x4d':('>',True)}
    if blob[:4] not in signatures:raise ValueError('capture_invalide')
    endian,_=signatures[blob[:4]]
    link=struct.unpack_from(endian+'I',blob,20)[0]
    if link not in (1,101):raise ValueError('format_lien_invalide')
    results=[0]*len(keys)
    offset=24
    while offset+16<=len(blob):
        _,_,n,_=struct.unpack_from(endian+'IIII',blob,offset);offset+=16
        if n>131072 or offset+n>len(blob):raise ValueError('trame_invalide')
        frame=blob[offset:offset+n];offset+=n
        if link==1:
            if len(frame)<14 or frame[12:14]!=b'\x08\x00':continue
            frame=frame[14:]
        if len(frame)<28 or frame[0]>>4!=4 or frame[9]!=17:continue
        ihl=(frame[0]&15)*4
        if (ihl<20 or len(frame)<ihl+8 or
                (struct.unpack_from('!H',frame,6)[0]&0x3fff)):continue
        if socket.inet_ntoa(frame[12:16])!=ip:continue
        packet=frame[ihl+8:]
        if not 44<=len(packet)<=1500:continue
        conv,cmd,frg,_,_,_,_,size=struct.unpack_from('<IBBHIIII',packet)
        if conv not in (0,1,2) or cmd not in (0x51,0x52,0x53,0x54):continue
        if frg!=0 or size>1456 or size+44!=len(packet):continue
        for i,key in enumerate(keys):
            if hmac.compare_digest(hmac.new(key,packet[:-20],hashlib.sha1).digest(),packet[-20:]):
                results[i]+=1
    return results

def _tcp_answer_key_detailed(path:Path,ip:str,local:bytes,sid:str):
    """Authenticate SDP and distinguish duplicate answers from distinct keys.

    Session HMAC, offer target and session ID are mandatory. Multiple SDP
    frames are valid only if they share the same key or exactly one candidate
    authenticates captured inbound KCP packets. No arbitrary key selection.
    """
    metrics={'flux_tcp_examines':0,'sessions_tuya_authentifiees':0,
       'offres_sdp_station_authentifiees':0,'reponses_sdp_authentifiees':0,
       'reponses_sdp_session_conforme':0,'reponses_sdp_avec_cle_media':0,
       'offre_avec_cle_media':False,'reponses_sdp_routage_alternatif':0,
       'cles_media_reponse_distinctes':0,'reponses_sdp_dupliquees':0,
       'selection_cle_reponse':'aucune','kcp_valides_cle_selectionnee':0,
       'raison_echec':'session_tuya_absente'}
    analysis=_read_pcap(path,ip)
    for flow in analysis['flows'].values():
        metrics['flux_tcp_examines']+=1
        outgoing=_frames_from_segments(flow['client'])
        incoming=_frames_from_segments(flow['station'])
        init=next((f for f in outgoing if f[0]==3),None)
        chall=next((f for f in incoming if f[0]==4),None)
        finish=next((f for f in outgoing if f[0]==5),None)
        if not (init and chall and finish):continue
        nonce=_verify_and_decode(init,local,False)
        resp=_verify_and_decode(chall,local,True)
        fin=_verify_and_decode(finish,local,False)
        if not (isinstance(nonce,bytes) and len(nonce)==16
             and isinstance(resp,bytes) and len(resp)==48
             and isinstance(fin,bytes) and len(fin)==32):continue
        if not (hmac.compare_digest(resp[16:],hmac.new(local,nonce,hashlib.sha256).digest())
             and hmac.compare_digest(fin,hmac.new(local,resp[:16],hashlib.sha256).digest())):continue
        metrics['sessions_tuya_authentifiees']+=1
        metrics['raison_echec']='offre_sdp_absente'
        sk=_session_key(local,nonce,resp[:16]); offers=[]
        for frame in outgoing:
            if frame[0]!=0x20:continue
            raw=_verify_and_decode(frame,sk,False)
            obj=_json_payload(raw) if isinstance(raw,bytes) else None
            header=obj.get('header') if isinstance(obj,dict) else None
            if (isinstance(header,dict) and header.get('type')=='offer'
                    and header.get('to')==sid):
                offers.append(obj)
        metrics['offres_sdp_station_authentifiees']+=len(offers)
        # A fresh session cannot be uniquely tied to multiple captured offers.
        if len(offers)!=1:
            metrics['raison_echec']='offre_sdp_absente' if not offers else 'offres_sdp_ambigues'
            continue
        offer=offers[0];h=offer['header'];session=h.get('sessionid');uid=h.get('from')
        if not isinstance(session,str) or not session or not isinstance(uid,str) or not uid:
            metrics['raison_echec']='session_offre_incomplete'
            continue
        msg=offer.get('msg')
        offer_key=_parse_answer_key(msg.get('sdp')) if isinstance(msg,dict) else None
        metrics['offre_avec_cle_media']=isinstance(offer_key,bytes) and len(offer_key)==16
        matches=[]
        for frame in incoming:
            if frame[0]!=0x20:continue
            raw=_verify_and_decode(frame,sk,True)
            obj=_json_payload(raw) if isinstance(raw,bytes) else None
            if not isinstance(obj,dict):continue
            hh=obj.get('header')
            if not isinstance(hh,dict):continue
            shape=_signal_response_summary(raw,session)
            if not shape.get('sdp_ice_valide'):continue
            metrics['reponses_sdp_authentifiees']+=1
            if not shape.get('session_id_identique'):continue
            metrics['reponses_sdp_session_conforme']+=1
            # Matching authenticated TCP transaction + SDP session is the
            # same acceptance criterion as the B152 live path. Some valid
            # station replies carry alternative routing labels.
            if hh.get('from') not in (None,sid) or hh.get('to') not in (None,uid):
                metrics['reponses_sdp_routage_alternatif']+=1
            ans_key=_answer_media_key(obj)
            if isinstance(ans_key,bytes) and len(ans_key)==16:
                metrics['reponses_sdp_avec_cle_media']+=1
                matches.append(ans_key)
        if not matches:
            metrics['raison_echec']=('reponse_sdp_absente' if not metrics['reponses_sdp_authentifiees']
               else 'session_sdp_non_conforme' if not metrics['reponses_sdp_session_conforme']
               else 'cle_media_reponse_absente')
            continue
        # The captured station may repeat an authenticated SDP response, or
        # provide multiple valid candidates for the same TCP session. Count
        # distinct *keys*, not SDP frames, before rejecting the transaction.
        unique=[]
        for candidate in matches:
            if candidate not in unique:unique.append(candidate)
        metrics['cles_media_reponse_distinctes']=len(unique)
        metrics['reponses_sdp_dupliquees']=len(matches)-len(unique)
        if not metrics['offre_avec_cle_media']:
            metrics['raison_echec']='cle_media_offre_absente'
            continue
        if len(unique)==1:
            answer_key=unique[0]
            metrics['selection_cle_reponse']=('reponses_equivalentes'
                if len(matches)>1 else 'reponse_unique')
        else:
            # Never choose 'first' or 'last' SDP arbitrarily. Require a
            # unique candidate to HMAC-authenticate actual station KCP frames.
            evidence=_station_kcp_key_evidence(path,ip,unique)
            winners=[i for i,count in enumerate(evidence) if count>0]
            if len(winners)!=1:
                metrics['raison_echec']=('cles_media_sans_confirmation_kcp'
                   if not winners else 'cles_media_kcp_ambigues')
                continue
            answer_key=unique[winners[0]]
            metrics['kcp_valides_cle_selectionnee']=evidence[winners[0]]
            metrics['selection_cle_reponse']='signature_kcp_capture'
        metrics['raison_echec']='aucune'
        return offer_key,answer_key,metrics
    return None,None,metrics


def _tcp_answer_key(path:Path,ip:str,local:bytes,sid:str):
    """Preserve the legacy two-value helper used by existing audit tests."""
    offer_key,answer_key,_=_tcp_answer_key_detailed(path,ip,local,sid)
    return offer_key,answer_key

def _station_control_capture(path:Path,ip:str,answer_key:bytes)->tuple[list[dict],int,int]:
    """Safely parse only first 5 inbound KCP channel-0 PUSH responses.

    The passed key is derived from an authenticated SDP answer in the capture.
    Strict HMAC before AES and magic check. Returns low-domain structural data.
    """
    raw=path.read_bytes()
    if not 24<=len(raw)<=32*1024*1024:raise ValueError('capture_invalide')
    signatures={b'\xd4\xc3\xb2\xa1':('<',False),b'\xa1\xb2\xc3\xd4':('>',False),
      b'\x4d\x3c\xb2\xa1':('<',True),b'\xa1\xb2\x3c\x4d':('>',True)}
    if raw[:4] not in signatures:raise ValueError('capture_invalide')
    endian,nano=signatures[raw[:4]]
    net=struct.unpack_from(endian+'I',raw,20)[0]
    if net not in (1,101):raise ValueError('format_lien_invalide')
    found={};offset=24;all_inbound=0;media_before_last=0
    while offset+16<=len(raw):
        sec,frac,n,orig=struct.unpack_from(endian+'IIII',raw,offset);offset+=16
        if n>131072 or offset+n>len(raw):raise ValueError('trame_invalide')
        frame=raw[offset:offset+n];offset+=n
        if net==1:
            if len(frame)<14 or frame[12:14]!=b'\x08\x00':continue
            frame=frame[14:]
        if len(frame)<28 or frame[0]>>4!=4 or frame[9]!=17:continue
        ihl=(frame[0]&15)*4
        if ihl<20 or len(frame)<ihl+8 or (struct.unpack_from('!H',frame,6)[0]&0x3fff):continue
        if socket.inet_ntoa(frame[12:16])!=ip:continue
        packet=frame[ihl+8:]
        if len(packet)<44:continue
        conv,cmd,frg,wnd,ts,sn,una,z=struct.unpack_from('<IBBHIIII',packet)
        if conv not in (0,1,2) or z+44!=len(packet) or cmd!=0x51:continue
        if not hmac.compare_digest(hmac.new(answer_key,packet[:-20],hashlib.sha1).digest(),packet[-20:]):continue
        if conv in (1,2):
            media_before_last+=1
            continue
        if conv!=0 or sn not in range(5) or sn in found:continue
        try: plain=_record_decrypt(answer_key,packet[24:-20])
        except (ValueError,TypeError):continue
        s=inspect_reply_b149(plain)
        if s.get('magic_valide') and s.get('type_et_sous_type_attendus') and s.get('longueur_declaree_coherente'):
            found[sn]={ 'numero_reponse':sn+1,
              'commande_associee':s.get('commande_associee'),
              'champ_3_valeur_candidate':s.get('champ_3_valeur_candidate'),
              'longueur_declaree_coherente':True,
              'taille_payload_classe':s.get('taille_payload_classe')}
            all_inbound+=1
    return [found[x] for x in sorted(found)],all_inbound,media_before_last

def audit_reponses_station_c9_b153(coordinator:Any,*,config_dir:str|Path,
        ip_station:str,confirmation_captures_personnelles:bool=False,
        autoriser_reconstitution_oem:bool=False,
        confirmation_envoi_mot_de_passe:bool=False)->dict:
    """B155: optional explicitly consented OEM preparation, then offline PCAP audit.

    Without both OEM permissions this action NEVER calls an external service.
    Secrets, private identifiers, SDP and decrypted payloads are never returned.
    """
    report={'diagnostic':'aosu_audit_reponses_station_c9_b157','analyse_hors_ligne':True,
        'analyse_pcap_hors_ligne':True,'preparation_oem_reseau':False,
        'appels_reseau':0,'commandes_video_envoyees':0,'requetes_rtc':0,
        'commandes_ptz_envoyees':0,'captures_rejouees':False,
        'identifiants_retournes':False,'secrets_retournes':False,
        'octets_clairs_retournes':False,'contenu_video_retourne':False,
        'modification_direct_b152':False,'etape_audit':'initialisation'}
    if confirmation_captures_personnelles is not True:
        return {**report,'etat':'confirmation_capture_requise'}
    try:
        ip=str(ipaddress.IPv4Address(ip_station))
    except (ValueError,TypeError,ipaddress.AddressValueError):
        return {**report,'etat':'ip_station_invalide'}
    phase='inventaire_oem'
    try:
        report['etape_audit']=phase
        try:
            sid,cid,devices,meta=_snapshot(coordinator,2,ip)
        except ValueError as first_exc:
            # The inventory is ephemeral across HA restarts. Refresh it only
            # if the caller explicitly authorizes OEM network access and
            # password submission. Do not retry unrelated identity mismatches.
            if str(first_exc) != 'inventaire_oem_absent':
                raise
            if not (autoriser_reconstitution_oem is True and
                    confirmation_envoi_mot_de_passe is True):
                return {**report,'etat':'inventaire_oem_absent',
                        'etape_echec':'inventaire_oem',
                        'preparation_oem_autorisation_requise':True}
            report['preparation_oem_reseau']=True
            report['analyse_hors_ligne']=False
            phase='preparation_oem';report['etape_audit']=phase
            preparation=_ensure_oem(coordinator, True, True)
            report['appels_reseau']=int(preparation.get('appels_http_oem',0))
            report['preparation_oem_terminee']=True
            phase='inventaire_oem';report['etape_audit']=phase
            sid,cid,devices,meta=_snapshot(coordinator,2,ip)
        station=devices.get(sid)
        if not isinstance(station,dict):
            return {**report,'etat':'station_oem_absente'}
        key=station.get('localKey')
        if not isinstance(key,str) or len(key.encode('utf-8'))!=16:
            return {**report,'etat':'cle_station_absente'}
        phase='capture_locale';report['etape_audit']=phase
        base=(Path(config_dir)/'smart_aosu_traces').resolve()
        path=(base/_CAPTURE).resolve()
        if path.parent!=base or not path.is_file():
            return {**report,'etat':'capture_c9_2_absente'}
        if not 24<=path.stat().st_size<=32*1024*1024:
            return {**report,'etat':'taille_capture_invalide'}
        phase='session_tuya_capture';report['etape_audit']=phase
        # Only inspect an authenticated *captured* TCP exchange, never LAN.
        offer_key,answer_key,safe=_tcp_answer_key_detailed(path,ip,key.encode('utf-8'),sid)
        report['diagnostic_session_capture_b157']=safe
        if offer_key is None or answer_key is None:
            return {**report,'etat':'reponse_sdp_capture_non_authentifiable',
                    'etape_echec':'session_tuya_capture'}
        report['sdp_capture_authentifiee']=True
        phase='identite_kcp_capture';report['etape_audit']=phase
        packets=_client_first_six_kcp(path,ip)
        if len(packets)!=6:
            return {**report,'etat':'six_messages_kcp_capture_incomplets'}
        plans=_decrypt_six(packets,offer_key)
        checks,matched=_unique_meta(plans[0],sid,cid,devices)
        if (matched!=meta or not checks.get('auth_bloc_camera_conforme')
                or not checks.get('auth_bloc_station_conforme')):
            return {**report,'etat':'routage_camera_capture_invalide'}
        report['capture_c9_2_identite_verifiee']=True
        phase='reponses_kcp_station_capture';report['etape_audit']=phase
        replies,n,media=_station_control_capture(path,ip,answer_key)
        report.update({'reponses_station_dechiffrees':n,
           'reponses':replies,
           'valeur_champ_3_identique_b152':(len(replies)==5 and
                                              all(x['champ_3_valeur_candidate']==1 for x in replies)),
           'media_capture_authentifie':media>0,
           'etat':'comparaison_reponses_capture_terminee' if len(replies)==5
                  else 'reponses_capture_incompletes',
           'etape_audit':'terminee'})
    except (ValueError,KeyError,IndexError,TypeError,OSError,UnicodeError,struct.error):
        # No raw exception: may contain user-provided device IDs or paths.
        report['etat']='etape_capture_non_exploitable'
        report['etape_echec']=phase
    except Exception:
        report['etat']='erreur_interne_audit_b154'
        report['etape_echec']=phase
    return report
