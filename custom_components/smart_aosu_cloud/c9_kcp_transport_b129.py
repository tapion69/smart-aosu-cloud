"""B129: one bounded, authenticated KCP window probe after nominated ICE.

Only performs a few short-term credential STUN checks to a host candidate
whose IPv4 address equals the selected owned H1L. Sends one KCP WASK (zero-payload window check); never sends video,
PTZ, MQTT, stale session data, or logs private packet/credential content.
"""
from __future__ import annotations
import hashlib
import hmac
import ipaddress
import json
import os
import select
import socket
import struct
import time
import zlib
from typing import Any

from .c9_lan_signal_b125 import essai_negociation_lan_c9_b125
from .c9_lan_signal_b122 import _json_payload, _signal_response_summary
from .h1l_local_auth_b104 import _pack, _read_response
from .h1l_local_status_b107 import _session_key, _read_status_frame, _SafeStatusProtocolError
from .h1l_pcap_offline_b111 import _field_values_b117
from .tuya_channel0_probe import _parse_answer_key
from .c9_ice_stun_b118 import (
    COOKIE, sdp_ice_credentials, stun_parse, stun_integrity_valid,
    stun_fingerprint_valid,
)


def _stun_attribute(kind:int,data:bytes)->bytes:
    return struct.pack('!HH',kind,len(data))+data+(b'\x00'*((-len(data))%4))


def _stun_signed(kind:int, tx:bytes, attrs:bytes, password:str)->bytes:
    """RFC 5389 short-term HMAC-SHA1 and final FINGERPRINT."""
    if len(tx)!=12 or not isinstance(password,str) or not 1<=len(password)<=256:
        raise ValueError('stun_parametres_invalides')
    prefix=struct.pack('!HH',kind,len(attrs)+24)+COOKIE+tx+attrs
    mi=_stun_attribute(0x0008,hmac.new(password.encode(),prefix,hashlib.sha1).digest())
    unsigned=struct.pack('!HH',kind,len(attrs)+24+8)+COOKIE+tx+attrs+mi
    crc=(zlib.crc32(unsigned)^0x5354554e)&0xffffffff
    message=unsigned+_stun_attribute(0x8028,struct.pack('!I',crc))
    assert stun_parse(message) is not None
    return message


def _stun_check(local_ufrag:str,peer_ufrag:str,peer_pwd:str)->tuple[bytes,bytes]:
    if not all(isinstance(s,str) and s and len(s)<=128 and ':' not in s and '\n' not in s for s in (local_ufrag,peer_ufrag)):
        raise ValueError('identifiants_ice_invalides')
    username=(peer_ufrag+':'+local_ufrag).encode()
    tx=os.urandom(12)
    attrs=(_stun_attribute(0x0006,username)
           +_stun_attribute(0x0024,struct.pack('!I',1845501695))
           +_stun_attribute(0x8029,os.urandom(8)))  # capture: H1L controlling, client controlled
    return _stun_signed(0x0001,tx,attrs,peer_pwd),tx


def _stun_success(request:bytes,addr:tuple,local_pwd:str)->bytes:
    tx=request[8:20]
    ip=ipaddress.IPv4Address(addr[0]).packed
    port=int(addr[1])
    xor_addr=bytes(a^b for a,b in zip(ip,COOKIE))
    mapped=bytes((0,1))+struct.pack('!H',port^0x2112)+xor_addr
    return _stun_signed(0x0101,tx,_stun_attribute(0x0020,mapped),local_pwd)


def _station_candidate(line:object,station_ip:str)->tuple[str,int]|None:
    """Do not contact Internet, public, relay, or another LAN device."""
    if not isinstance(line,str) or len(line)>1024:return None
    parts=line.strip().lower().removeprefix('a=').split()
    if len(parts)<8 or not parts[0].startswith('candidate:') or parts[2]!='udp':return None
    if 'typ' not in parts:return None
    ix=parts.index('typ')
    if ix+1>=len(parts) or parts[ix+1]!='host':return None
    try:
        host=str(ipaddress.ip_address(parts[4]))
        port=int(parts[5])
        if ipaddress.ip_address(host).version!=4 or host!=station_ip or not 1024<=port<=65535:return None
        return host,port
    except (ValueError,IndexError):return None


def _station_sdp(message:dict)->tuple[str,str]|None:
    msg=message.get('msg')
    if not isinstance(msg,dict):return None
    candidates=[]
    for _,raw in _field_values_b117(msg,'sdp')[:8]:
        credentials=sdp_ice_credentials(raw)
        if credentials:candidates.append(credentials)
    return candidates[0] if len(candidates)==1 else None


def _kcp_wask_packet(offer_key:bytes,stamp:int=0)->bytes:
    """Fresh KCP WASK on conversation 0: no user command or captured payload.

    The 20-byte SHA1 signature uses the fresh *offer* AES key, as shown by
    an operator-supplied C9 capture. This is a transport window query, not auth.
    """
    if not isinstance(offer_key,bytes) or len(offer_key)!=16:
        raise ValueError('cle_offre_invalide')
    if not isinstance(stamp,int) or not 0<=stamp<=0xffffffff:
        raise ValueError('horodatage_invalide')
    segment=struct.pack('<IBBHIIII',0,0x53,0,512,stamp,0,0,0)
    assert len(segment)==24
    return segment+hmac.new(offer_key,segment,hashlib.sha1).digest()


def _kcp_identify_response(packet:bytes,answer_key:bytes)->str:
    """Return only a safe packet class; do not decrypt or reveal media.

    Inbound HMAC is checked with *answer* AES key, not the offer key.
    """
    if not isinstance(answer_key,bytes) or len(answer_key)!=16:
        return 'cle_reponse_absente'
    if not isinstance(packet,bytes) or len(packet)<44 or len(packet)>1420:
        return 'format_invalide'
    conv,cmd,frg,wnd,stamp,seq,una,size=struct.unpack_from('<IBBHIIII',packet)
    if conv not in (0,1,2) or cmd not in (0x51,0x52,0x53,0x54):
        return 'format_invalide'
    if frg!=0 or size>1376 or size+44!=len(packet):
        return 'format_invalide'
    if not hmac.compare_digest(hmac.new(answer_key,packet[:-20],hashlib.sha1).digest(),packet[-20:]):
        return 'hmac_invalide'
    if conv!=0:
        return 'media' if conv in (1,2) else 'autre'
    return {0x51:'push',0x52:'ack',0x53:'wask',0x54:'wins'}[cmd]


def _answer_media_key(response:dict)->bytes|None:
    msg=response.get('msg')
    if not isinstance(msg,dict):return None
    keys=[]
    for _,value in _field_values_b117(msg,'sdp')[:8]:
        aes=_parse_answer_key(value)
        if aes is not None:keys.append(aes)
    return keys[0] if len(keys)==1 else None


def _session_kcp_b129(ip:str,key:bytes,offer:dict,candidate:dict,udp:socket.socket)->dict:
    """Same authenticated TCP 0x20 rendezvous as B125, then bounded ICE.

    Local/STUN passwords and remote SDP stay in RAM for this invocation.
    No packet/username/candidate/secret goes to HA service output.
    """
    report={'tcp_authentifie':False,'lecture_0x10_authentifiee':False,
            'offres_0x20_envoyees':0,'candidats_0x20_envoyes':0,
            'reponses_0x20_authentifiees':0,'reponses_0x20_vides':0,
            'reponses_0x20_json':0,'reponse_sdp_recue':False,
            'session_id_reponse_identique':False,'candidats_station_recus':0,
            'candidat_h1l_local_valide':False,'candidats_rejetes_non_locaux':0,
            'stun_envoyes':0,'stun_recus':0,'stun_reponses_hmac_valides':0,
            'stun_requetes_authentifiees':0,'stun_reponses_envoyees':0,
            'stun_hmac_invalides':0,'datagrammes_non_stun_recus':0,
            'stun_roles_station_controlling':0,'stun_roles_station_controlled':0,
            'stun_nominations_recue_valide':0,'stun_erreurs_recues':0,
            'stun_erreur_487':0,'ice_paire_nommee':False,
            'kcp_paquets_passifs':0,'kcp_controle_passif':0,'kcp_media_passif':0,
            'offres_mqtt_envoyees':0,'requetes_video_envoyees':0,
            'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
            'kcp_demarre':False,'video_demarre':False,
            'kcp_wask_envoyes':0,'kcp_reponses_hmac_valides':0,
            'kcp_reponses_hmac_invalides':0,'kcp_wins_recus':0,
            'kcp_ack_recus':0,'kcp_push_recus':0,
            'kcp_media_authenticated_passif':0,
            'kcp_sonde_transport_terminee':False,
            'aucun_secret_retourne':True}
    local_msg=offer.get('msg',{})
    local_sdp=local_msg.get('sdp') if isinstance(local_msg,dict) else None
    local_creds=sdp_ice_credentials(local_sdp)
    if local_creds is None:return {**report,'etat':'sdp_locale_invalide'}
    expected=offer.get('header',{}).get('sessionid')
    own_station=offer.get('header',{}).get('to')
    own_account=offer.get('header',{}).get('from')
    if not all(isinstance(s,str) and s for s in (expected,own_station,own_account)):
        return {**report,'etat':'offre_identite_invalide'}
    nonce=os.urandom(16)
    seq=(int.from_bytes(os.urandom(4),'big')&0x7fffffff) or 1
    peer_creds=None;target=None;sent_tx=None;sent_when=None
    # These keys are per-session and remain only in memory; no output/log.
    offer_media_key=_parse_answer_key(local_sdp)
    answer_media_key=None
    kcp_sent_at=None
    if offer_media_key is None:return {**report,'etat':'cle_media_offre_absente'}
    try:
        with socket.create_connection((ip,6668),timeout=3) as tcp:
            tcp.settimeout(3)
            tcp.sendall(_pack(key,seq,3,nonce))
            op,challenge=_read_response(tcp,key)
            if op!=4 or len(challenge)!=48:
                return {**report,'etat':'challenge_invalide'}
            server_nonce,proof=challenge[:16],challenge[16:]
            if not hmac.compare_digest(proof,hmac.new(key,nonce,hashlib.sha256).digest()):
                return {**report,'etat':'preuve_challenge_invalide'}
            sk=_session_key(key,nonce,server_nonce)
            tcp.sendall(_pack(key,seq+1,5,hmac.new(key,server_nonce,hashlib.sha256).digest()))
            tcp.sendall(_pack(sk,seq+2,0x10,b'{}'))
            for _ in range(4):
                op,payload=_read_status_frame(tcp,sk,initial_key=key)
                if op==0x10:
                    report['tcp_authentifie']=True
                    report['lecture_0x10_authentifiee']=True
                    break
                if op not in (0x08,0x09):return {**report,'etat':'lecture_0x10_inattendue'}
            if not report['lecture_0x10_authentifiee']:
                return {**report,'etat':'lecture_0x10_absente'}
            encoded=json.dumps(offer,separators=(',',':'),ensure_ascii=False).encode()
            encoded_candidate=json.dumps(candidate,separators=(',',':'),ensure_ascii=False).encode()
            if not 64<=len(encoded)<=8192 or not 64<=len(encoded_candidate)<=8192:
                return {**report,'etat':'offre_ou_candidat_trop_grand'}
            tcp.sendall(_pack(sk,seq+3,0x20,encoded));report['offres_0x20_envoyees']=1
            tcp.sendall(_pack(sk,seq+4,0x20,encoded_candidate));report['candidats_0x20_envoyes']=1
            # B125 returned here as soon as SDP arrived, closing UDP. B127
            # keeps the same socket bound during the station candidate exchange.
            deadline=time.monotonic()+16
            udp.setblocking(False)
            tcp.settimeout(1.0)
            processed=0
            while time.monotonic()<deadline and processed<64:
                available,_,_=select.select([tcp,udp],[],[],min(.25,max(0,deadline-time.monotonic())))
                if udp in available:
                    for _ in range(8):
                        try:packet,addr=udp.recvfrom(4096)
                        except BlockingIOError:break
                        if addr[0]!=ip:continue
                        if target is not None and addr[1]!=target[1]:continue
                        parsed=stun_parse(packet)
                        if parsed is None:
                            report['datagrammes_non_stun_recus']+=1
                            # Classify only packets from the nominated owned H1L.
                            # Inbound authenticity is established by a fresh
                            # answer SDP AES key (never the stale PCAP key).
                            if target is not None and answer_media_key is not None:
                                kind=_kcp_identify_response(packet,answer_media_key)
                                if kind=='hmac_invalide':
                                    report['kcp_reponses_hmac_invalides']+=1
                                elif kind in ('push','ack','wask','wins','media'):
                                    report['kcp_reponses_hmac_valides']+=1
                                    report['kcp_paquets_passifs']+=1
                                    if kind=='media':
                                        report['kcp_media_passif']+=1
                                        report['kcp_media_authenticated_passif']+=1
                                    else:
                                        report['kcp_controle_passif']+=1
                                        if kind=='wins':report['kcp_wins_recus']+=1
                                        elif kind=='ack':report['kcp_ack_recus']+=1
                                        elif kind=='push':report['kcp_push_recus']+=1
                            continue
                        report['stun_recus']+=1
                        fingerprint=stun_fingerprint_valid(packet,parsed)
                        if fingerprint is not True:
                            report['stun_hmac_invalides']+=1;continue
                        if parsed['kind']==0x0101 and sent_tx is not None and packet[8:20]==sent_tx:
                            if target is None or addr[1]!=target[1]:continue
                            ok=stun_integrity_valid(packet,parsed,peer_creds[1]) if peer_creds else False
                            if ok is True:report['stun_reponses_hmac_valides']+=1
                            else:report['stun_hmac_invalides']+=1
                        elif parsed['kind']==0x0111 and sent_tx is not None and packet[8:20]==sent_tx:
                            # Don't trust an unauthenticated error packet even
                            # if its TXID matches: same SDP peer credential.
                            if not peer_creds or stun_integrity_valid(packet,parsed,peer_creds[1]) is not True:
                                report['stun_hmac_invalides']+=1
                                continue
                            report['stun_erreurs_recues']+=1
                            code=parsed['attrs'].get(0x0009)
                            if code and len(code[1])>=4:
                                c=(code[1][2] & 7)*100+code[1][3]
                                if c==487:report['stun_erreur_487']+=1
                        elif parsed['kind']==0x0001 and peer_creds is not None:
                            # STUN from station -> us is authenticated with our own ICE pwd.
                            username=parsed['attrs'].get(0x0006)
                            expected_user=(local_creds[0]+':'+peer_creds[0]).encode()
                            if not username or not hmac.compare_digest(username[1],expected_user):
                                report['stun_hmac_invalides']+=1;continue
                            if stun_integrity_valid(packet,parsed,local_creds[1]) is not True:
                                report['stun_hmac_invalides']+=1;continue
                            # In both own C9 captures the station is controlling
                            # and nominates the selected candidate using USE-CANDIDATE.
                            # Another controlled peer is a role collision, not a
                            # reason to silently assume the pair is selected.
                            attrs=parsed['attrs']
                            if 0x8029 in attrs:
                                report['stun_roles_station_controlled']+=1
                                continue
                            if 0x802a not in attrs or len(attrs[0x802a][1])!=8:
                                continue
                            report['stun_roles_station_controlling']+=1
                            report['stun_requetes_authentifiees']+=1
                            udp.sendto(_stun_success(packet,addr,local_creds[1]),addr)
                            report['stun_reponses_envoyees']+=1
                            if 0x0025 in attrs and attrs[0x0025][1]==b'':
                                report['stun_nominations_recue_valide']+=1
                                report['ice_paire_nommee']=True
                        else:
                            continue
                if tcp in available:
                    try:op,plain=_read_status_frame(tcp,sk,initial_key=key)
                    except socket.timeout:
                        return {**report,'etat':'tcp_trame_incomplete'}
                    processed+=1
                    if op in (0x08,0x09):continue
                    if op!=0x20:return {**report,'etat':'trame_tcp_non_attendue'}
                    report['reponses_0x20_authentifiees']+=1
                    if not plain:
                        report['reponses_0x20_vides']+=1;continue
                    obj=_json_payload(plain)
                    if not isinstance(obj,dict):continue
                    report['reponses_0x20_json']+=1
                    header=obj.get('header');msg=obj.get('msg')
                    if not isinstance(header,dict) or not isinstance(msg,dict):continue
                    shape=_signal_response_summary(plain,expected)
                    # The authenticated Tuya/TCP session plus matching fresh
                    # session ID is authoritative for the SDP. Some valid
                    # reply headers have absent/alternate routing labels.
                    if shape['sdp_ice_valide'] and shape['session_id_identique']:
                        report['reponse_sdp_recue']=True
                        report['session_id_reponse_identique']=True
                        peer_creds=_station_sdp(obj)
                        answer_media_key=_answer_media_key(obj)
                    # For candidate-only messages, which may omit a session
                    # ID, require the sender/recipient (when supplied) to
                    # match the two accounts from the authenticated offer.
                    authorized_route=(header.get('from') in (None,own_station)
                        and header.get('to') in (None,own_account))
                    if authorized_route:
                        for _,value in _field_values_b117(msg,'candidate')[:8]:
                            report['candidats_station_recus']+=1
                            c=_station_candidate(value,ip)
                            if c is not None and target is None:
                                target=c
                                report['candidat_h1l_local_valide']=True
                            elif c is None:
                                report['candidats_rejetes_non_locaux']+=1
                # The station candidate and authenticated answer must refer to
                # the same owned LAN session before sending any STUN traffic.
                if (sent_tx is None and peer_creds and target and
                    report['reponse_sdp_recue'] and report['session_id_reponse_identique']):
                    packet,sent_tx=_stun_check(local_creds[0],peer_creds[0],peer_creds[1])
                    udp.sendto(packet,target)
                    report['stun_envoyes']=1
                    report['stun_envoye']=True
                    sent_when=time.monotonic()
                if (kcp_sent_at is None and report['ice_paire_nommee']
                    and report['stun_reponses_hmac_valides']>0
                    and target is not None and answer_media_key is not None):
                    # H1L local IP and UDP port validated by B127. 44 bytes,
                    # no KCP application command or device authentication.
                    probe=_kcp_wask_packet(offer_media_key,int(time.monotonic()*1000)&0xffffffff)
                    udp.sendto(probe,target)
                    report['kcp_wask_envoyes']=1
                    kcp_sent_at=time.monotonic()
                if kcp_sent_at is not None and time.monotonic()-kcp_sent_at>6.0:
                    report['kcp_sonde_transport_terminee']=True
                    break
                if kcp_sent_at is None and sent_when is not None and time.monotonic()-sent_when>9.0:
                    break
            if report['kcp_wask_envoyes']:
                if report['kcp_wins_recus']:
                    return {**report,'etat':'kcp_reponse_wins_authentifiee'}
                if report['kcp_reponses_hmac_valides']:
                    return {**report,'etat':'kcp_reponse_autre_authentifiee'}
                return {**report,'etat':'kcp_wask_sans_reponse_authentifiee'}
            if report['stun_reponses_hmac_valides'] and report['ice_paire_nommee']:
                return {**report,'etat':'ice_nomination_et_reponse_valides_kcp_non_envoye'}
            if report['ice_paire_nommee']:
                return {**report,'etat':'ice_nomination_station_observee'}
            if report['stun_reponses_hmac_valides']:
                return {**report,'etat':'stun_reponse_lan_authentifiee'}
            if report['stun_erreur_487']:
                return {**report,'etat':'conflit_role_ice_487'}
            if report['stun_requetes_authentifiees']:
                return {**report,'etat':'stun_requete_station_authentifiee'}
            if sent_tx is not None:return {**report,'etat':'stun_lan_sans_reponse_valide'}
            if report['reponse_sdp_recue'] and report['session_id_reponse_identique']:
                return {**report,'etat':'sdp_recue_candidat_local_station_absent'}
            return {**report,'etat':'delai_reponse_sdp'}
    except _SafeStatusProtocolError as error:
        return {**report,'etat':'reponse_tuya_invalide','cause_protocole':error.code}
    except (OSError,TimeoutError):return {**report,'etat':'erreur_reseau_ou_timeout'}
    except (ValueError,KeyError,TypeError):return {**report,'etat':'erreur_format_recu'}
    except Exception:return {**report,'etat':'erreur_interne_sans_details'}


def essai_transport_kcp_c9_b129(coordinator:Any,*,config_dir,
    nom_capture,ip_station,camera_numero,confirmation_capture_personnelle,
    confirmation_camera_candidate,autoriser_offre_lan_active,
    autoriser_configuration_rtc,autoriser_test_ice_actif,autoriser_test_kcp_actif,
    autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    if autoriser_test_kcp_actif is not True:
        return {'diagnostic':'aosu_essai_transport_kcp_c9_b129','etat':'consentement_kcp_requis',
                'offres_0x20_envoyees':0,'stun_envoyes':0,'kcp_wask_envoyes':0,
                'requetes_video_envoyees':0,'commandes_ptz_envoyees':0}
    if autoriser_test_ice_actif is not True:
        return {'diagnostic':'aosu_essai_transport_kcp_c9_b129','etat':'consentement_ice_requis',
                'offres_0x20_envoyees':0,'stun_envoyes':0,'requetes_video_envoyees':0,
                'commandes_ptz_envoyees':0}
    result=essai_negociation_lan_c9_b125(coordinator,config_dir=config_dir,
       nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
       confirmation_capture_personnelle=confirmation_capture_personnelle,
       confirmation_camera_candidate=confirmation_camera_candidate,
       autoriser_offre_lan_active=autoriser_offre_lan_active,
       autoriser_configuration_rtc=autoriser_configuration_rtc,
       autoriser_reconstitution_oem=autoriser_reconstitution_oem,
       confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
       session_handler=_session_kcp_b129)
    result['diagnostic']='aosu_essai_transport_kcp_c9_b129'
    return result
