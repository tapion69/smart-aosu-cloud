"""B138: strict reconstruction of C9's five video startup controls.

Captured frames are verified in RAM against a local H1L key and never sent.
Commands are constructed anew from current OEM camera metadata, known
non-secret wire constants, and fresh RTC/SDP keys. The active path is opt-in,
LAN-only, bounded, and never writes or exposes user video or secret material.
The B134/C5L modules are not modified.
"""
from __future__ import annotations
import hashlib,hmac,os,struct,time,socket,select,json,ipaddress,zlib
from pathlib import Path
from typing import Any
from .c9_kcp_command_fields_b136 import _decrypt_six
from .c9_media_diagnostics_b138 import C9MediaProbeB138
from .tuya_hevc_rtp import extract_rtp
from .tuya_kcp_receive_b87 import KcpReceiveB87
from .c9_kcp_bootstrap_b128 import _client_first_six_kcp
from .c9_kcp_auth_rtc_b133 import _context,_unique_meta
from .c9_kcp_auth_gateway_b134 import _new_auth_with_h1l_key,audit_cle_h1l_c9_b134
from .c9_video_preflight_b123 import _authenticated_transcript
from .c9_lan_signal_b125 import essai_negociation_lan_c9_b125
from .tuya_channel0_probe import _parse_answer_key,_record_encrypt,_record_decrypt,_command
from .c9_kcp_auth_b130 import (_stun_check,_stun_success,_station_candidate,_station_sdp,
  _kcp_wask_packet,_kcp_identify_response,_answer_media_key,_fresh_kcp_auth_packet)
from .c9_lan_signal_b122 import _json_payload,_signal_response_summary
from .h1l_local_auth_b104 import _pack,_read_response
from .h1l_local_status_b107 import _session_key,_read_status_frame,_SafeStatusProtocolError
from .h1l_pcap_offline_b111 import _field_values_b117
from .c9_ice_stun_b118 import stun_parse,stun_fingerprint_valid,stun_integrity_valid,sdp_ice_credentials

_EXPECTED=((0,0x0a,4),(2,0x0c,68),(0x10004,0x13,72),
           (0x10003,0x10,72),(0x10005,0x40010,72))


def _reconstruct_post_auth(plains:list[bytes],meta:str)->tuple[bytes,...]:
    """Build only five allowlisted commands; no arbitrary captured payload.

    Profile fields are stateless protocol flags: exactly one nonzero bit in
    a 4-byte command, or a 36-byte zero mask at fixed byte offsets. All user
    and device IDs come from the fresh OEM inventory, never from the PCAP.
    """
    if len(plains)!=6 or not isinstance(meta,str):raise ValueError('sequence_absente')
    ref=meta.encode('utf-8')
    if not 5<=len(ref)<=32 or any(c<32 or c>126 for c in ref):
        raise ValueError('reference_oem_camera_invalide')
    out=[]
    for i,(kind,sub,size) in enumerate(_EXPECTED,1):
        plain=plains[i]
        if (len(plain)!=20+size or
            struct.unpack_from('<IIIII',plain,0)!=(0x12345678,kind,0,sub,size)):
            raise ValueError('commande_c9_entete_inattendu')
        payload=plain[20:]
        if i==1:
            indices=[j for j,b in enumerate(payload) if b]
            if len(indices)!=1 or payload[indices[0]] not in (1,2,4,8,16,32,64,128):
                raise ValueError('commande_c9_flag_inattendu')
            # The capture only defines protocol flags (non-secret); reconstruct
            # a new 4-byte constant independently, never copy payload bytes.
            new=bytearray(size);new[indices[0]]=payload[indices[0]]
        else:
            if not hmac.compare_digest(payload[:32],ref.ljust(32,b'\0')):
                raise ValueError('reference_camera_non_conforme')
            new=bytearray(size);new[:32]=ref.ljust(32,b'\0')
            if i==2:
                if any(payload[32:]):raise ValueError('commande_c9_extension_2')
            else:
                indices=[j for j in range(32,size) if payload[j]]
                # B136 found ONE small u32 per trailing command. The single
                # nonzero byte is at a known word boundary, not an unknown ID.
                expected_index=64 if i==4 else 68
                if indices!=[expected_index] or payload[expected_index] not in (1,2,4,8,16,32,64,128):
                    raise ValueError('commande_c9_parametre_non_reconstructible')
                new[expected_index]=payload[expected_index]
        regenerated=_command(kind,sub,bytes(new))
        if not hmac.compare_digest(regenerated,plain):
            raise ValueError('profil_capture_non_reproductible')
        out.append(regenerated)
    return tuple(out)


def _prepare_profile(coordinator,config_dir,nom_capture,ip_station):
    plain,sid,cid,devices=_context(coordinator,config_dir,nom_capture,ip_station)
    checks,meta=_unique_meta(plain,sid,cid,devices)
    if meta is None or checks.get('auth_schema_reconstructible') is not True:
        raise ValueError('identite_station_camera_invalide')
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    path=(root/str(nom_capture)).resolve()
    if path.parent!=root or not path.is_file() or path.stat().st_size>32*1024*1024:
        raise ValueError('capture_non_exploitable')
    sk=devices[sid]['localKey']
    if not isinstance(sk,str) or len(sk.encode())!=16:raise ValueError('cle_station_absente')
    offer,_,_=_authenticated_transcript(path,ip_station,sk.encode())
    media_key=_parse_answer_key(offer.get('msg',{}).get('sdp')) if isinstance(offer,dict) else None
    if media_key is None:raise ValueError('cle_offre_capture_absente')
    plains=_decrypt_six(_client_first_six_kcp(path,ip_station),media_key)
    commands=_reconstruct_post_auth(plains,meta)
    return plain,sid,cid,devices,commands


def _fresh_push(offer_key:bytes,plain:bytes,sequence:int,stamp:int)->bytes:
    if not isinstance(plain,bytes) or not 1<=sequence<=5 or len(offer_key)!=16:
        raise ValueError('kcp_parametres_commandes_invalides')
    if len(plain)>96 or plain[:4]!=struct.pack('<I',0x12345678):
        raise ValueError('commande_non_conforme')
    record=_record_encrypt(offer_key,plain,os.urandom(16))
    header=struct.pack('<IBBHIIII',0,0x51,0,512,stamp,sequence,0,len(record))
    return header+record+hmac.new(offer_key,header+record,hashlib.sha1).digest()


def _fresh_ack(offer_key:bytes,incoming:bytes)->bytes:
    if len(offer_key)!=16 or len(incoming)<44 or incoming[4]!=0x51:
        raise ValueError('kcp_ack_invalide')
    conv,cmd,frg,wnd,ts,sn,una,size=struct.unpack_from('<IBBHIIII',incoming)
    if conv not in (0,1,2) or size+44!=len(incoming):
        raise ValueError('kcp_ack_invalide')
    head=struct.pack('<IBBHIIII',conv,0x52,0,512,ts,sn,0,0)
    return head+hmac.new(offer_key,head,hashlib.sha1).digest()


# B138: recipient acknowledges a sender sequence, and advances UNA only
# after contiguous authenticated receive. The AES record is never echoed.
def _fresh_ack_with_una_b138(offer_key: bytes, incoming: bytes, una: int) -> bytes:
    if not isinstance(una,int) or not 0 <= una <= 0xffffffff:
        raise ValueError('una_hors_limites')
    if len(offer_key)!=16 or len(incoming)<44:
        raise ValueError('ack_trame_invalide')
    conv,cmd,frg,wnd,ts,sn,old_una,n=struct.unpack_from('<IBBHIIII',incoming)
    if conv not in (0,1,2) or cmd!=0x51 or n+44!=len(incoming):
        raise ValueError('ack_trame_invalide')
    head=struct.pack('<IBBHIIII',conv,0x52,0,512,ts,sn,una,0)
    return head+hmac.new(offer_key,head,hashlib.sha1).digest()

def audit_profil_demarrage_c9_b137(coordinator:Any,*,config_dir,nom_capture,ip_station,
  camera_numero,confirmation_capture_personnelle,confirmation_camera_candidate,
  autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    report={'diagnostic':'aosu_audit_profil_demarrage_c9_b137',
      'analyse_hors_ligne':True,'offres_0x20_envoyees':0,'stun_envoyes':0,
      'kcp_envoyes':0,'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
      'profil_c9_reconstructible':False,'captures_rejouees':False,
      'secrets_retournes':False,'identifiants_retournes':False,'payloads_bruts_retournes':False}
    if not all(x is True for x in (confirmation_capture_personnelle,confirmation_camera_candidate)):
        return {**report,'etat':'confirmations_requises'}
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_cle_h1l_c9_b134(coordinator,config_dir=config_dir,
      nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
      confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
      autoriser_reconstitution_oem=autoriser_reconstitution_oem,
      confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for k in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if k in pre:report[k]=pre[k]
    if pre.get('auth_gateway_key_preparable') is not True:
        return {**report,'etat':'preparation_cle_station_impossible'}
    try:
        _plain,_sid,_cid,_devices,commands=_prepare_profile(coordinator,config_dir,nom_capture,ip_station)
        report.update({'profil_c9_reconstructible':True,
          'commandes_post_auth_reconstruites':len(commands),
          'tailles_commandes_claires':[len(x) for x in commands],
          'cle_station_hypothese_md5_non_verifiee':True,
          'etat':'profil_demarrage_c9_reconstruit'})
        return report
    except (ValueError,TypeError,IndexError,KeyError,OSError,UnicodeError,struct.error):
        return {**report,'etat':'profil_demarrage_c9_non_reconstructible'}
    except Exception:return {**report,'etat':'erreur_interne_masquee'}


def _session_kcp_b139(ip:str,key:bytes,offer:dict,candidate:dict,udp:socket.socket,auth_plain:bytes,
                       commands:tuple[bytes,...],preview,stop_event)->dict:
    """Same authenticated TCP 0x20 rendezvous as B125, then bounded ICE.

    Local/STUN passwords and remote SDP stay in RAM for this invocation.
    No packet/username/candidate/secret goes to HA service output.
    """
    if not isinstance(commands,tuple) or len(commands)!=5:
        raise ValueError('profil_commandes_invalide')
    for i,c in enumerate(commands):
        typ,sub,size=_EXPECTED[i]
        if len(c)!=20+size or struct.unpack_from('<IIIII',c)!=(0x12345678,typ,0,sub,size):
            raise ValueError('profil_commandes_invalide')
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
            'kcp_auth_push_envoyes':0,'kcp_auth_ack_recus':0,
            'kcp_auth_reponses_push_recues':0,'kcp_auth_confirmee':False,
            'aucun_secret_retourne':True,
            'kcp_commandes_post_auth_envoyees':0,'kcp_commandes_ack_recus':0,
            'kcp_push_station_acquittes':0,'kcp_media_dechiffrables':0,
            'kcp_reponses_controle_dechiffrables':0,
            'reception_media_authentifiee':False,'video_h265_decodec':False,
            'kcp_acks_media_envoyes':0,'limite_acks_kcp_atteinte':False}
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
    auth_sent_at=None
    post_sent_at=None
    post_ack_sequences=set()
    kcp_inbound_acks=0
    media_probe=C9PreviewProbeB139(preview)
    control_rx=KcpReceiveB87()
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
            deadline=time.monotonic()+100
            udp.setblocking(False)
            tcp.settimeout(1.0)
            processed=0
            while time.monotonic()<deadline and processed<64 and not stop_event.is_set():
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
                                    # B138: fresh authenticated packet only, bounded
                                    # ACKs, per-channel contiguous UNA and no data replay.
                                    if packet[4]==0x51 and kind in ('push','media'):
                                        conv,_,frg,_,_,seqno,_,_=struct.unpack_from('<IBBHIIII',packet)
                                        decoded=None
                                        try:
                                            decoded=_record_decrypt(answer_media_key,packet[24:-20])
                                            if kind=='media' and len(decoded)>=8:
                                                report['kcp_media_dechiffrables']+=1
                                                report['reception_media_authentifiee']=True
                                            elif kind=='push' and decoded[:4]==struct.pack('<I',0x12345678):
                                                report['kcp_reponses_controle_dechiffrables']+=1
                                        except ValueError:pass
                                        if kind=='media' and decoded is not None:
                                            contiguous_una=media_probe.accept(conv,seqno,frg,decoded)
                                        elif conv==0:
                                            control_rx.accept(seqno,frg,decoded if decoded is not None else b'')
                                            contiguous_una=control_rx.next_sequence
                                        else:
                                            contiguous_una=0
                                        if kcp_inbound_acks<20000:
                                            udp.sendto(_fresh_ack_with_una_b138(offer_media_key,packet,contiguous_una),target)
                                            kcp_inbound_acks+=1
                                            report['kcp_push_station_acquittes']+=1
                                            if conv in (1,2): report['kcp_acks_media_envoyes']+=1
                                        elif not report['limite_acks_kcp_atteinte']:
                                            report['limite_acks_kcp_atteinte']=True
                                    report['kcp_reponses_hmac_valides']+=1
                                    report['kcp_paquets_passifs']+=1
                                    if kind=='media':
                                        report['kcp_media_passif']+=1
                                        report['kcp_media_authenticated_passif']+=1
                                    else:
                                        report['kcp_controle_passif']+=1
                                        if kind=='wins':report['kcp_wins_recus']+=1
                                        elif kind=='ack':
                                            report['kcp_ack_recus']+=1
                                            ack_sn=struct.unpack_from('<I',packet,12)[0]
                                            if auth_sent_at is not None and ack_sn==0:
                                                report['kcp_auth_ack_recus']+=1
                                            elif post_sent_at is not None and 1<=ack_sn<=5:
                                                post_ack_sequences.add(ack_sn)
                                                report['kcp_commandes_ack_recus']=len(post_ack_sequences)
                                        elif kind=='push':
                                            report['kcp_push_recus']+=1
                                            if auth_sent_at is not None:
                                                report['kcp_auth_reponses_push_recues']+=1
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
                # A station-authenticated WINS proves KCP transport readiness,
                # but the client must not send auth until that point. This
                # plaintext was regenerated from *current* OEM credentials and
                # capture-validated structure, not from captured old credentials.
                if (auth_sent_at is None and report['kcp_wins_recus']>0 and
                    report['stun_reponses_hmac_valides']>0 and
                    report['ice_paire_nommee'] and target is not None):
                    fresh_auth=_fresh_kcp_auth_packet(offer_media_key,auth_plain,
                        int(time.monotonic()*1000)&0xffffffff)
                    udp.sendto(fresh_auth,target)
                    report['kcp_auth_push_envoyes']=1
                    report['kcp_demarre']=True
                    auth_sent_at=time.monotonic()
                if (post_sent_at is None and report['kcp_auth_ack_recus']>0 and
                    report['ice_paire_nommee'] and report['stun_reponses_hmac_valides']>0 and
                    target is not None):
                    # The application's genuine C9 profile is verified before
                    # any active SDP, but the B134 auth MD5 remains a hypothesis.
                    # One bounded, explicitly authorized video command burst.
                    for num,command in enumerate(commands,1):
                        fresh=_fresh_push(offer_media_key,command,num,int(time.monotonic()*1000)&0xffffffff)
                        udp.sendto(fresh,target)
                        report['kcp_commandes_post_auth_envoyees']+=1
                    report['commandes_video_envoyees']=report['kcp_commandes_post_auth_envoyees']
                    post_sent_at=time.monotonic()
                if post_sent_at is not None and time.monotonic()-post_sent_at>75.0:
                    break
                if auth_sent_at is not None and post_sent_at is None and time.monotonic()-auth_sent_at>6.0:
                    break
                if auth_sent_at is None and kcp_sent_at is not None and time.monotonic()-kcp_sent_at>6.0:
                    report['kcp_sonde_transport_terminee']=True
                    break
                if kcp_sent_at is None and sent_when is not None and time.monotonic()-sent_when>9.0:
                    break
            if report['kcp_commandes_post_auth_envoyees']:
                report.update(media_probe.summary())
                report['etat']=('images_c9_decodees' if preview.image() else
                    'medias_kcp_c9_recus_sans_jpeg' if report['kcp_media_authenticated_passif']
                    else 'cinq_commandes_video_envoyees_sans_media')
                report['kcp_auth_confirmee']=False  # ACK transport is NOT an auth acceptance
                report['video_demarre']=bool(preview.image())
                return report
            if report['kcp_auth_push_envoyes']:
                if report['kcp_auth_ack_recus'] or report['kcp_auth_reponses_push_recues']:
                    return {**report,'etat':'auth_kcp_reponse_authentifiee'}
                return {**report,'etat':'auth_kcp_envoyee_sans_confirmation'}
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



class C9PreviewProbeB139(C9MediaProbeB138):
    """B138 KCP reassembly plus C5L decoder input on HEVC channel 1.

    All frames are held in RAM; only aggregate counters and JPEG via the
    authenticated HA camera entity are exposed.
    """
    def __init__(self,preview):
        super().__init__()
        self.preview=preview
        self.fed_rtp=0

    def accept(self,conv:int,sn:int,frg:int,plain:bytes)->int:
        if conv not in self._rx or not isinstance(plain,bytes):
            raise ValueError('canal_media_invalide')
        self._observed[conv]+=1
        completed=self._rx[conv].accept(sn,frg,plain)
        for record in completed:
            if len(record)>128*1024:
                self._record_too_large+=1
                continue
            packet=extract_rtp(record) if conv==1 else None
            if packet is not None:
                self.fed_rtp+=1
                self.preview.feed(record)
            if self._samples[conv]>=2048:
                continue
            self._samples[conv]+=1
            if record.startswith((b'\x00\x00\x00\x01',b'\x00\x00\x01')):
                self._annexb_matches[conv]+=1
            if packet is not None:
                self._rtp_matches[conv]+=1
                self._hevc[conv].feed(record)
            elif conv!=1 and extract_rtp(record) is not None:
                self._rtp_matches[conv]+=1
            elif len(record)>=14 and record[0] in (0x80,0x90) and (record[1]&0x7f)==95:
                self._direct_rtp_matches[conv]+=1
        return self._rx[conv].next_sequence

    def summary(self)->dict:
        result=super().summary()
        result['c9_rtp_vers_decodeur_c5l']=self.fed_rtp
        return result


def lancer_direct_c9_b139(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
    confirmation_capture_personnelle,confirmation_camera_candidate,
    autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False,
    autoriser_configuration_rtc=False,autoriser_offre_lan_active=False,
    autoriser_test_ice_actif=False,autoriser_test_kcp_actif=False,
    autoriser_auth_kcp_active=False,autoriser_essai_cle_station_b134=False,
    autoriser_commandes_video_c9_b137=False,autoriser_direct_c9_b139=False,
    preview=None,stop_event=None)->dict:
    report={'diagnostic':'aosu_direct_c9_b139','etat':'autorisations_manquantes',
      'video_demarre':False,'secrets_retournes':False,'identifiants_retournes':False,
      'captures_rejouees':False,'commandes_ptz_envoyees':0}
    if not all(x is True for x in (confirmation_capture_personnelle,confirmation_camera_candidate,
            autoriser_configuration_rtc,autoriser_offre_lan_active,autoriser_test_ice_actif,
            autoriser_test_kcp_actif,autoriser_auth_kcp_active,autoriser_essai_cle_station_b134,
            autoriser_commandes_video_c9_b137,autoriser_direct_c9_b139)):
        return report
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    if preview is None or stop_event is None or not preview._opened:
        return {**report,'etat':'decodeur_non_prepare'}
    pre=audit_profil_demarrage_c9_b137(coordinator,config_dir=config_dir,
      nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
      confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
      autoriser_reconstitution_oem=autoriser_reconstitution_oem,
      confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    if pre.get('profil_c9_reconstructible') is not True:
        return {**report,'etat':'profil_c9_non_reconstructible'}
    try:
        old_auth,station_id,camera_id,devices,commands=_prepare_profile(
          coordinator,config_dir,nom_capture,ip_station)
    except (ValueError,OSError,TypeError,KeyError,IndexError,UnicodeError):
        return {**report,'etat':'profil_c9_non_reconstructible'}
    if stop_event.is_set():return {**report,'etat':'interrompu_avant_session'}
    def new_session(rtc,client,sid,cid):
        if stop_event.is_set():raise ValueError('session_annulee')
        if sid!=station_id or cid!=camera_id:
            raise ValueError('auth_schema_identites_non_conforme')
        current_auth,current_sid,current_cid,current_devices,current_commands=_prepare_profile(
            coordinator,config_dir,nom_capture,ip_station)
        if current_sid!=sid or current_cid!=cid or current_commands!=commands:
            raise ValueError('inventaire_camera_modifie')
        checks,auth=_new_auth_with_h1l_key(current_auth,sid,cid,current_devices,rtc)
        if auth is None:
            if not checks.get('auth_mot_de_passe_rtc_present'):
                raise ValueError('auth_rtc_password_absent')
            raise ValueError('auth_rtc_cle_station_absente')
        return lambda ip,key,offer,candidate,udp:_session_kcp_b139(
           ip,key,offer,candidate,udp,auth,current_commands,preview,stop_event)
    result=essai_negociation_lan_c9_b125(coordinator,config_dir=config_dir,
      nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
      confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
      autoriser_reconstitution_oem=autoriser_reconstitution_oem,
      confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
      autoriser_configuration_rtc=True,autoriser_offre_lan_active=True,
      session_context_factory=new_session)
    result.update({'diagnostic':'aosu_direct_c9_b139',
      'video_demarre':bool(preview.image()),'captures_rejouees':False,
      'secrets_retournes':False,'identifiants_retournes':False,
      'commandes_ptz_envoyees':0})
    return result
