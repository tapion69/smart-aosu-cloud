"""Manual, one-shot OEM MQTT AES/KCP offer/answer diagnostic (b18).

Active test: sends one encrypted P2P offer, then one encrypted disconnect.
Never starts relay, media, camera recording, PTZ or persistent background tasks.
No sensitive MQTT material, SDP, addresses, camera IDs or error strings leave RAM.

Wire format adapted to Tuya IPC P2P SDK (MIT):
https://github.com/roquerodrigo/tuya-ipc-p2p-sdk
AOSU C5L interoperability is still experimental, and must be verified live.
"""
from __future__ import annotations

import json
import threading
import secrets
import socket
import ssl
import struct
import time
import zlib
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .tuya_media_bootstrap import PrivateMediaBootstrap
from .tuya_ice_b85 import ControlledIceB85
from .tuya_relay_handshake import probe_relay_handshake
from .tuya_mqtt_signaling import (
    _BROKER, _PORT, _identity, _mqtt_connect_packet, _mqtt_subscribe_packet,
    _packet_remaining_length, _recv_exact, _u16_string,
)

_MAX_PACKET=32768
_WAIT_ANSWER_SECONDS=9
_WAIT_ANSWER_LIVE_SECONDS=20  # User-initiated direct; reference SDK waits 20 s for SDP.
_OFFER_LOCK=threading.Lock()
_OFFER_NEXT_ALLOWED:dict[int,float]={}


def _pkcs7(data:bytes)->bytes:
    n=16-len(data)%16
    return data+bytes([n])*n


def _encrypt(key:bytes,plain:bytes)->bytes:
    cipher=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
    return cipher.update(_pkcs7(plain))+cipher.finalize()


def _decrypt(key:bytes,encrypted:bytes)->bytes:
    if not encrypted or len(encrypted)%16:raise ValueError('cipher blocks')
    decoder=Cipher(algorithms.AES(key),modes.ECB()).decryptor()
    padded=decoder.update(encrypted)+decoder.finalize()
    n=padded[-1]
    if not 1<=n<=16 or padded[-n:]!=bytes([n])*n:raise ValueError('padding')
    return padded[:-n]


def _signal_frame(key:bytes,sequence:int,source:bytes,protocol:int,data:dict)->bytes:
    raw=json.dumps({'data':data,'protocol':protocol,'t':int(time.time())},
                   ensure_ascii=False,separators=(',',':')).encode('utf-8')
    tail=struct.pack('!I',sequence)+source+_encrypt(key,raw)
    return b'2.2'+struct.pack('!I',zlib.crc32(tail))+tail


def _decode_signal(key:bytes,blob:bytes)->tuple[int,dict]:
    if len(blob)<31 or len(blob)>_MAX_PACKET or blob[:3]!=b'2.2':
        raise ValueError('bad envelope')
    if zlib.crc32(blob[7:])!=int.from_bytes(blob[3:7],'big'):
        raise ValueError('bad checksum')
    obj=json.loads(_decrypt(key,blob[15:]))
    if not isinstance(obj,dict) or not isinstance(obj.get('data'),dict):
        raise ValueError('bad json')
    return obj.get('protocol'),obj['data']


def _signal_protocol_class(protocol: object) -> str:
    """Fixed labels only, never expose MQTT payload or vendor identifiers.

    Protocol 22 is the response family for the sigQry that this same client
    sends immediately before its protocol-302 offer. It is not a SDP answer.
    """
    if type(protocol) is int and protocol == 22:
        return 'sigqry'
    if type(protocol) is int and protocol == 302:
        return 'offer_answer'
    return 'other'


def _mqtt_publish(topic:str,payload:bytes,packet_id:int)->bytes:
    if len(payload)>_MAX_PACKET:raise ValueError('oversized signal')
    body=_u16_string(topic)+struct.pack('!H',packet_id)+payload
    return b'\x32'+_packet_remaining_length(len(body))+body


def _mqtt_read(sock:Any)->tuple[int,bytes]:
    header=_recv_exact(sock,1)[0]
    length=0
    for shift in range(0,28,7):
        octet=_recv_exact(sock,1)[0]
        length+=(octet&127)<<shift
        if not octet&128:break
    else:raise ValueError('mqtt remaining length malformed')
    if length>_MAX_PACKET:raise ValueError('mqtt oversized')
    # _recv_exact is deliberately capped at 32 for the older MQTT probe;
    # use bounded chunks for frames that contain encrypted SDP.
    body=bytearray()
    while len(body)<length:
        chunk=sock.recv(min(4096,length-len(body)))
        if not chunk:raise EOFError('mqtt closed')
        body.extend(chunk)
    return header,bytes(body)


def _incoming_pub(header:int,body:bytes)->tuple[str,bytes,int|None]:
    if len(body)<2:raise ValueError('short publish')
    tlen=int.from_bytes(body[:2],'big')
    if tlen>512 or len(body)<2+tlen:raise ValueError('bad topic')
    topic=body[2:2+tlen].decode('utf-8')
    pos=2+tlen
    packet_id=None
    if (header>>1)&3:
        if len(body)<pos+2:raise ValueError('short qos id')
        packet_id=int.from_bytes(body[pos:pos+2],'big');pos+=2
    return topic,body[pos:],packet_id


def _media_payload(media:PrivateMediaBootstrap, uid:str, *, use_moto_id:bool=False)->tuple[bytes,dict]:
    local=media.local_key.encode('utf-8')
    if len(local) not in (16,24,32):raise ValueError('local key length unsupported')
    if not media.is_fresh():raise ValueError('rtc expired')
    if not isinstance(media.ice_servers,list) or len(media.ice_servers)>30:
        raise ValueError('missing ice servers')
    # Per Tuya SDK, relay rendezvous id is not the expiry-bound server id.
    rendezvous=f'{media.device_id}{int(time.time())}{secrets.token_hex(4)}'
    tcp=dict(media.relay);tcp['sessionId']=rendezvous
    trace=f'{media.trace_id}_{media.device_id}_{int(time.time()*1000)}'
    moto=(media.moto_id if use_moto_id and
          isinstance(media.moto_id,str) and 1<=len(media.moto_id)<=128 else '')
    header={
        'type':'offer','from':uid,'to':media.device_id,
        'sessionid':media.session_id,'moto_id':moto,'path':'mqtt',
        'trace_id':trace,'is_pre':0,'p2p_skill':1635,'security_level':3,
    }
    offer={'header':header,'msg':{'sdp':media.sdp_offer,'preconnect':True,
        'token':media.ice_servers,'tcp_token':tcp,'log':media.log_config}}
    return local,offer


def _disconnect(uid:str,media:PrivateMediaBootstrap,*, moto_id:str='')->dict:
    return {'header':{'type':'disconnect','from':uid,'to':media.device_id,
        'sessionid':media.session_id,'moto_id':moto_id,'path':'mqtt'},
        'msg':{'close_reason':4,'close_reason_local':0}}


def _send_once(sock:Any,key:bytes,topic:str,source:bytes,seq:int,
               packet_id:int,protocol:int,body:dict)->None:
    frame=_signal_frame(key,seq,source,protocol,body)
    sock.sendall(_mqtt_publish(topic,frame,packet_id))


def _observe_mqtt_while_video(sock, *, auth_topic: str, key: bytes,
                              observer, done: threading.Event, video_stop) -> None:
    """Read the existing signal channel and keep its MQTT 30s lease alive.

    Keepalive is a protocol-level PINGREQ (not a device command).  No new
    connection, subscription, video offer or Tuya DP.  The associated relay
    remains under the user's explicit Live/Stop control.
    """
    observer.monitoring(True)
    # CONNECT announces 30s MQTT keepalive; send PINGREQ within 15s even
    # when no incoming PUBLISH messages arrive. PINGRESP is consumed below.
    last_outbound = time.monotonic()
    try:
        sock.settimeout(1.0)
        while not done.is_set() and not video_stop.is_set():
            if time.monotonic() - last_outbound >= 12.0:
                try:
                    sock.sendall(b'\xc0\x00')  # MQTT PINGREQ, no camera command
                    last_outbound = time.monotonic()
                except (OSError, ssl.SSLError, ConnectionError):
                    if not done.is_set() and not video_stop.is_set():
                        observer.failure()
                    break
            try:
                packet_type, body = _mqtt_read(sock)
            except (TimeoutError, socket.timeout):
                continue
            except (OSError, ssl.SSLError, EOFError, ValueError, ConnectionError):
                if not done.is_set() and not video_stop.is_set():
                    observer.failure()
                break
            if packet_type == 0xD0:  # MQTT PINGRESP: broker still alive
                continue
            if packet_type & 0xF0 != 0x30:
                continue
            try:
                topic, raw, packet_id = _incoming_pub(packet_type, body)
                if packet_id is not None:
                    sock.sendall(b'\x40\x02' + struct.pack('!H', packet_id))
                    last_outbound = time.monotonic()
                    observer.puback()
                if topic != auth_topic:
                    observer.packet(own_topic=False)
                    continue
                try:
                    protocol, data = _decode_signal(key, raw)
                    header = data.get('header')
                    kind = header.get('type') if isinstance(header, dict) else None
                    # Do not retain decoded JSON: inspect only fixed PTZ tokens.
                    wire = json.dumps(data, separators=(',', ':'), ensure_ascii=False)
                    observer.packet(own_topic=True, protocol=protocol,
                        header_type=kind,
                        ptz_control='ptz_control' in wire,
                        ptz_stop='ptz_stop' in wire)
                    if kind == 'disconnect':
                        msg = data.get('msg')
                        if isinstance(msg, dict):
                            observer.remote_disconnect(msg.get('close_reason'),
                                                       msg.get('close_reason_local'))
                except (ValueError, KeyError, TypeError, UnicodeError,
                        json.JSONDecodeError):
                    observer.packet(own_topic=True, decode_error=True)
            except (ValueError, UnicodeError, OSError, ssl.SSLError):
                observer.failure()
    finally:
        observer.monitoring(False)


def _probe(auth:Any,uid:str,media:PrivateMediaBootstrap, *, tester_relais_tcp:bool=False, tester_kcp:bool=False,tester_media:bool=False,
              local_capture_directory:str|None=None,live_preview=None,
              use_moto_id:bool=False)->dict[str,object]:
    """One connection, one sig-query, one offer, bounded read, best-effort disconnect."""
    result={
        'connexion_tls_validee':False,'connack_accepte':False,
        'abonnement_signalisation_accepte':False,'signalisation_chiffree_preparee':False,
        'offre_sdp_envoyee':False,'ack_offre_mqtt':False,'reponse_sdp_recue':False,
        'reponse_sdp_aes_kcp':False,'reponse_ice_presente':False,
        'mqtt_messages_lus':0,'mqtt_messages_publies':0,'deconnexion_signalee':False,
        'commande_ptz':0,'session_video_creee':False,'secrets_retournes':False,
    }
    try:
        key,offer=_media_payload(media,uid,use_moto_id=use_moto_id)
        result['signalisation_chiffree_preparee']=True
        result['moto_id_applique']=bool(offer['header']['moto_id'])
    except (ValueError,AttributeError,TypeError):
        result['etat']='rtc_ou_cle_locale_incompatible'
        return result
    ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.verify_mode=ssl.CERT_REQUIRED;ctx.check_hostname=True
    pubtopic=f'smart/mb/out/{media.device_id}'
    # All topics are private; never return them in a response.
    source=secrets.token_bytes(4)
    sent_offer=False
    ice=None
    ice_candidate=None
    interactive_ice=(live_preview is not None and tester_media and tester_kcp)
    # B89: only fixed, non-sensitive signaling counters; never return SDP, UID,
    # MQTT topics, network addresses, tokens, or server exception strings.
    diag={
        'fenetre_reponse_sdp_s': (_WAIT_ANSWER_LIVE_SECONDS if interactive_ice
                                  else _WAIT_ANSWER_SECONDS),
        'etape': 'initialisation',
        'tls_connecte': False,
        'connack_accepte': False,
        'abonnement_confirme': False,
        'offre_envoyee': False,
        'candidat_ice_publie': False,
        'puback_offre': False,
        'messages_reception_total': 0,
        'messages_sur_topic_session': 0,
        'messages_hors_topic_session': 0,
        'reponses_session_incorrecte': 0,
        'reponses_sigqry': 0,  # response to our own protocol-22 query (not SDP)
        'reponses_protocole_inattendu': 0,
        'messages_302_format_invalide': 0,
        'messages_302_autres_types': 0,
        'messages_indecodables': 0,
        'messages_candidats': 0,
        'messages_answer': 0,
        'messages_disconnect': 0,
        'fin_attente': 'non_lancee',
    }
    result['signalisation_b89'] = diag
    try:
        with socket.create_connection((_BROKER,_PORT),timeout=8) as tcp:
            with ctx.wrap_socket(tcp,server_hostname=_BROKER) as sock:
                sock.settimeout(8)
                result['connexion_tls_validee']=True
                diag['etape']='tls_connecte'
                diag['tls_connecte']=True
                if live_preview is not None and hasattr(live_preview, 'mark_phase_b93'): live_preview.mark_phase_b93('mqtt_tls_connecte')
                try:
                    sock.sendall(_mqtt_connect_packet(auth))
                    t,p=_mqtt_read(sock)
                    if t!=0x20 or len(p)!=2 or p[1]!=0:
                        result['etat']='connack_non_accepte';return result
                    result['connack_accepte']=True
                    diag['etape']='mqtt_connecte'
                    diag['connack_accepte']=True
                    sock.sendall(_mqtt_subscribe_packet(auth.topic))
                    t,p=_mqtt_read(sock)
                    if t!=0x90 or len(p)!=3 or p[:2]!=b'\x00\x01' or p[2]==0x80:
                        result['etat']='abonnement_non_accepte';return result
                    result['abonnement_signalisation_accepte']=True
                    diag['etape']='abonnement_confirme'
                    diag['abonnement_confirme']=True
                    _send_once(sock,key,pubtopic,source,1,10,22,{'reqType':'sigQry'})
                    result['mqtt_messages_publies']=1
                    _send_once(sock,key,pubtopic,source,2,11,302,offer)
                    sent_offer=True
                    result['offre_sdp_envoyee']=True
                    diag['etape']='offre_envoyee'
                    diag['offre_envoyee']=True
                    if live_preview is not None and hasattr(live_preview, 'mark_phase_b93'): live_preview.mark_phase_b93('offre_mqtt_envoyee')
                    result['mqtt_messages_publies']=2
                    # New b85 ICE controlled-role responder; never active in
                    # manual read-only/signaling-only diagnostics.
                    if interactive_ice:
                        ice=ControlledIceB85(media.ice_password)
                        ice_candidate=ice.start()
                        if ice_candidate:
                            candidate_msg={
                                'header':{
                                    'type':'candidate','from':uid,'to':media.device_id,
                                    'sessionid':media.session_id,
                                    'moto_id':offer['header']['moto_id'],
                                    'path':'mqtt'},
                                'msg':{'candidate':ice_candidate},
                            }
                            _send_once(sock,key,pubtopic,source,3,12,302,candidate_msg)
                            result['mqtt_messages_publies']+=1
                            result['candidat_ice_b85_publie']=True
                            diag['candidat_ice_publie']=True
                        else:
                            result['candidat_ice_b85_publie']=False
                    deadline=time.monotonic()+diag['fenetre_reponse_sdp_s']
                    diag['etape']='attente_sdp'
                    diag['fin_attente']='en_cours'
                    count=0
                    while (time.monotonic()<deadline and count<64
                           and not (live_preview is not None
                                    and live_preview._stop.is_set())):
                        count+=1
                        sock.settimeout(max(0.2,min(2.0,deadline-time.monotonic())))
                        try:
                            t,p=_mqtt_read(sock)
                        except (TimeoutError,socket.timeout):continue
                        except (EOFError,ConnectionError,OSError):
                            diag['fin_attente']='socket_fermee_ou_erreur'
                            break
                        if t==0x40 and len(p)==2:
                            if int.from_bytes(p,'big')==11:
                                result['ack_offre_mqtt']=True
                                diag['puback_offre']=True
                            continue
                        if t&0xF0!=0x30:continue
                        result['mqtt_messages_lus']+=1
                        diag['messages_reception_total']+=1
                        try:
                            topic,raw,pid=_incoming_pub(t,p)
                            if pid is not None:sock.sendall(b'\x40\x02'+struct.pack('!H',pid))
                            if topic!=auth.topic:
                                diag['messages_hors_topic_session']+=1
                                continue
                            diag['messages_sur_topic_session']+=1
                            protocol,data=_decode_signal(key,raw)
                            protocol_class = _signal_protocol_class(protocol)
                            if protocol_class == 'sigqry':
                                # Expected response family for our sigQry
                                # request, not evidence of an incompatible
                                # media protocol or of a successful offer.
                                diag['reponses_sigqry']+=1
                                continue
                            if protocol_class != 'offer_answer':
                                diag['reponses_protocole_inattendu']+=1
                                continue
                            header=data.get('header');msg=data.get('msg')
                            if not isinstance(header,dict) or not isinstance(msg,dict):
                                diag['messages_302_format_invalide']+=1
                                continue
                            if header.get('sessionid')!=media.session_id:
                                diag['reponses_session_incorrecte']+=1
                                continue
                            typ=header.get('type')
                            if typ=='answer' and isinstance(msg.get('sdp'),str):
                                sdp=msg['sdp']
                                result['reponse_sdp_recue']=True
                                diag['messages_answer']+=1
                                if live_preview is not None and hasattr(live_preview, 'mark_phase_b93'): live_preview.mark_phase_b93('reponse_sdp_recue')
                                diag['fin_attente']='answer_recue'
                                diag['etape']='sdp_recue'
                                result['reponse_sdp_aes_kcp']='AES/KCP' in sdp
                                result['reponse_ice_presente']='a=ice-ufrag:' in sdp and 'a=ice-pwd:' in sdp
                                result['etat']='reponse_sdp_recue_sans_video'
                                if tester_relais_tcp and result['reponse_sdp_aes_kcp'] and result['reponse_ice_presente']:
                                    observer = getattr(live_preview, 'ptz_mqtt_observer', None)
                                    watch = None
                                    watch_end = None
                                    if tester_media and observer is not None and hasattr(live_preview, '_stop'):
                                        # The ONLY reader of the MQTT socket during the
                                        # blocking KCP video relay. No second CONNECT.
                                        watch_end = threading.Event()
                                        watch = threading.Thread(
                                            target=_observe_mqtt_while_video,
                                            kwargs={'sock': sock, 'auth_topic': auth.topic,
                                                    'key': key, 'observer': observer,
                                                    'done': watch_end,
                                                    'video_stop': live_preview._stop},
                                            name='aosu-mqtt-existing-session', daemon=True)
                                        watch.start()
                                    try:
                                        result['relais_tcp']=probe_relay_handshake(offer['msg']['tcp_token'],uid,media.device_id,
                                            media=media if tester_kcp else None,offer=offer if tester_kcp else None,
                                            tester_kcp=tester_kcp,tester_media=tester_media,answer_sdp=sdp,
                                            local_capture_directory=local_capture_directory,live_preview=live_preview,
                                            ice_candidate=ice_candidate)
                                    finally:
                                        if watch_end is not None:
                                            watch_end.set()
                                        if watch is not None:
                                            watch.join(timeout=2.5)
                                if tester_media:
                                    r=(((result.get('relais_tcp') or {}).get('kcp') or {}).get('media_start') or {})
                                    result['commandes_demarrage_video']=r.get('commandes_controle_envoyees',0)
                                    result['session_video_creee']=bool(r.get('conversation_video_detectee'))
                                break
                            if typ=='disconnect':
                                diag['messages_disconnect']+=1
                                diag['fin_attente']='deconnexion_distante'
                                result['refus_p2p_explicite']=True
                                result['etat']='deconnexion_camera_recue'
                                break
                            if typ=='candidate':
                                result['candidats_distants_recus']=True
                                diag['messages_candidats']+=1
                            elif typ=='answer':
                                # Missing/nonstring SDP. Never expose it.
                                diag['messages_302_format_invalide']+=1
                            else:
                                diag['messages_302_autres_types']+=1
                        except (UnicodeError,ValueError,TypeError,KeyError,json.JSONDecodeError):
                            result['trame_mqtt_indecodable']=True
                            diag['messages_indecodables']+=1
                            continue
                    if 'etat' not in result:
                        if live_preview is not None and live_preview._stop.is_set():
                            result['etat']='arret_demande_avant_reponse_sdp'
                            diag['fin_attente']='annulee_par_utilisateur'
                        else:
                            result['etat']='offre_envoyee_sans_reponse_sdp'
                            if diag['fin_attente']=='en_cours':
                                diag['fin_attente']=('limite_messages'
                                    if count>=64 else 'delai_sdp_depasse')
                    diag['etape']='attente_terminee'
                finally:
                    if ice is not None:
                        result['negociation_ice_b85']=ice.snapshot()
                        ice.close()
                    if sent_offer:
                        try:
                            # Best-effort release: a published offer may reserve the camera.
                            _send_once(sock,key,pubtopic,source,4 if ice_candidate else 3,
                                       13 if ice_candidate else 12,302,_disconnect(
                                           uid,media,moto_id=offer['header']['moto_id']))
                            result['mqtt_messages_publies']+=1
                            result['deconnexion_signalee']=True
                        except (OSError,ValueError,ssl.SSLError):pass
                    try:sock.sendall(b'\xe0\x00')
                    except (OSError,ssl.SSLError):pass
    except ssl.SSLCertVerificationError:result['etat']='certificat_tls_non_valide'
    except (TimeoutError,socket.timeout):result['etat']='mqtt_timeout'
    except (OSError,ssl.SSLError,ConnectionError):result['etat']='mqtt_reseau_echec'
    except (ValueError,TypeError,EOFError):result['etat']='mqtt_trame_inattendue'
    return result


def run_tuya_mqtt_offer(client:Any, identity:Any, signer:Any, session:Any,
                        install_id:str,media:PrivateMediaBootstrap, *, tester_relais_tcp:bool=False, tester_kcp:bool=False,tester_media:bool=False,
              local_capture_directory:str|None=None,live_preview=None,interactive_live:bool=False,
              use_standalone_c9c_moto_id:bool=False)->dict[str,object]:
    """Call only from the explicitly confirmed b18 inventory action."""
    outcome={'diagnostic':'aosu_tuya_mqtt_offer_b18','offre_sdp_envoyee':False,
             'session_video_creee':False,'secrets_retournes':False,
             'commande_camera':0,'mot_de_passe_AOSU_envoye':False}
    interactive_live = (interactive_live is True and live_preview is not None
                        and tester_relais_tcp and tester_kcp and tester_media)
    if not _OFFER_LOCK.acquire(blocking=False):
        return {**outcome,'etat':'offre_deja_en_cours'}
    try:
        now=time.monotonic()
        if not interactive_live and now < _OFFER_NEXT_ALLOWED.get(id(client),0):
            return {**outcome,'etat':'limite_offre_trente_minutes'}
        if not media.is_fresh() or media.owner_uid!=session.uid:
            return {**outcome,'etat':'session_ou_rtc_expire'}
        try:
            credentials=_identity(identity,signer,session,install_id,media.device_id)
        except (TypeError,ValueError,AttributeError):
            return {**outcome,'etat':'identifiants_mqtt_indisponibles'}
        # Conservative cooldown for manual diagnostics only. Explicit user Play
        # uses a separate controller with bounded retry after real failures.
        if not interactive_live:
            _OFFER_NEXT_ALLOWED[id(client)]=now+1800
        return {**outcome,**_probe(credentials,session.uid,media,tester_relais_tcp=tester_relais_tcp,tester_kcp=tester_kcp,tester_media=tester_media,
             local_capture_directory=local_capture_directory,live_preview=live_preview,
             use_moto_id=(interactive_live and use_standalone_c9c_moto_id is True))}
    finally:
        _OFFER_LOCK.release()
