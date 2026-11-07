"""Strictly opt-in Tuya OEM MQTT connect-and-subscribe *probe* (no offer).

Uses a fresh in-memory UID session and a fresh in-memory C5L RTC media
bootstrap. Does NOT issue HTTP calls, ask for a password, publish a message,
create a video session, or command any camera. No identities, MQTT credentials,
topic, device IDs, or exceptions are exported into HA diagnostics.

Credential algorithm reference:
https://github.com/roquerodrigo/tuya-ipc-p2p-sdk (MIT)
https://github.com/thekoma/aventproxy/blob/main/WHITEPAPER.md
Neither reference has been confirmed against AOSU C5L specifically.
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .oem_preflight_b7 import APKIdentity, TuyaSigner
from .tuya_uid_gateway import TuyaAuthSession
from .tuya_media_bootstrap import PrivateMediaBootstrap

_BROKER = 'm1.tuyaeu.com'
_PORT = 8883
_TIMEOUT_SECONDS = 8
_LOCK = threading.Lock()
_NEXT_ALLOWED: dict[int,float] = {}


def _md5(value: str) -> str:
    return hashlib.md5(value.encode('utf-8'), usedforsecurity=False).hexdigest()


@dataclass(repr=False)
class _MqttIdentity:
    client_id: str = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)
    topic: str = field(repr=False)
    def __repr__(self):
        return '<_MqttIdentity redacted>'


def _identity(identity: APKIdentity, signer: TuyaSigner, session: TuyaAuthSession,
              install_id: str, device_id: str) -> _MqttIdentity:
    """Derive the *candidate* mobile SDK MQTT identity, never export it."""
    for name, v in (('sid',session.sid),('ecode',session.ecode),('uid',session.uid),
                    ('install_id',install_id),('device_id',device_id)):
        if not isinstance(v,str) or not v or len(v)>256 or '\x00' in v:
            raise ValueError('invalid '+name)
    composite=signer.material()
    if not isinstance(composite,str) or len(composite)<100:
        raise ValueError('missing composite key')
    # An independent fingerprint avoids knocking the vendor phone app off the
    # broker by connecting with an identical MQTT client ID.
    ha_fingerprint=hashlib.sha256(('smart-aosu-ha:'+install_id).encode()).hexdigest()[:32]
    client_id=f'{identity.package}_mb_{ha_fingerprint}_{_md5(session.uid+"sdkfasodifca")}_DEFAULT'
    username=f'p1000018_v1_{identity.app_id}_{signer.channel_key()}_mb_{session.sid}'
    username+=_md5(_md5(identity.app_id)+session.ecode)[16:32]
    password=_md5(_md5(composite)+session.ecode)[8:24]
    # A camera-scoped inbound topic used by the independent AES/KCP SDK.
    # Subscription does not start the camera or send an offer.
    topic=f'smart/mb/in/{device_id}'
    if any(c in topic for c in ('#','+','\x00','\r','\n')):
        raise ValueError('invalid device topic')
    return _MqttIdentity(client_id,username,password,topic)


def _u16_string(value: str) -> bytes:
    raw=value.encode('utf-8')
    if not raw or len(raw)>65535:
        raise ValueError('mqtt length limit')
    return struct.pack('!H',len(raw))+raw


def _packet_remaining_length(length:int)->bytes:
    """MQTT variable length, max four bytes."""
    if length<0 or length>268435455:
        raise ValueError('invalid MQTT length')
    result=bytearray()
    while True:
        d=length%128
        length//=128
        result.append(d | (128 if length else 0))
        if not length: break
    return bytes(result)


def _mqtt_connect_packet(auth:_MqttIdentity)->bytes:
    protocol=_u16_string('MQTT') + bytes([4,0xC2]) + struct.pack('!H',30)
    payload=_u16_string(auth.client_id)+_u16_string(auth.username)+_u16_string(auth.password)
    body=protocol+payload
    return bytes([0x10])+_packet_remaining_length(len(body))+body


def _mqtt_subscribe_packet(topic:str)->bytes:
    body=struct.pack('!H',1)+_u16_string(topic)+bytes([1])
    return bytes([0x82])+_packet_remaining_length(len(body))+body


def _recv_exact(sock:Any,n:int)->bytes:
    if n<0 or n>32:raise ValueError('invalid response length')
    data=b''
    while len(data)<n:
        fragment=sock.recv(n-len(data))
        if not fragment:raise EOFError('mqtt closed before response')
        data+=fragment
    return data


def _read_packet(sock:Any)->tuple[int,bytes]:
    header=_recv_exact(sock,1)[0]
    shift=0
    length=0
    for _ in range(4):
        octet=_recv_exact(sock,1)[0]
        length+=(octet&127)<<shift
        if not octet&128:break
        shift+=7
    else:raise ValueError('invalid mqtt length encoding')
    if length>4096:raise ValueError('oversize MQTT response')
    return header,_recv_exact(sock,length)


def _tls_probe(auth:_MqttIdentity)->dict[str,object]:
    """Exactly one TLS connection, one MQTT CONNECT + one SUBSCRIBE, DISCONNECT."""
    result={'connexion_tls_validee':False,'connack_accepte':False,
            'abonnement_signalisation_accepte':False,'mqtt_messages_publies':0,
            'mqtt_commandes_camera':0,'mqtt_messages_lus':0}
    context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # Maintain strict certificate and hostname validation; never fall back to
    # an unverified connection to work around a mismatched server certificate.
    context.check_hostname=True
    context.verify_mode=ssl.CERT_REQUIRED
    try:
        with socket.create_connection((_BROKER,_PORT),timeout=_TIMEOUT_SECONDS) as tcp:
            with context.wrap_socket(tcp,server_hostname=_BROKER) as conn:
                conn.settimeout(_TIMEOUT_SECONDS)
                result['connexion_tls_validee']=True
                try:
                    conn.sendall(_mqtt_connect_packet(auth))
                    t,p=_read_packet(conn)
                    if t!=0x20 or len(p)!=2 or p[0]&0xFE:
                        result['etat']='connack_format_non_conforme'
                        return result
                    code=p[1]
                    if code!=0:
                        # Only fixed MQTT 3.1.1 return codes can leave the service.
                        result['categorie_connack']={1:'protocole',2:'identifiant_client',
                            3:'service_indisponible',4:'identifiants_mqtt',
                            5:'autorisation'}.get(code,'inattendu')
                        result['etat']='broker_connack_refus'
                        return result
                    result['connack_accepte']=True
                    conn.sendall(_mqtt_subscribe_packet(auth.topic))
                    t,p=_read_packet(conn)
                    if t!=0x90 or len(p)!=3 or p[:2]!=b'\x00\x01':
                        result['etat']='suback_non_conforme'
                        return result
                    if p[2]==0x80:
                        result['etat']='abonnement_refuse'
                        return result
                    if p[2] not in (0,1,2):
                        result['etat']='abonnement_code_inattendu'
                        return result
                    result['abonnement_signalisation_accepte']=True
                    result['etat']='mqtt_connecte_abonne_aucune_offre_envoyee'
                    return result
                finally:
                    try:conn.sendall(b'\xE0\x00')
                    except (OSError,ssl.SSLError):pass
    except ssl.SSLCertVerificationError:
        result['etat']='certificat_tls_non_valide'
    except (TimeoutError, socket.timeout):
        result['etat']='connexion_mqtt_timeout'
    except (socket.gaierror,ConnectionError,OSError,ssl.SSLError):
        result['etat']='connexion_mqtt_reseau_echec'
    except (ValueError,EOFError):
        result['etat']='reponse_mqtt_inattendue'
    return result


def run_tuya_mqtt_signalisation(client:Any,identity:APKIdentity,signer:TuyaSigner,
                                 session:TuyaAuthSession,install_id:str,
                                 media:PrivateMediaBootstrap)->dict[str,object]:
    """Session and media credentials already available in memory only."""
    report={'diagnostic':'aosu_tuya_mqtt_signalisation_b17',
            'source_mqtt':'reference_tuya_non_validee_C5L',
            'courtier_europe_m1':True,'port_tls':8883,
            'appel_http_supplementaire':0,'mot_de_passe_AOSU_envoye':False,
            'offre_sdp_envoyee':False,'commande_camera':0,
            'session_video_creee':False,'secrets_retournes':False,
            'mqtt_messages_publies':0,
            'connexion_tls_validee':False,'connack_accepte':False,
            'abonnement_signalisation_accepte':False}
    if not _LOCK.acquire(blocking=False):return {**report,'etat':'sonde_mqtt_deja_en_cours'}
    try:
        now=time.monotonic()
        key=id(client)
        if now<_NEXT_ALLOWED.get(key,0):return {**report,'etat':'limite_test_mqtt_dix_minutes'}
        if not isinstance(session,TuyaAuthSession) or now-session.acquired_at>1200:
            return {**report,'etat':'session_uid_absente_ou_expiree'}
        if not isinstance(media,PrivateMediaBootstrap) or not media.is_fresh():
            return {**report,'etat':'configuration_rtc_absente_ou_expiree'}
        if media.owner_uid!=session.uid:
            return {**report,'etat':'uid_et_rtc_incoherents'}
        try:
            credentials=_identity(identity,signer,session,install_id,media.device_id)
        except (TypeError,ValueError,AttributeError):
            return {**report,'etat':'construction_mqtt_invalide'}
        # Rate-limit *before* attempting a broker connection; no retries.
        _NEXT_ALLOWED[key]=now+600
        try:
            outcome=_tls_probe(credentials)
        except Exception:
            outcome={'etat':'erreur_mqtt_sans_details'}
        return {**report,**outcome}
    finally:
        _LOCK.release()
