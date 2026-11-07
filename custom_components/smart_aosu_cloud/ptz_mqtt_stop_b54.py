"""b54 — one-shot experimental MQTT STOP for owner-selected AOSU C5L.

NO direction or video messages. A MQTT PUBACK means transport receipt ONLY;
never infer a physical stop. Protocol=4 and abilityId=116 remain hypotheses
for this device despite Tuya model/SDK support. Opt-in requires 4 booleans.

No retries, bounded wait, no secrets, device IDs, topics or raw payload in result.
"""
from __future__ import annotations
import json
import secrets
import struct
import threading
import time
import zlib
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

_LOCK = threading.Lock()
_LAST: dict[int,float] = {}
_INTERVAL = 600


def _key_from_row(row:Any)->bytes|None:
    """Bounded, fail-closed key extraction from unique C5L OEM descriptor."""
    from .ptz_sdk_sources_b47 import _walk
    values=set()
    for node in _walk(row):
        if isinstance(node,dict) and 'localKey' in node:
            value=node.get('localKey')
            if not isinstance(value,str):return None
            try: key=value.encode('ascii')
            except UnicodeEncodeError:return None
            if len(key) != 16 or any(b<33 or b>126 for b in key):return None
            values.add(key)
    if len(values)!=1:return None
    return next(iter(values))


def _frame_stop_pv22(topic_id:str, local_key:bytes, *, protocol:int,
                     o:int,s:int,t:int)->bytes:
    """Experimental SDK-derived frame; not a proven C5L test vector."""
    if not isinstance(topic_id,str) or not topic_id or len(topic_id)>128:
        raise ValueError('invalid topic ID')
    if type(local_key) is not bytes or len(local_key)!=16:raise ValueError('invalid key')
    if type(protocol) is not int or protocol!=4:raise ValueError('invalid protocol')
    if not (1000<=o<=1000999 and s==3 and 1<=t<2**32):
        raise ValueError('invalid sequence')
    # C5L's product model labels abilityId 116 as an RW boolean ptz_stop;
    # actual physical handling has not yet been verified.
    plain=json.dumps({'data':{'116':True},'protocol':4,'t':t},
                     ensure_ascii=False,separators=(',',':')).encode('utf-8')
    p=PKCS7(128).padder(); padded=p.update(plain)+p.finalize()
    enc=Cipher(algorithms.AES(local_key),modes.ECB()).encryptor()
    ciphertext=enc.update(padded)+enc.finalize()
    body=struct.pack('!II',o,s)+ciphertext
    return topic_id.encode('utf-8') + struct.pack('!I',zlib.crc32(body)&0xffffffff)+body


def _mqtt_qos1_publish(topic:str,body:bytes,packet_id:int=2)->bytes:
    from .tuya_mqtt_signaling import _u16_string, _packet_remaining_length
    if not isinstance(topic,str) or not topic.startswith('smart/mb/out/'):
        raise ValueError('invalid outbound topic')
    if any(c in topic for c in ('#','+','\x00','\r','\n')):
        raise ValueError('wildcards')
    if type(body) is not bytes or not 16<=len(body)<=4096 or packet_id!=2:
        raise ValueError('invalid payload')
    content=_u16_string(topic)+struct.pack('!H',packet_id)+body
    return bytes([0x32])+_packet_remaining_length(len(content))+content


def _publish_once(auth, topic_id:str, frame:bytes)->dict:
    """One new MQTT TLS session; QoS1 PUBACK (not device motor ACK)."""
    import socket,ssl
    from .tuya_mqtt_signaling import (_BROKER,_PORT,_TIMEOUT_SECONDS,
                                     _mqtt_connect_packet,_mqtt_subscribe_packet,_read_packet)
    report={'tls_valide':False,'connexion_authentifiee':False,
            'abonnement_reponse_accepte':False,'publication_mqtt_tentee':False,
            'puback_broker_recu':False,'reponse_camera_ptz_validee':False,
            'messages_mqtt_publies':0}
    context=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname=True
    context.verify_mode=ssl.CERT_REQUIRED
    try:
        with socket.create_connection((_BROKER,_PORT),timeout=_TIMEOUT_SECONDS) as tcp:
            with context.wrap_socket(tcp,server_hostname=_BROKER) as sock:
                sock.settimeout(_TIMEOUT_SECONDS)
                report['tls_valide']=True
                try:
                    sock.sendall(_mqtt_connect_packet(auth))
                    kind,data=_read_packet(sock)
                    if kind!=0x20 or len(data)!=2 or data!=b'\x00\x00':
                        report['etat']='connexion_mqtt_refusee';return report
                    report['connexion_authentifiee']=True
                    sock.sendall(_mqtt_subscribe_packet(auth.topic))
                    kind,data=_read_packet(sock)
                    if kind!=0x90 or len(data)!=3 or data[:2]!=b'\x00\x01' or data[2] not in (0,1):
                        report['etat']='abonnement_mqtt_non_accepte';return report
                    report['abonnement_reponse_accepte']=True
                    msg=_mqtt_qos1_publish('smart/mb/out/'+topic_id,frame)
                    sock.sendall(msg)
                    report['publication_mqtt_tentee']=True
                    report['messages_mqtt_publies']=1
                    # QoS1 receipt from MQTT broker is not proof of camera STOP.
                    for _ in range(5):
                        kind,data=_read_packet(sock)
                        if kind==0x40 and len(data)==2 and data==b'\x00\x02':
                            report['puback_broker_recu']=True
                            report['etat']='puback_broker_pas_confirmation_camera'
                            return report
                        if kind>>4==3: # incoming MQTT PUBLISH may be unrelated
                            continue
                        report['etat']='reponse_mqtt_non_decisive';return report
                    report['etat']='puback_absent';return report
                finally:
                    try:sock.sendall(b'\xe0\x00')
                    except (OSError,ssl.SSLError):pass
    except (socket.timeout,TimeoutError):report['etat']='timeout_mqtt'
    except (OSError,ssl.SSLError,EOFError,ValueError):report['etat']='echec_mqtt_sans_details'
    return report


def test_mqtt_stop_once(coordinator: Any, *, mqtt_confirmed=False,
                        camera_confirmed=False, stop_confirmed=False,
                        mapping_experimental_confirmed=False)->dict:
    """Use only through explicit owner manual HA service call."""
    out={'diagnostic':'aosu_ptz_stop_mqtt_b54','test_experimental':True,
         'commande_direction_envoyee':False,'commandes_arret_envoyees':0,
         'messages_mqtt_publies':0,'video_modifiee':False,'appels_http':0,
         'arret_physique_valide':False,'mouvement_autorise':False,
         'publication_camera_validee':False,'identifiants_retournes':False,
         'secrets_retournes':False,'schema_dp_c5l_certifie':False,
         'format_protocole_4_experimental':True}
    if not all(flag is True for flag in (mqtt_confirmed,camera_confirmed,stop_confirmed,
                                         mapping_experimental_confirmed)):
        return {**out,'etat':'quatre_confirmations_requises'}
    live=getattr(coordinator,'live_controller',None)
    if live is not None and getattr(live,'running',False):
        return {**out,'etat':'direct_home_assistant_en_cours'}
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_sdk_sources_b47 import inspect_sdk_properties
    from .ptz_mqtt_transport_b53 import _communication_topic_id
    from .tuya_uid_gateway import TuyaAuthSession
    from .uid_token_probe import _ready_identity,_apk_preflight
    from .tuya_mqtt_signaling import _identity
    selected,why=select_c5l_oem(coordinator)
    if selected is None:return {**out,'etat':why}
    _id,row,method=selected
    out['selection_oem']=method
    if inspect_sdk_properties(row).get('pv')!='2.2':
        return {**out,'etat':'pv22_non_confirme'}
    key=_key_from_row(row)
    if key is None:return {**out,'etat':'cle_locale_invalide_ou_ambigue'}
    topic_id,why=_communication_topic_id(row)
    if topic_id is None:return {**out,'etat':why}
    session=getattr(coordinator.client,'_tuya_oem_session',None)
    if not isinstance(session,TuyaAuthSession) or not 0<=time.monotonic()-session.acquired_at<1200:
        return {**out,'etat':'session_uid_absente_ou_expiree'}
    ready=_ready_identity(coordinator.client)
    if ready is None:return {**out,'etat':'profil_oem_absent'}
    _,install_id=ready
    try:
        _,material=_apk_preflight(coordinator.client.apk_path)
        if material is None:return {**out,'etat':'ressources_oem_invalides'}
        identity,signer=material
        auth=_identity(identity,signer,session,install_id,topic_id)
    except (ValueError,TypeError,AttributeError):
        return {**out,'etat':'identite_mqtt_non_preparee'}
    guard=id(coordinator.client)
    now=time.monotonic()
    if _LAST.get(guard,0)>now:return {**out,'etat':'temporisation_dix_minutes'}
    if not _LOCK.acquire(blocking=False):return {**out,'etat':'test_deja_en_cours'}
    try:
        if _LAST.get(guard,0)>time.monotonic():return {**out,'etat':'temporisation_dix_minutes'}
        # No fallback, no retry. Random o varies per fresh session.
        _LAST[guard]=time.monotonic()+_INTERVAL
        frame=_frame_stop_pv22(topic_id,key,protocol=4,
                              o=secrets.randbelow(1000000)+1000,s=3,t=int(time.time()))
        try: result=_publish_once(auth,topic_id,frame)
        except Exception:return {**out,'etat':'erreur_mqtt_sans_details'}
        out.update(result)
        if result.get('messages_mqtt_publies')==1:
            out['commandes_arret_envoyees']=1
        return out
    finally:
        _LOCK.release()
