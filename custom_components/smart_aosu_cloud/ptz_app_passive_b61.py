"""b61 strictly passive MQTT topic comparison against the native AOSU app.

No MQTT device PUBLISH, no HTTP requests, no video/session initiation and no
PTZ commands. Subscription to candidate outbound topics may be rejected by
Tuya; an accepted SUBACK proves permission to subscribe, not device routing.
Only aggregate counters and normalized status enums leave this module.
"""
from __future__ import annotations

import socket
import ssl
import struct
import threading
import time
from typing import Any

WINDOW_SECONDS = 14.0
MIN_RETRY_SECONDS = 60.0
MAX_FRAMES = 120
_LOCK = threading.Lock()
_NEXT_ALLOWED: dict[int,float] = {}
_CHANNELS = ('retour_devId', 'sortie_devId', 'retour_communicationNode', 'sortie_communicationNode')


def _subscribe(topic: str, packet_id: int)->bytes:
    from .tuya_mqtt_signaling import _u16_string,_packet_remaining_length
    if not isinstance(topic,str) or not topic.startswith('smart/mb/') or len(topic)>320:
        raise ValueError('topic invalide')
    if any(c in topic for c in ('#','+','\x00','\r','\n')):
        raise ValueError('topic invalide')
    if not 1 <= packet_id <= 4:
        raise ValueError('packet id invalide')
    payload=struct.pack('!H',packet_id)+_u16_string(topic)+b'\x01'
    return b'\x82'+_packet_remaining_length(len(payload))+payload


def _publish_topic(header:int, body:bytes)->tuple[str,int,int|None]|None:
    if header>>4 != 3 or len(body)<3:
        return None
    count=struct.unpack('!H',body[:2])[0]
    if not 1<=count<=320 or len(body)<2+count:
        return None
    try:
        topic=body[2:2+count].decode('utf-8')
    except UnicodeDecodeError:
        return None
    qos=(header>>1)&3
    if qos==3:
        return None
    off=2+count
    packet=None
    if qos:
        if len(body)<off+2:
            return None
        packet=struct.unpack('!H',body[off:off+2])[0]
        if not packet:
            return None
        off+=2
    return topic,len(body)-off,packet if qos==1 else None


def _listen(conn: Any, topics: dict[str,str], duration:float=WINDOW_SECONDS)->dict:
    """Subscribe to four candidates and count inbound messages; no body retained."""
    from .tuya_mqtt_signaling import _read_packet
    results={name:{'abonnement':'non_tente','messages_recus':0} for name in _CHANNELS}
    for packet_id,name in enumerate(_CHANNELS,1):
        try:
            conn.sendall(_subscribe(topics[name],packet_id))
            typ,body=_read_packet(conn)
            if typ!=0x90 or len(body)!=3 or body[:2]!=struct.pack('!H',packet_id):
                results[name]['abonnement']='reponse_inattendue'
                continue
            results[name]['abonnement']='accepte' if body[2] in (0,1,2) else 'refuse' if body[2]==0x80 else 'reponse_inattendue'
        except (TimeoutError,EOFError,OSError,ValueError):
            results[name]['abonnement']='lecture_impossible'
    deadline=time.monotonic()+duration
    total=0
    unknown=0
    # MQTT QoS1 PUBACKs (0x40), if used, are the only outbound application
    # packets during observation. They are not device commands or PUBLISH.
    while time.monotonic()<deadline and total<MAX_FRAMES:
        try:
            conn.settimeout(max(0.05,min(2.0,deadline-time.monotonic())))
            header,body=_read_packet(conn)
        except (socket.timeout,TimeoutError):
            continue
        except (OSError,EOFError,ValueError):
            break
        parsed=_publish_topic(header,body)
        if parsed is None:
            continue
        total+=1
        received,byte_count,packet_id=parsed
        matches=[n for n,t in topics.items() if received==t]
        if not matches:
            unknown+=1
        else:
            for name in matches:
                results[name]['messages_recus']+=1
                results[name]['charge_utile_16_octets_ou_plus']=bool(results[name].get('charge_utile_16_octets_ou_plus',False) or byte_count>=16)
        if packet_id is not None:
            try:conn.sendall(b'\x40\x02'+struct.pack('!H',packet_id))
            except OSError:break
    return {'canaux':results,'messages_mqtt_entree_total':total,'messages_autres_topics':unknown}


def _safe_preflight(coordinator:Any):
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_mqtt_transport_b53 import _communication_topic_id
    from .ptz_live_control_b56 import _preflight
    control=getattr(coordinator,'ptz_live_b55',None)
    if control is not None and control.status().get('controle_actif'):
        raise ValueError('moteur_experimental_actif')
    # Existing preflight checks current HA live, fresh identity/session and pv=2.2.
    key,dev_id,auth,device_id=_preflight(coordinator)
    # Use a DIFFERENT MQTT client ID from the working PTZ/video connections.
    # This reuses only the already authenticated in-memory OEM session.
    from .uid_token_probe import _ready_identity,_apk_preflight
    from .tuya_mqtt_signaling import _identity
    _,install_id=_ready_identity(coordinator.client)
    _,material=_apk_preflight(coordinator.client.apk_path)
    identity,signer=material
    session=coordinator.client._tuya_oem_session
    auth=_identity(identity,signer,session,install_id+'-ptz-observe-b61',dev_id)
    selected,why=select_c5l_oem(coordinator)
    if selected is None:raise ValueError('cache_oem_absent_ou_expire')
    _,row,method=selected
    node,reason=_communication_topic_id(row)
    if node is None:raise ValueError('noeud_communication_absent')
    if any(not (5<=len(v)<=128) or any(c in v for c in ('#','+','\x00','/','\r','\n')) for v in (node,dev_id)):
        raise ValueError('identifiant_topic_invalide')
    topics={'retour_devId':'smart/mb/in/'+dev_id,
            'sortie_devId':'smart/mb/out/'+dev_id,
            'retour_communicationNode':'smart/mb/in/'+node,
            'sortie_communicationNode':'smart/mb/out/'+node}
    return auth,topics,dev_id==node


def audit_mqtt_ptz_app_b61(coordinator:Any, *, confirm_read=False,confirm_camera=False)->dict:
    out={'diagnostic':'aosu_ptz_app_passive_b61','mode':'observation_passive_app_aosu',
         'duree_ecoute_secondes':WINDOW_SECONDS,
         'commandes_ptz_envoyees':0,'commandes_stop_envoyees':0,
         'publications_mqtt_emises':0,'video_modifiee':False,
         'appels_http':0,'identifiants_retournes':False,'secrets_retournes':False}
    if confirm_read is not True or confirm_camera is not True:
        return {**out,'etat':'confirmations_requises'}
    now=time.monotonic();guard=id(coordinator.client)
    if _NEXT_ALLOWED.get(guard,0)>now:
        return {**out,'etat':'temporisation_une_minute'}
    if not _LOCK.acquire(False):return {**out,'etat':'observation_deja_en_cours'}
    try:
        if _NEXT_ALLOWED.get(guard,0)>time.monotonic():
            return {**out,'etat':'temporisation_une_minute'}
        try:auth,topics,same=_safe_preflight(coordinator)
        except Exception:
            # Never expose OEM credential, topic or raw exception text.
            return {**out,'etat':'preparation_impossible_actualiser_session_ou_direct'}
        _NEXT_ALLOWED[guard]=time.monotonic()+MIN_RETRY_SECONDS
        out['topic_devId_et_communicationNode_identiques']=same
        from .tuya_mqtt_signaling import _BROKER,_PORT,_TIMEOUT_SECONDS,_mqtt_connect_packet,_read_packet
        try:
            ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname=True;ctx.verify_mode=ssl.CERT_REQUIRED
            with socket.create_connection((_BROKER,_PORT),timeout=_TIMEOUT_SECONDS) as tcp:
                with ctx.wrap_socket(tcp,server_hostname=_BROKER) as conn:
                    conn.settimeout(_TIMEOUT_SECONDS)
                    conn.sendall(_mqtt_connect_packet(auth))
                    typ,data=_read_packet(conn)
                    if typ!=0x20 or data!=b'\x00\x00':
                        return {**out,'etat':'connexion_mqtt_non_acceptee'}
                    report=_listen(conn,topics)
                    try:conn.sendall(b'\xe0\x00')
                    except OSError:pass
                    return {**out,'connexion_mqtt_authentifiee':True,**report,
                            'etat':'observation_terminee_sans_preuve_execution_camera'}
        except (OSError,EOFError,TimeoutError,ssl.SSLError,ValueError):
            return {**out,'etat':'observation_mqtt_impossible'}
    finally:
        _LOCK.release()
