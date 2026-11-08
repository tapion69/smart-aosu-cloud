"""Opt-in, ephemeral C9C MQTT topic observer for native-app comparisons.

Observes topic-level activity only; discards every received encrypted payload.
No offer, stream, PTZ, recording, MQTT content or credentials are returned.
"""
from __future__ import annotations

import socket
import ssl
import struct
import threading
import time
from typing import Any

from .tuya_mqtt_signaling import (
    _BROKER, _PORT, _identity, _mqtt_connect_packet,
    _packet_remaining_length, _u16_string,
)
from .tuya_mqtt_offer import _mqtt_read, _incoming_pub, _decode_signal
from .tuya_media_bootstrap import PrivateMediaBootstrap
from .c9c_mqtt_classify import classify_observed_signal

_LOCK=threading.Lock()
_ALLOWED:dict[int,float]={}
_DURATION=20


def _subscribe(topic:str,packet_id:int)->bytes:
    if not 1<=packet_id<=65535:
        raise ValueError("invalid subscribe id")
    if not isinstance(topic,str) or any(c in topic for c in "#+\r\n\x00"):
        raise ValueError("invalid topic")
    body=struct.pack("!H",packet_id)+_u16_string(topic)+b"\x01"
    return b"\x82"+_packet_remaining_length(len(body))+body


def _observe(auth:Any, uid:str, *, device_id:str, local_key:str)->dict:
    """Own TLS client, two exact topics. No MQTT PUBLISH is ever sent."""
    base={
        "etat":"non_lance", "abonnement_appareil":False,
        "abonnement_moto":False,
        "messages_appareil":0, "messages_moto":0, "messages_autres":0,
        "offres_envoyees":0, "commandes_camera":0, "commandes_ptz":0,
        "video_lancee":False, "identifiants_retournes":False,
        "secrets_retournes":False, "payloads_conserves":False,
        "trames_pv22":0,"trames_autres":0,
        "decodages_ok":0,"decodages_echec":0,
        "protocoles_22":0,"protocoles_302":0,"protocoles_autres":0,
        "types_offer":0,"types_answer":0,
        "types_candidate":0,"types_disconnect":0,"types_autres":0,
        "origine_appareil_confirmee":0,"destinataire_appareil_confirme":0,
        "origine_utilisateur_confirmee":0,"destinataire_utilisateur_confirme":0,
    }
    local=local_key.encode("utf-8") if isinstance(local_key,str) and len(local_key)<=64 else b""
    local=local if len(local) in (16,24,32) else None
    if not isinstance(uid,str) or not 1<=len(uid)<=256 or any(c in uid for c in "#+\r\n\x00"):
        return {**base,"etat":"uid_indisponible"}
    channels=[("appareil",auth.topic),("moto","/av/u/"+uid)]
    ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.check_hostname=True
    try:
        with socket.create_connection((_BROKER,_PORT),timeout=8) as tcp:
            with ctx.wrap_socket(tcp,server_hostname=_BROKER) as conn:
                conn.settimeout(8)
                conn.sendall(_mqtt_connect_packet(auth))
                t,p=_mqtt_read(conn)
                if t!=0x20 or len(p)!=2 or p[1]!=0:
                    return {**base,"etat":"connexion_mqtt_refusee"}
                for n,(label,topic) in enumerate(channels,1):
                    conn.sendall(_subscribe(topic,n))
                    t,p=_mqtt_read(conn)
                    if t!=0x90 or len(p)!=3 or int.from_bytes(p[:2],"big")!=n:
                        return {**base,"etat":"abonnement_inattendu"}
                    base["abonnement_"+label]=p[2] in (0,1,2)
                if not base["abonnement_appareil"] and not base["abonnement_moto"]:
                    return {**base,"etat":"aucun_abonnement_accepte"}
                deadline=time.monotonic()+_DURATION
                while time.monotonic()<deadline:
                    conn.settimeout(max(0.2,min(1.5,deadline-time.monotonic())))
                    try:
                        t,p=_mqtt_read(conn)
                    except (TimeoutError,socket.timeout):
                        continue
                    if t & 0xF0 != 0x30:
                        continue
                    topic,raw,packet_id=_incoming_pub(t,p)
                    # Deliberately do not inspect or store raw encrypted bytes.
                    if packet_id is not None:
                        conn.sendall(b"\x40\x02"+struct.pack("!H",packet_id))
                    if topic==channels[0][1]:
                        base["messages_appareil"]+=1
                        # In-memory decryption to classify *only* known fields.
                        # All raw data and decoder errors are discarded instantly.
                        result=classify_observed_signal(
                            raw,key=local,device_id=device_id,uid=uid,
                            decoder=_decode_signal)
                        if result["pv22"]:
                            base["trames_pv22"]+=1
                            if result["decoded"]:
                                base["decodages_ok"]+=1
                                protocol=result["protocol"]
                                base["protocoles_"+protocol if protocol in ("22","302") else "protocoles_autres"]+=1
                                kind=result["type"]
                                base["types_"+kind if kind in ("offer","answer","candidate","disconnect") else "types_autres"]+=1
                                for field,flag in (
                                    ("origine_appareil_confirmee","from_device"),
                                    ("destinataire_appareil_confirme","to_device"),
                                    ("origine_utilisateur_confirmee","from_user"),
                                    ("destinataire_utilisateur_confirme","to_user")):
                                    base[field]+=int(result[flag] is True)
                            else:
                                base["decodages_echec"]+=1
                        else:
                            base["trames_autres"]+=1
                    elif topic==channels[1][1]:
                        base["messages_moto"]+=1
                    else:
                        base["messages_autres"]+=1
                    if sum(base[k] for k in ("messages_appareil","messages_moto","messages_autres"))>=100:
                        break
                base["etat"]="ecoute_terminee"
                base["fenetre_observation_s"]=_DURATION
                try:conn.sendall(b"\xe0\x00")
                except (OSError,ssl.SSLError):pass
                return base
    except ssl.SSLCertVerificationError:
        base["etat"]="certificat_tls_non_valide"
    except (socket.timeout,TimeoutError):
        base["etat"]="mqtt_timeout"
    except (ValueError,TypeError,EOFError):
        base["etat"]="trame_mqtt_inattendue"
    except (OSError,ssl.SSLError,ConnectionError):
        base["etat"]="erreur_reseau_mqtt"
    return base


def observe_mqtt_for_c9c(client:Any, identity:Any, signer:Any,
                         session:Any, install_id:str,
                         media:PrivateMediaBootstrap)->dict:
    """One manual observation per ten minutes, no P2P or camera commands."""
    base={"diagnostic":"aosu_c9c_mqtt_passif_b11",
          "etat":"non_lance","commandes_camera":0,"commandes_ptz":0,
          "offres_envoyees":0,"video_lancee":False,
          "identifiants_retournes":False,"secrets_retournes":False,
          "payloads_conserves":False}
    if not _LOCK.acquire(blocking=False):
        return {**base,"etat":"ecoute_deja_en_cours"}
    try:
        now=time.monotonic()
        if now<_ALLOWED.get(id(client),0):
            return {**base,"etat":"limite_ecoute_dix_minutes"}
        if not isinstance(media,PrivateMediaBootstrap) or not media.is_fresh():
            return {**base,"etat":"rtc_expire"}
        if media.owner_uid != session.uid:
            return {**base,"etat":"session_incoherente"}
        try:
            auth=_identity(identity,signer,session,install_id,media.device_id)
        except (TypeError,ValueError,AttributeError):
            return {**base,"etat":"identite_mqtt_indisponible"}
        _ALLOWED[id(client)]=now+600
        return {**base,**_observe(
            auth,session.uid,device_id=media.device_id,
            local_key=media.local_key)}
    finally:
        _LOCK.release()
