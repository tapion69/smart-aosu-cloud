"""Optional subscribe-only MQTT channel check for one standalone C9C.

Never publishes an offer, a wake packet, an SDP or a PTZ command.
The msid MUST come from an explicit RTC value, not a guessed UID.
"""
from __future__ import annotations
import re
import socket
import ssl
import threading
import time
from typing import Any

from .tuya_mqtt_signaling import (
    _BROKER, _PORT, _identity, _mqtt_connect_packet, _mqtt_subscribe_packet)
from .tuya_mqtt_offer import _mqtt_read

_MSID=re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_LOCK=threading.Lock()
_ALLOWED:dict[int,float]={}
_COOLDOWN_S=600


def subscribe_webrtc_once(client:Any, identity:Any, signer:Any,
                          session:Any, install_id:str,
                          device_id:str, msid:str|None)->dict:
    result={"etat":"non_lance","mqtt_tls":False,"mqtt_connack":False,
            "abonnement_accepte":False,"publications":0,"offres_envoyees":0,
            "commandes_camera":0,"commandes_ptz":0,"video_lancee":False,
            "identifiants_retournes":False,"secrets_retournes":False}
    if not isinstance(msid,str) or not _MSID.fullmatch(msid):
        return {**result,"etat":"msid_explicite_manquant"}
    if not _LOCK.acquire(blocking=False):
        return {**result,"etat":"test_deja_en_cours"}
    try:
        now=time.monotonic()
        if now<_ALLOWED.get(id(client),0):
            return {**result,"etat":"limite_dix_minutes"}
        if not isinstance(device_id,str) or not 5<=len(device_id)<=128:
            return {**result,"etat":"cible_invalide"}
        try:
            auth=_identity(identity,signer,session,install_id,device_id)
        except (ValueError,TypeError,AttributeError):
            return {**result,"etat":"identite_mqtt_indisponible"}
        _ALLOWED[id(client)]=now+_COOLDOWN_S
        ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.verify_mode=ssl.CERT_REQUIRED
        ctx.check_hostname=True
        try:
            with socket.create_connection((_BROKER,_PORT),timeout=8) as tcp:
                with ctx.wrap_socket(tcp,server_hostname=_BROKER) as sock:
                    sock.settimeout(8)
                    result["mqtt_tls"]=True
                    sock.sendall(_mqtt_connect_packet(auth))
                    typ,payload=_mqtt_read(sock)
                    if typ!=0x20 or len(payload)!=2 or payload[1]!=0:
                        return {**result,"etat":"connexion_refusee"}
                    result["mqtt_connack"]=True
                    sock.sendall(_mqtt_subscribe_packet("/av/u/"+msid))
                    typ,payload=_mqtt_read(sock)
                    if typ!=0x90 or len(payload)!=3 or payload[:2]!=b"\x00\x01":
                        return {**result,"etat":"suback_invalide"}
                    result["abonnement_accepte"]=payload[2] in (0,1,2)
                    result["etat"]=("abonnement_accepte" if result["abonnement_accepte"]
                                    else "abonnement_refuse")
                    try:
                        sock.sendall(b"\xe0\x00")
                    except (OSError,ssl.SSLError):
                        pass
                    return result
        except ssl.SSLCertVerificationError:
            result["etat"]="certificat_tls_invalide"
        except (socket.timeout,TimeoutError):
            result["etat"]="mqtt_timeout"
        except (OSError,ssl.SSLError,ConnectionError):
            result["etat"]="reseau_mqtt_indisponible"
        except (ValueError,TypeError,EOFError):
            result["etat"]="trame_mqtt_invalide"
        return result
    finally:
        _LOCK.release()
