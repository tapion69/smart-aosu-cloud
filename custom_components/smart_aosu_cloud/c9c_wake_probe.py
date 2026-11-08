"""One manually authorized wake attempt for a standalone battery C9C.

Uses a candidate Tuya low-power wake path. The CRC never leaves memory except
inside the authenticated TLS MQTT session. Does not start video or PTZ.
"""
from __future__ import annotations

import socket
import ssl
import struct
import threading
import time
import zlib
from typing import Any

from .tuya_mqtt_signaling import (
    _BROKER, _PORT, _identity, _mqtt_connect_packet, _mqtt_subscribe_packet
)
from .tuya_mqtt_offer import _mqtt_publish, _mqtt_read, _incoming_pub, _decode_signal
from .c9c_mqtt_classify import classify_observed_signal
from .tuya_media_bootstrap import PrivateMediaBootstrap

_WAKE_LOCK = threading.Lock()
_LAST_WAKE: dict[int, float] = {}
_COOLDOWN_S = 600
_WAIT_S = 25


def build_wake_packet(device_id: str, local_key: str) -> tuple[str, bytes]:
    """Generate one binary CRC32 wake packet, no arbitrary payload accepted."""
    if (not isinstance(device_id, str) or not 5 <= len(device_id) <= 128
            or any(c in device_id for c in "#+\r\n\x00/")):
        raise ValueError("invalid device id")
    if not isinstance(local_key, str) or not 1 <= len(local_key) <= 64:
        raise ValueError("invalid local key")
    key = local_key.encode("utf-8")
    if len(key) not in (16, 24, 32):
        raise ValueError("unsupported local key length")
    crc = zlib.crc32(key) & 0xFFFFFFFF
    return "m/w/" + device_id, struct.pack(">I", crc)


def _attempt(auth: Any, uid: str, device_id: str, local_key: str) -> dict:
    base = {
        "etat": "non_lance",
        "mqtt_connecte": False, "abonnement_confirme": False,
        "wake_envoye": False, "puback_wake": False,
        "dp149_vrai": 0, "dp149_faux": 0, "dp149_autre": 0,
        "messages_appareil": 0, "messages_dechiffres": 0,
        "requetes_reveil": 0,
        "images_recues": 0, "video_lancee": False, "commandes_ptz": 0,
        "identifiants_retournes": False, "secrets_retournes": False,
        "payloads_conserves": False,
        "confirmation_reveil": "non_confirmee",
    }
    try:
        topic, payload = build_wake_packet(device_id, local_key)
        key = local_key.encode("utf-8")
    except ValueError:
        return {**base, "etat": "identite_reveil_invalide"}
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((_BROKER, _PORT), timeout=8) as tcp:
            with ctx.wrap_socket(tcp, server_hostname=_BROKER) as conn:
                conn.settimeout(8)
                conn.sendall(_mqtt_connect_packet(auth))
                typ, msg = _mqtt_read(conn)
                if typ != 0x20 or len(msg) != 2 or msg[1] != 0:
                    return {**base, "etat": "mqtt_connexion_refusee"}
                base["mqtt_connecte"] = True
                conn.sendall(_mqtt_subscribe_packet(auth.topic))
                typ, msg = _mqtt_read(conn)
                if (typ != 0x90 or len(msg) != 3
                        or int.from_bytes(msg[:2], "big") != 1
                        or msg[2] not in (0, 1, 2)):
                    return {**base, "etat": "mqtt_abonnement_refuse"}
                base["abonnement_confirme"] = True

                # Exactly one manual wake publish, QoS 1, packet identifier 2.
                conn.sendall(_mqtt_publish(topic, payload, 2))
                base["wake_envoye"] = True
                base["requetes_reveil"] = 1
                deadline = time.monotonic() + _WAIT_S
                while time.monotonic() < deadline:
                    conn.settimeout(max(0.2, min(1.5, deadline - time.monotonic())))
                    try:
                        typ, msg = _mqtt_read(conn)
                    except (socket.timeout, TimeoutError):
                        continue
                    if typ == 0x40:
                        if msg == b"\x00\x02":
                            base["puback_wake"] = True
                        continue
                    if typ & 0xF0 != 0x30:
                        continue
                    recv_topic, raw, packet_id = _incoming_pub(typ, msg)
                    if packet_id is not None:
                        conn.sendall(b"\x40\x02" + struct.pack("!H", packet_id))
                    if recv_topic != auth.topic or typ & 0x01:
                        continue
                    base["messages_appareil"] += 1
                    flags = classify_observed_signal(
                        raw, key=key, device_id=device_id,
                        uid=uid, decoder=_decode_signal)
                    if flags["decoded"]:
                        base["messages_dechiffres"] += 1
                        if flags["dp149_present"]:
                            base["dp149_vrai"] += int(flags["dp149_true"])
                            base["dp149_faux"] += int(flags["dp149_false"])
                            base["dp149_autre"] += int(flags["dp149_non_bool"])
                    if base["dp149_vrai"] and base["puback_wake"]:
                        # Could still be correlated with another client;
                        # presence after publish is a clue, not proof.
                        break
                base["etat"] = "observation_terminee"
                if base["dp149_vrai"]:
                    base["confirmation_reveil"] = "dp149_true_observe"
                try:
                    conn.sendall(b"\xe0\x00")
                except (OSError, ssl.SSLError):
                    pass
                return base
    except ssl.SSLCertVerificationError:
        base["etat"] = "certificat_tls_invalide"
    except (socket.timeout, TimeoutError):
        base["etat"] = "delai_mqtt_depasse"
    except (OSError, ssl.SSLError, ConnectionError):
        base["etat"] = "reseau_mqtt_indisponible"
    except (ValueError, TypeError, EOFError):
        base["etat"] = "trame_mqtt_invalide"
    return base


def try_wake_c9c_on_open_socket(client: Any, session: Any,
                                media: PrivateMediaBootstrap, sock: Any,
                                auth_topic: str, *, stop_event: Any = None) -> dict:
    """Wake C9C on caller's already authenticated + subscribed MQTT socket.

    Owns neither CONNECT nor SUBSCRIBE nor DISCONNECT. The same 10-minute
    cooldown protects this path and the separate manual wake button.
    """
    result = {
        "etat": "non_lance", "socket_reutilisee": True,
        "wake_envoye": False, "puback_wake": False,
        "dp149_vrai": 0, "dp149_faux": 0,
        "messages_appareil": 0, "messages_dechiffres": 0,
        "delai_reveil_confirme_ms": None,
        "identifiants_retournes": False, "secrets_retournes": False,
    }
    if not _WAKE_LOCK.acquire(blocking=False):
        return {**result, "etat": "test_reveil_deja_en_cours"}
    try:
        now = time.monotonic()
        if now < _LAST_WAKE.get(id(client), 0):
            return {**result, "etat": "limite_reveil_dix_minutes"}
        if not isinstance(media, PrivateMediaBootstrap) or not media.is_fresh():
            return {**result, "etat": "configuration_rtc_expiree"}
        if media.owner_uid != getattr(session, "uid", None):
            return {**result, "etat": "session_tuya_incoherente"}
        if not isinstance(auth_topic, str) or not auth_topic:
            return {**result, "etat": "preparation_reveil_invalide"}
        try:
            topic, payload = build_wake_packet(media.device_id, media.local_key)
            key = media.local_key.encode("utf-8")
        except (ValueError, TypeError, AttributeError):
            return {**result, "etat": "preparation_reveil_invalide"}
        _LAST_WAKE[id(client)] = now + _COOLDOWN_S
        started = time.monotonic()
        try:
            # Wake QoS1 packet id 2 differs from SDP offer packet id 11.
            sock.sendall(_mqtt_publish(topic, payload, 2))
            result["wake_envoye"] = True
            deadline = started + _WAIT_S
            while time.monotonic() < deadline:
                if stop_event is not None and stop_event.is_set():
                    result["etat"] = "arret_demande"
                    return result
                sock.settimeout(max(0.2, min(1.5, deadline - time.monotonic())))
                try:
                    typ, msg = _mqtt_read(sock)
                except (socket.timeout, TimeoutError):
                    continue
                if typ == 0x40:
                    if msg == b"\x00\x02":
                        result["puback_wake"] = True
                    if result["puback_wake"] and result["dp149_vrai"]:
                        break
                    continue
                if typ & 0xF0 != 0x30:
                    continue
                recv_topic, raw, packet_id = _incoming_pub(typ, msg)
                if packet_id is not None:
                    sock.sendall(b"\x40\x02" + struct.pack("!H", packet_id))
                if recv_topic != auth_topic or typ & 0x01:
                    continue
                result["messages_appareil"] += 1
                flags = classify_observed_signal(
                    raw, key=key, device_id=media.device_id,
                    uid=session.uid, decoder=_decode_signal)
                if flags["decoded"]:
                    result["messages_dechiffres"] += 1
                    if flags["dp149_present"]:
                        result["dp149_vrai"] += int(flags["dp149_true"])
                        result["dp149_faux"] += int(flags["dp149_false"])
                if result["puback_wake"] and result["dp149_vrai"]:
                    break
            result["etat"] = "observation_terminee"
            if result["puback_wake"] and result["dp149_vrai"]:
                result["delai_reveil_confirme_ms"] = max(
                    0, min(60000, int((time.monotonic() - started) * 1000)))
            return result
        except (socket.timeout, TimeoutError):
            result["etat"] = "delai_mqtt_depasse"
        except (OSError, ssl.SSLError, ConnectionError):
            result["etat"] = "reseau_mqtt_indisponible"
        except (ValueError, TypeError, EOFError, KeyError):
            result["etat"] = "trame_mqtt_invalide"
        return result
    finally:
        _WAKE_LOCK.release()


def try_wake_c9c_once(client: Any, identity: Any, signer: Any,
                      session: Any, install_id: str,
                      media: PrivateMediaBootstrap) -> dict:
    """At most one wake attempt per ten minutes on this live client."""
    base = {
        "diagnostic": "aosu_c9c_reveil_manuel_b19", "etat": "non_lance",
        "requetes_reveil": 0, "video_lancee": False, "commandes_ptz": 0,
        "secrets_retournes": False, "identifiants_retournes": False,
        "payloads_conserves": False,
    }
    if not _WAKE_LOCK.acquire(blocking=False):
        return {**base, "etat": "test_reveil_deja_en_cours"}
    try:
        now = time.monotonic()
        if now < _LAST_WAKE.get(id(client), 0):
            return {**base, "etat": "limite_reveil_dix_minutes"}
        if not isinstance(media, PrivateMediaBootstrap) or not media.is_fresh():
            return {**base, "etat": "configuration_rtc_expiree"}
        if media.owner_uid != getattr(session, "uid", None):
            return {**base, "etat": "session_tuya_incoherente"}
        try:
            # Validate the exact target before any network connection.
            build_wake_packet(media.device_id, media.local_key)
            auth = _identity(identity, signer, session, install_id, media.device_id)
        except (ValueError, TypeError, AttributeError):
            return {**base, "etat": "preparation_reveil_invalide"}
        # Consume the cooldown before sending; no automatic retries.
        _LAST_WAKE[id(client)] = now + _COOLDOWN_S
        return {**base, **_attempt(auth, session.uid,
                                  media.device_id, media.local_key)}
    finally:
        _WAKE_LOCK.release()
