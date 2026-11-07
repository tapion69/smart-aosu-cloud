"""One-shot authenticated TCP relay handshake for owned AOSU/Tuya IPC devices.

Experimental transport verification only. No channel-0 authorization, KCP,
video, microphone, camera controls, persistence, or secret-bearing diagnostics.

Protocol interoperability reference (MIT):
https://github.com/roquerodrigo/tuya-ipc-p2p-sdk
See third-party MIT license for upstream contributions. The C5L implementation
and live compatibility of the handshake require confirmation on real hardware.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import socket
import struct
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_MAX_FRAME = 8192
_TIMEOUT_SECONDS = 7.0
_ALNUM = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def _pad(data: bytes) -> bytes:
    p = 16 - (len(data) % 16)
    return data + bytes([p]) * p


def _cbc_encrypt(key: bytes, iv: bytes, plain: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return cipher.update(_pad(plain)) + cipher.finalize()


def _cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != 16 or not data or len(data) % 16:
        raise ValueError('invalid ciphertext length')
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    out = cipher.update(data) + cipher.finalize()
    p = out[-1]
    if p < 1 or p > 16 or out[-p:] != bytes([p]) * p:
        raise ValueError('invalid padding')
    return out[:-p]


def _tlv(t: int, v: bytes) -> bytes:
    return struct.pack('!HH', t, len(v)) + v


def _f4(index: int, key: bytes, session_id: bytes, username: bytes, obj: dict) -> bytes:
    """Relay f4 TLV message; HMAC covers frame through the trailing MAC TLV header."""
    if len(key) != 16 or len(session_id) > 256 or len(username) > 256:
        raise ValueError('bad relay materials')
    iv = secrets.token_bytes(16)
    message = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    encrypted = _cbc_encrypt(key, iv, message)
    body = (b'\x00\x01\x00\x02' + struct.pack('!H', index) + b'\x00\x00'
            + _tlv(2, iv) + _tlv(3, session_id) + _tlv(4, username)
            + b'\x00\x00\x00\x00' + b'\x07' + struct.pack('!H', len(encrypted)) + encrypted)
    length = len(body) + 36
    if length > _MAX_FRAME:
        raise ValueError('oversized handshake')
    signed = b'\xf4\x00' + struct.pack('!H', length) + body + b'\x00\x08\x00\x20'
    return signed + hmac.new(key, signed, hashlib.sha256).digest()


def _parse_f4(key: bytes, payload: bytes) -> dict:
    """Unpack an f4 payload (without 4-byte outer header); bound lengths."""
    if len(payload) < 16 or len(payload) > _MAX_FRAME:
        raise ValueError('bad frame length')
    cursor = 8
    iv = None
    while cursor + 4 <= len(payload):
        kind, length = struct.unpack('!HH', payload[cursor:cursor + 4])
        if kind == 0 and length == 0:
            cursor += 4
            break
        if length > 512 or cursor + 4 + length > len(payload):
            raise ValueError('tlv bounds')
        if kind == 2:
            iv = payload[cursor + 4:cursor + 4 + length]
        cursor += 4 + length
    if iv is None or len(iv) != 16 or cursor + 3 >= len(payload) or payload[cursor] != 7:
        raise ValueError('no encrypted section')
    cipherlen = struct.unpack('!H', payload[cursor + 1:cursor + 3])[0]
    start = cursor + 3
    if cipherlen > 4096 or start + cipherlen + 36 > len(payload):
        raise ValueError('bad encrypted section bounds')
    plain = _cbc_decrypt(key, iv, payload[start:start + cipherlen])
    result = json.loads(plain)
    if not isinstance(result, dict):
        raise ValueError('invalid payload type')
    return result


def _auth_value(value: Any, wanted: str) -> str:
    if not isinstance(value, str):
        return ''
    for item in value.split(','):
        k, sep, v = item.strip().partition('=')
        if sep and k == wanted and len(v) <= 256:
            return v
    return ''


def _endpoint(urls: Any) -> tuple[str, int]:
    if not isinstance(urls, list) or not urls:
        raise ValueError('no relay URL')
    uri = next((x for x in urls if isinstance(x, str) and x.startswith('tcp4:')), urls[0])
    if not isinstance(uri, str) or not uri.startswith(('tcp4:', 'tcp6:')) or len(uri) > 300:
        raise ValueError('unsupported relay URL')
    address = uri.split(':', 1)[1]
    host, sep, port_s = address.rpartition(':')
    if not sep or not port_s.isdigit() or not 1 <= int(port_s) <= 65535:
        raise ValueError('invalid relay port')
    host = host.strip('[]')
    if not host or len(host) > 253:
        raise ValueError('invalid relay host')
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError('relay host is not a public address')
    except ValueError as exc:
        if 'not a public address' in str(exc):
            raise
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,251}[a-zA-Z0-9]', host):
            raise ValueError('unsupported host characters') from exc
    return host, int(port_s)


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    out = bytearray()
    while len(out) < size:
        part = sock.recv(size - len(out))
        if not part:
            raise EOFError('relay closed')
        out += part
    return bytes(out)


def _read_f4(sock: socket.socket) -> bytes:
    for _ in range(5):
        head = _recv_exact(sock, 4)
        size = int.from_bytes(head[2:4], 'big')
        if size > _MAX_FRAME:
            raise ValueError('relay frame too large')
        payload = _recv_exact(sock, size)
        if head[0] == 0xF5:
            continue
        if head[0] != 0xF4:
            raise ValueError('unexpected relay frame')
        return payload
    raise TimeoutError('no handshake')


def _digest(auth_key: bytes, fields: tuple[str, ...]) -> str:
    return hmac.new(auth_key, ':'.join(fields).encode('utf-8'), hashlib.sha256).hexdigest()


def _handshake(sock: socket.socket, relay: dict, uid: str, did: str) -> dict[str, bool]:
    outcome = {'relais_defi_recu': False, 'relais_signature_verifiee': False,
               'relais_ack_chiffre_envoye': False, 'relais_handshake_termine': False}
    credential = relay['credential']
    username = relay['username']
    session_id = relay['sessionId']
    if not all(isinstance(v, str) and 1 <= len(v) <= 256 for v in
               (credential, username, session_id, uid, did)):
        raise ValueError('invalid credential format')
    if len(credential) < 16:
        raise ValueError('credential too short')
    key = credential[:16].encode('utf-8')
    if len(key) != 16:
        raise ValueError('credential byte length')
    auth_key = credential.encode().ljust(64, b'\x00')
    stamp = username.split(':', 1)[0]
    prefix = (stamp, did, session_id, uid)
    random_part = ''.join(secrets.choice(_ALNUM) for _ in range(32))
    request = {'clientType': 1, 'method': 'request', 'devId': did,
               'uId': uid, 'authorization': f'random={random_part}'}
    sock.sendall(_f4(0, key, session_id.encode(), username.encode(), request))
    response = _parse_f4(key, _read_f4(sock))
    auth = response.get('authorization')
    remote_sig = _auth_value(auth, 'signature')
    remote_random = _auth_value(auth, 'random')
    outcome['relais_defi_recu'] = True
    if not remote_sig or not remote_random:
        return outcome
    if not hmac.compare_digest(_digest(auth_key, (*prefix, random_part)), remote_sig):
        return outcome
    outcome['relais_signature_verifiee'] = True
    signature = _digest(auth_key, (*prefix, remote_sig, remote_random))
    ack = {'clientType': 1, 'method': 'ack', 'devId': did, 'uId': uid,
           'statuscode': 200, 'authorization': f'signature={signature}'}
    sock.sendall(_f4(2, key, session_id.encode(), username.encode(), ack))
    outcome['relais_ack_chiffre_envoye'] = True
    last = _read_f4(sock)
    # Relay may send a final ack without any structured JSON object.
    outcome['relais_handshake_termine'] = bool(last)
    return outcome


def probe_relay_handshake(relay: Any, uid: str, did: str, *, media=None, offer=None, tester_kcp: bool=False, tester_media: bool=False, answer_sdp: str='',
                          local_capture_directory: str | None = None, live_preview=None, ice_candidate: str | None = None) -> dict[str, object]:
    """One raw TCP connection; bounded reads; no KCP and no camera commands."""
    out: dict[str, object] = {'diagnostic': 'aosu_tuya_relais_tcp_b19',
        'connexion_tcp_relais': False,
        'relais_defi_recu': False,
        'relais_signature_verifiee': False,
        'relais_ack_chiffre_envoye': False,
        'relais_handshake_termine': False,
        'kcp_demarre': False, 'video_recue': False,
        'commande_camera': 0, 'secrets_retournes': False,
        'etat': 'preparation_relais_incomplete'}
    if not isinstance(relay, dict):
        return out
    try:
        urls = relay.get('urls') or relay.get('urlsEx')
        host, port = _endpoint(urls)
        if not all(isinstance(relay.get(k), str) and relay[k]
                   for k in ('credential', 'sessionId', 'username')):
            return out
        with socket.create_connection((host, port), timeout=_TIMEOUT_SECONDS) as sock:
            sock.settimeout(_TIMEOUT_SECONDS)
            out['connexion_tcp_relais'] = True
            result = _handshake(sock, relay, uid, did)
            out.update(result)
            if live_preview is not None and out['relais_handshake_termine'] and hasattr(live_preview, 'mark_phase_b93'):
                live_preview.mark_phase_b93('relais_tcp_pret')
            if tester_kcp and out['relais_handshake_termine'] and media is not None and offer is not None:
                from .tuya_kcp_probe import _probe_loop
                out['kcp']=_probe_loop(sock, media.aes_key, offer,
                    tester_media=tester_media,answer_sdp=answer_sdp,
                    local_key=media.local_key,device_password=media.device_password,
                    local_capture_directory=local_capture_directory,live_preview=live_preview,
                    ice_candidate=ice_candidate)
                out['kcp_demarre']=bool(out['kcp'].get('tunnel_offre_relais_envoyee'))
                if tester_media:
                    out['commande_camera']=out['kcp'].get('commandes_demarrage_video',0)
                    out['video_recue']=bool(out['kcp'].get('conversation_video_detectee'))
        out['etat'] = ('handshake_tcp_relais_reussi_sans_video' if out['relais_handshake_termine']
                       else 'defi_relais_non_valide')
    except (TimeoutError, socket.timeout):
        out['etat'] = 'relais_delai_depasse'
    except (OSError, ConnectionError, EOFError):
        out['etat'] = 'relais_injoignable_ou_ferme'
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        out['etat'] = 'relais_trame_ou_identifiants_incompatibles'
    return out
