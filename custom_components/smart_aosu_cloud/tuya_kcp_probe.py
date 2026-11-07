"""Bounded, one-shot KCP tunnel probe after a verified Tuya TCP relay handshake.

The probe never sends channel-0 auth/start, video control, PTZ, or media frames.
It resends the *same* previously broker-published offer over the authenticated
relay, then acknowledges inbound KCP pushes to avoid stalling the remote peer.
All sensitive data are handled only in RAM. No payload is exported or logged.

Protocol reference: tuya-ipc-p2p-sdk (Rodrigo Roque, MIT).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import struct
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

_MAX_FRAMES = 160
_MAX_FRAME_BYTES = 8192
_MAX_MESSAGE = 16384
_WAIT_SECONDS = 6.0
_WINDOW = 512
_CONV_TUNNEL = 0x010000F3


def _pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def _segment(conv: int, command: int, sequence: int, una: int = 0,
             timestamp: int = 0, data: bytes = b'', *, wnd: int = _WINDOW) -> bytes:
    if not 0 <= len(data) <= 1376:
        raise ValueError('oversized KCP segment')
    return (struct.pack('<I', conv) + bytes([command, 0]) +
            struct.pack('<HIIII', wnd, timestamp, sequence, una, len(data)) + data)


def _parse_segment(raw: bytes) -> tuple[int, int, int, int, int, int, bytes] | None:
    if len(raw) < 24:
        return None
    conv, cmd, frag, wnd, stamp, seq, una, length = struct.unpack('<IBBHIIII', raw[:24])
    if length > 1376 or len(raw) != length + 24:
        return None
    return conv, cmd, frag, stamp, seq, una, raw[24:]


def _media_frame(key: bytes, segment: bytes) -> bytes:
    tag = hmac.new(key, segment, hashlib.sha1).digest()
    body = b'\x00\x07' + struct.pack('!H', len(segment) + 20) + segment + tag
    if len(body) > _MAX_FRAME_BYTES:
        raise ValueError('frame too long')
    return b'\xf6\x00' + struct.pack('!H', len(body)) + body


def _unwrap_media(key: bytes, frame: bytes) -> bytes:
    if len(frame) < 4 + 20 or frame[:2] != b'\x00\x07':
        raise ValueError('bad media header')
    inner = struct.unpack('!H', frame[2:4])[0]
    if inner < 20 or inner + 4 != len(frame):
        raise ValueError('bad media size')
    content = frame[4:-20]
    expected = hmac.new(key, content, hashlib.sha1).digest()
    if not hmac.compare_digest(expected, frame[-20:]):
        raise ValueError('bad media tag')
    return content


def _encrypt_tunnel_chunks(media_key: bytes, offer: dict, *, start_sequence: int = 0) -> list[bytes]:
    if len(media_key) != 16:
        raise ValueError('bad aes key')
    # Relay envelope uses plaintext JSON, not the MQTT AES-ECB envelope.
    packet = {'header': dict(offer['header']), 'msg': dict(offer['msg'])}
    packet['header']['path'] = 'relay'
    raw = json.dumps(packet, separators=(',', ':'), ensure_ascii=False).encode()
    if len(raw) > _MAX_MESSAGE or not raw:
        raise ValueError('invalid relay offer size')
    envelope = b'\x00\x01' + struct.pack('!H', len(raw)) + raw
    if len(raw) & 1:
        envelope += b'\x00'
    padded = _pad(envelope)
    frames = []
    for i, offset in enumerate(range(0, len(padded), 1312)):
        iv = secrets.token_bytes(16)
        chunk = padded[offset:offset + 1312]
        cipher = Cipher(algorithms.AES(media_key), modes.CBC(iv)).encryptor()
        ciphertext = cipher.update(chunk) + cipher.finalize()
        frames.append(_segment(_CONV_TUNNEL, 0x51, start_sequence + i, data=iv + ciphertext, wnd=64))
    return frames


def _recv_exact(sock: Any, count: int) -> bytes:
    if not 0 <= count <= _MAX_FRAME_BYTES:
        raise ValueError('invalid recv size')
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError('relay closed')
        buf.extend(chunk)
    return bytes(buf)


def _next_frame(sock: Any) -> tuple[int, bytes]:
    header = _recv_exact(sock, 4)
    size = struct.unpack('!H', header[2:4])[0]
    if size > _MAX_FRAME_BYTES:
        raise ValueError('relay frame oversized')
    return header[0], _recv_exact(sock, size)


def _probe_loop(sock: Any, media_key: bytes, offer: dict, *, tester_media: bool=False,
                answer_sdp: str='', local_key: str='', device_password: str='',
                local_capture_directory: str | None = None, live_preview=None, ice_candidate: str | None = None) -> dict[str, object]:
    """Socket is authenticated by b19; no second TCP session is opened here."""
    out: dict[str, object] = {
        'tunnel_offre_relais_envoyee': False,
        'segments_kcp_envoyes': 0,
        'segments_kcp_valides_recus': 0,
        'segments_kcp_acquittes': 0,
        'conversation_controle_detectee': False,
        'conversation_video_detectee': False,
        'conversation_audio_detectee': False,
        'trame_media_hmac_invalide': False,
        'commandes_demarrage_video': 0,
        'video_dechiffree': False,
        'session_video_creee': False,
        'secrets_retournes': False,
        'etat': 'preparation_kcp_non_executee',
    }
    if not isinstance(offer, dict) or not isinstance(offer.get('header'), dict):
        return out
    try:
        outgoing = _encrypt_tunnel_chunks(media_key, offer)
    except (ValueError, TypeError, KeyError, OverflowError):
        out['etat'] = 'offre_relais_non_conforme'
        return out
    try:
        for segment in outgoing:
            sock.sendall(_media_frame(media_key, segment))
            out['segments_kcp_envoyes'] += 1
        out['tunnel_offre_relais_envoyee'] = True
        if ice_candidate is not None and tester_media and live_preview is not None:
            offer_header = dict(offer['header'])
            candidate_header = {k:offer_header[k] for k in (
                'from','to','sessionid','moto_id','path') if k in offer_header}
            if 'trace_id' in offer_header:
                candidate_header['trace_id']=offer_header['trace_id']
            candidate_header['type']='candidate'
            frame={'header':candidate_header,'msg':{'candidate':ice_candidate}}
            candidate_chunks=_encrypt_tunnel_chunks(media_key, frame, start_sequence=len(outgoing))
            for segment in candidate_chunks:
                sock.sendall(_media_frame(media_key, segment))
                out['segments_kcp_envoyes'] += 1
            out['candidat_ice_tunnel_b85_envoye']=True
        if tester_media:
            from .tuya_channel0_probe import run_media_start
            out['media_start']=run_media_start(sock,media_key,answer_sdp,local_key,device_password,
                     local_capture_directory=local_capture_directory,live_preview=live_preview,
                     wait_seconds=11.0)
            out['commandes_demarrage_video']=out['media_start']['commandes_controle_envoyees']
            out['conversation_controle_detectee']=out['media_start']['conversation_controle_detectee']
            out['conversation_video_detectee']=out['media_start']['conversation_video_detectee']
            out['video_dechiffree']=out['media_start']['paquets_video_dechiffres']>0
            out['session_video_creee']=out['media_start']['conversation_video_detectee']
            out['segments_kcp_valides_recus']=out['media_start']['segments_media_valides_recus']
            out['segments_kcp_acquittes']=out['media_start']['segments_media_acquittes']
            out['commande_camera']=out['commandes_demarrage_video']
            out['etat']='essai_media_canal0_termine'
            return out
        deadline = time.monotonic() + _WAIT_SECONDS
        next_seq: dict[int, int] = {}
        seen: set[tuple[int,int]] = set()
        frames = 0
        while time.monotonic() < deadline and frames < _MAX_FRAMES:
            sock.settimeout(max(.1, min(1., deadline - time.monotonic())))
            try:
                kind, payload = _next_frame(sock)
            except (socket.timeout, TimeoutError):
                continue
            except (EOFError, ConnectionError, OSError):
                break
            frames += 1
            if kind == 0xF5:
                # Reply with an empty keepalive frame so the relay does not time out.
                sock.sendall(b'\xf5\x00\x00\x00')
                continue
            if kind != 0xF6:
                continue
            try:
                segment = _parse_segment(_unwrap_media(media_key, payload))
            except (ValueError, TypeError):
                out['trame_media_hmac_invalide'] = True
                continue
            if segment is None:
                continue
            conv, cmd, frag, stamp, seq, una, data = segment
            out['segments_kcp_valides_recus'] += 1
            if conv == 0:
                out['conversation_controle_detectee'] = True
            elif conv == 1:
                out['conversation_video_detectee'] = True
            elif conv == 2:
                out['conversation_audio_detectee'] = True
            if cmd == 0x51:
                marker = (conv, seq)
                current = next_seq.get(conv, 0)
                # Advance the simple receive-window cursor only for in-order pushes.
                if seq == current:
                    next_seq[conv] = current + 1
                if marker not in seen:
                    seen.add(marker)
                ack = _segment(conv, 0x52, seq, next_seq.get(conv, 0), stamp)
                sock.sendall(_media_frame(media_key, ack))
                out['segments_kcp_acquittes'] += 1
            elif cmd == 0x53:
                win = _segment(conv, 0x54, 0, next_seq.get(conv, 0))
                sock.sendall(_media_frame(media_key, win))
        out['etat'] = ('reponses_kcp_verifiees_sans_video' if out['segments_kcp_valides_recus']
                       else 'offre_relais_envoyee_sans_reponse_kcp')
    except (socket.timeout, TimeoutError):
        out['etat'] = 'delai_kcp_depasse'
    except (ValueError, TypeError, OSError, ConnectionError, EOFError):
        out['etat'] = 'transport_kcp_interrompu'
    return out
