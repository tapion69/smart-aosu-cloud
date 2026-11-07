"""C5L ICE controlled-role responder for the existing TCP-relayed media session.

Adapted from Rodrigo Roque's tuya-ipc-p2p-sdk, MIT (see THIRD_PARTY_NOTICES.md).
Only answers standard STUN Binding requests. Does not transmit media or PTZ.
UDP is opened only for an explicitly user-started live session and closed with it.
"""
from __future__ import annotations

import hashlib
import hmac
import socket
import threading
import time
import zlib

_COOKIE = 0x2112A442
_XOR = 0x5354554E


def _attr(kind: int, payload: bytes) -> bytes:
    return kind.to_bytes(2, 'big') + len(payload).to_bytes(2, 'big') + payload + b'\0' * ((-len(payload)) % 4)


def binding_success(transaction: bytes, ip: str, port: int, password: str) -> bytes:
    """Return a STUN Binding success with MESSAGE-INTEGRITY and FINGERPRINT."""
    if len(transaction) != 12 or not 0 < port <= 65535:
        raise ValueError('invalid transaction or port')
    mapped = (b'\0\x01' + (port ^ (_COOKIE >> 16)).to_bytes(2, 'big')
              + (int.from_bytes(socket.inet_aton(ip), 'big') ^ _COOKIE).to_bytes(4, 'big'))
    body = _attr(0x0020, mapped)
    header = bytearray(b'\x01\x01\0\0' + _COOKIE.to_bytes(4, 'big') + transaction)
    header[2:4] = (len(body) + 24).to_bytes(2, 'big')
    msg = header + body
    mac = hmac.new(password.encode('utf-8'), msg, hashlib.sha1).digest()
    msg += _attr(0x0008, mac)
    msg[2:4] = (len(msg) - 20 + 8).to_bytes(2, 'big')
    checksum = (zlib.crc32(msg) ^ _XOR) & 0xffffffff
    return bytes(msg) + _attr(0x8028, checksum.to_bytes(4, 'big'))


def _host_ip() -> str | None:
    """Resolve outbound IPv4 interface without sending a packet."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try:
            probe.connect(('8.8.8.8', 80))
            ip = probe.getsockname()[0]
        except OSError:
            return None
    return ip if ip and ip != '0.0.0.0' and not ip.startswith('127.') else None


class ControlledIceB85:
    def __init__(self, password: str):
        self._password = password
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._close = threading.Event()
        self._lock = threading.Lock()
        self._answered = 0
        self._requests = 0
        self._outcome = 'non_lance'

    def start(self) -> str | None:
        if not self._password or self._sock is not None:
            return None
        ip = _host_ip()
        if ip is None:
            self._outcome = 'adresse_ipv4_indisponible'
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(('0.0.0.0', 0))
            sock.settimeout(0.5)
        except OSError:
            sock.close()
            self._outcome = 'port_udp_indisponible'
            return None
        self._sock = sock
        # Never return candidate in a status response or persist local IP.
        foundation = zlib.crc32(ip.encode())
        candidate = f'a=candidate:{foundation} 1 udp 2130706431 {ip} {sock.getsockname()[1]} typ host\r\n'
        self._outcome = 'candidat_hote_pret'
        self._thread = threading.Thread(target=self._listen, name='aosu-ice-controlled-b85', daemon=True)
        self._thread.start()
        return candidate

    def _listen(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while not self._close.is_set():
            try:
                msg, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if (len(msg) < 20 or msg[:2] != b'\x00\x01' or
                msg[4:8] != _COOKIE.to_bytes(4, 'big') or
                (len(msg) - 20) != int.from_bytes(msg[2:4], 'big')):
                continue
            with self._lock:
                self._requests += 1
            try:
                response = binding_success(msg[8:20], peer[0], peer[1], self._password)
                sock.sendto(response, peer)
            except (OSError, ValueError):
                continue
            with self._lock:
                self._answered += 1
            self._outcome = 'reponse_stun_envoyee'

    def snapshot(self) -> dict:
        with self._lock:
            return {'etat': self._outcome, 'requetes_binding_recues': self._requests,
                    'reponses_binding_envoyees': self._answered,
                    'role': 'controlled', 'contenu_stun_conserve': False,
                    'adresse_ip_retournee': False, 'secret_retourne': False}

    def close(self) -> None:
        self._close.set()
        sock, self._sock = self._sock, None
        if sock is not None:
            sock.close()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=1)
        self._thread = None
