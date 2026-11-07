"""B107: opt-in, one-shot Tuya 3.4 DP_QUERY_NEW to the authenticated H1L candidate.

A reference trace shows 0x03 -> 0x04 -> 0x05 -> 0x10 -> 0x10 reply on
<H1L_IPV4>:6668. This reproduces only that read-only transaction.
It never sends CONTROL or UPDATEDPS, starts video, or exports device values.
The OEM local key is kept solely in memory. Session key is bound to two fresh
nonces. One session is closed immediately after reading the response.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import struct
import threading
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_auth_b104 import _aes_decrypt, _exact, _pack, _read_response, _PREFIX, _SUFFIX
from .h1l_local_probe_b103 import _validate_target

_LOCK = threading.Lock()
_NEXT_ALLOWED: dict[str, float] = {}
_COOLDOWN_SECONDS = 300
# This is a *local* read that cryptographically verifies the key for every use.
# Unlike cloud RTC tests, it does not need a live OEM login: retained RAM cache
# from the same account is acceptable for up to 12 hours.
_MAX_CACHE_SECONDS = 12 * 3600
_MAX_FRAME = 8192


def _session_key(local_key: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes:
    if any(len(x) != 16 for x in (local_key, client_nonce, server_nonce)):
        raise ValueError('invalid nonce or key length')
    mixed = bytes(a ^ b for a, b in zip(client_nonce, server_nonce))
    crypt = Cipher(algorithms.AES(local_key), modes.ECB()).encryptor()
    return crypt.update(mixed) + crypt.finalize()  # No padding for key derivation.


class _SafeStatusProtocolError(ValueError):
    """Fixed non-sensitive error class. Never propagate frame or key contents."""

    _ALLOWED = frozenset({
        'prefix_invalide', 'taille_invalide', 'trame_incomplete',
        'fin_trame_invalide', 'hmac_avec_cle_locale_initiale',
        'hmac_session_invalide', 'chiffrement_invalide',
        'code_reponse_non_zero', 'dechiffrement_invalide',
    })

    def __init__(self, code: str, *, command: int | None = None,
                 retcode: int | None = None) -> None:
        super().__init__(code if code in self._ALLOWED else 'reponse_protocole_invalide')
        self.code = code if code in self._ALLOWED else 'reponse_protocole_invalide'
        # Only discrete safe metadata, never encrypted data or device identifiers.
        self.command_type = ('lecture_0x10' if command == 0x10 else
                             'heartbeat_0x09' if command == 0x09 else
                             'etat_0x08' if command == 0x08 else
                             'autre' if command is not None else 'inconnu')
        self.return_code = retcode if type(retcode) is int and 0 < retcode < 256 else None


def _read_status_frame(sock: Any, session_key: bytes,
                       *, initial_key: bytes | None = None) -> tuple[int, bytes]:
    """Authenticate Tuya 3.4 response; classify failures without exposing bytes.

    The optional initial key is used *only* to classify a failed HMAC, never to
    authenticate, decrypt, or accept a message. A failed session HMAC always
    stops processing before decryption.
    """
    try:
        head = _exact(sock, 16)
    except ValueError:
        raise _SafeStatusProtocolError('trame_incomplete') from None
    if head[:4] != _PREFIX:
        raise _SafeStatusProtocolError('prefix_invalide')
    _sequence, command, length = struct.unpack('>III', head[4:])
    if not 40 <= length <= _MAX_FRAME:
        raise _SafeStatusProtocolError('taille_invalide')
    try:
        body = _exact(sock, length)
    except ValueError:
        raise _SafeStatusProtocolError('trame_incomplete') from None
    if body[-4:] != _SUFFIX:
        raise _SafeStatusProtocolError('fin_trame_invalide')
    signed = head + body[:-36]
    observed = body[-36:-4]
    session_valid = hmac.compare_digest(
        hmac.new(session_key, signed, hashlib.sha256).digest(), observed)
    if not session_valid:
        # Diagnostic only: never accept the packet under the initial key.
        if initial_key is not None and len(initial_key) == 16 and hmac.compare_digest(
            hmac.new(initial_key, signed, hashlib.sha256).digest(), observed
        ):
            raise _SafeStatusProtocolError('hmac_avec_cle_locale_initiale')
        raise _SafeStatusProtocolError('hmac_session_invalide')
    if len(body) < 40 or (len(body)-40) % 16:
        raise _SafeStatusProtocolError('chiffrement_invalide')
    returned_code = int.from_bytes(body[:4], 'big')
    if returned_code != 0:
        raise _SafeStatusProtocolError('code_reponse_non_zero',
                                       command=command, retcode=returned_code)
    payload = body[4:-36]
    if not payload:
        return command, b''
    try:
        plaintext = _aes_decrypt(session_key, payload)
    except ValueError:
        raise _SafeStatusProtocolError('dechiffrement_invalide') from None
    return command, plaintext


def _safe_structure(payload: bytes) -> dict:
    """Whitelist structural counts, never raw IDs, DP names, DP values or text."""
    if not payload or len(payload) > _MAX_FRAME:
        return {'objet_json_valide': False, 'dps_present': False, 'nombre_dps': 0,
                'relation_appareils_secondaires_presente': False,
                'noms_ou_valeurs_retournes': False}
    try:
        data = json.loads(payload.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError, ValueError):
        data = None
    if not isinstance(data, dict):
        return {'objet_json_valide': False, 'dps_present': False, 'nombre_dps': 0,
                'relation_appareils_secondaires_presente': False,
                'noms_ou_valeurs_retournes': False}
    dps = data.get('dps')
    if not isinstance(dps, dict):
        nested = data.get('data')
        if isinstance(nested, dict):
            dps = nested.get('dps')
    # These are only schema indicators, never identifiers or values.
    child_keys = frozenset({'subDic','subDevices','subDeviceList','subDevList',
                            'subDevInfos','nodeId','nodes','channelId',
                            'channelList','deviceList'})
    children = False
    for obj in (data, data.get('data') if isinstance(data.get('data'), dict) else None):
        if isinstance(obj, dict) and any(k in obj for k in child_keys):
            children = True
    return {
        'objet_json_valide': True,
        'dps_present': isinstance(dps, dict),
        'nombre_dps': min(len(dps), 1000) if isinstance(dps, dict) else 0,
        'relation_appareils_secondaires_presente': children,
        'contenu_dps_analyse': False,
        'noms_ou_valeurs_retournes': False,
    }


def _read_station_status_once(ip: str, key: bytes) -> dict:
    """One active read: 0x03 0x05 0x10, never command 0x07/0x0d."""
    status = {'tcp_connecte': False, 'challenge_authentifie': False,
              'confirmation_session_envoyee': False, 'session_tuya34_validee': False,
              'commande_lecture_envoyee': 0,
              'code_lecture': '0x10', 'reponse_lecture_authentifiee': False,
              'commandes_ecriture_envoyees': 0, 'commandes_video_envoyees': 0,
              'commandes_ptz_envoyees': 0, 'secret_retourne': False,
              'etat_local': 'non_lance',
              'etape_b109': 'avant_connexion',
              'cause_precise_b109': 'aucune'}
    nonce = os.urandom(16)
    seq = (int.from_bytes(os.urandom(4), 'big') & 0x7fffffff) or 1
    try:
        with socket.create_connection((ip, 6668), timeout=3) as sock:
            status['tcp_connecte'] = True
            status['etape_b109'] = 'authentification_challenge'
            sock.settimeout(3)
            sock.sendall(_pack(key, seq, 3, nonce))
            command, answer = _read_response(sock, key)
            if command != 4 or len(answer) != 48:
                status['etat_local'] = 'challenge_inattendu'
                return status
            server_nonce, proof = answer[:16], answer[16:]
            if not hmac.compare_digest(proof, hmac.new(key, nonce, hashlib.sha256).digest()):
                status['etat_local'] = 'preuve_challenge_invalide'
                return status
            status['challenge_authentifie'] = True
            session_key = _session_key(key, nonce, server_nonce)
            sock.sendall(_pack(key, seq+1, 5, hmac.new(key, server_nonce, hashlib.sha256).digest()))
            status['confirmation_session_envoyee'] = True  # HMAC challenge verified; session not yet proven.
            status['etape_b109'] = 'attente_reponse_lecture'
            # Tuya 3.4 DP_QUERY_NEW requires the JSON object '{}', not zero
            # plaintext bytes. Both encrypt into a 16-byte PKCS#7 block,
            # so packet length alone cannot reveal this difference in a PCAP.
            sock.sendall(_pack(session_key, seq+2, 0x10, b'{}'))
            status['commande_lecture_envoyee'] = 1
            # Only known read-only response types: DP_QUERY_NEW and HEART_BEAT.
            for _ in range(3):
                cmd, payload = _read_status_frame(sock, session_key, initial_key=key)
                status['type_reponse_b109'] = ('lecture_0x10' if cmd == 0x10 else
                                               'heartbeat_0x09' if cmd == 0x09 else
                                               'etat_0x08' if cmd == 0x08 else 'autre')
                if cmd == 0x10:
                    status['reponse_lecture_authentifiee'] = True
                    status['session_tuya34_validee'] = True
                    status['structure'] = _safe_structure(payload)
                    status['etat_local'] = 'lecture_statut_authentifiee'
                    status['etape_b109'] = 'lecture_verifiee'
                    return status
                if cmd not in (0x09, 0x08):
                    status['etat_local'] = 'reponse_inattendue'
                    return status
            status['etat_local'] = 'aucune_reponse_statut'
    except socket.timeout:
        status['etat_local'] = 'delai_depasse'
        status['cause_precise_b109'] = 'timeout'
    except (OSError, EOFError):
        status['etat_local'] = 'erreur_reseau_ou_connexion_fermee'
        status['cause_precise_b109'] = 'connexion_fermee'
    except _SafeStatusProtocolError as error:
        status['etat_local'] = 'reponse_authentification_invalide'
        status['cause_precise_b109'] = error.code
        if error.code == 'code_reponse_non_zero':
            status['type_reponse_b110'] = error.command_type
            status['code_retour_tuya_b110'] = error.return_code
    except ValueError:
        status['etat_local'] = 'reponse_authentification_invalide'
        status['cause_precise_b109'] = 'challenge_ou_format_invalide'
    except Exception:
        status['etat_local'] = 'erreur_protocole_non_detaillee'
        status['cause_precise_b109'] = 'erreur_interne_non_detaillee'
    return status


def audit_h1l_read_status_b107(coordinator: Any, *, ip_station: object,
                               confirm_station: bool, confirm_read: bool,
                               now: float | None = None) -> dict:
    report = {
        'diagnostic': 'aosu_h1l_statut_local_b107',
        'lecture_seule': True, 'appels_http': 0, 'login_tuya': False,
        'rtc_demande': False, 'mqtt_offre': False, 'udp_kcp_demarre': False,
        'session_video_creee': False, 'commandes_camera': 0,
        'commandes_ptz': 0, 'identifiants_retournes': False,
        'cle_locale_retournee': False, 'noms_retournes': False,
        'consentement_station': confirm_station is True,
        'consentement_lecture': confirm_read is True,
        'station_par_serie_prouvee': False,
    }
    try:
        ip = _validate_target(ip_station)
    except ValueError:
        return {**report, 'etat': 'adresse_lan_invalide'}
    if confirm_station is not True or confirm_read is not True:
        return {**report, 'etat': 'double_confirmation_requise'}
    controller = getattr(coordinator, 'live_controller', None)
    if controller is not None and getattr(controller, 'running', False):
        return {**report, 'etat': 'direct_c5l_en_cours'}
    if controller is not None and callable(getattr(controller, 'status', None)):
        try:
            if controller.status().get('direct_actif') is True:
                return {**report, 'etat': 'direct_c5l_en_cours'}
        except (AttributeError, TypeError):
            return {**report, 'etat': 'statut_c5l_indisponible'}
    client = getattr(coordinator, 'client', None)
    cache = getattr(client, '_tuya_oem_inventory_cache', None)
    session = getattr(client, '_tuya_oem_session', None)
    tick = time.monotonic() if now is None else now
    if not isinstance(cache, dict) or not isinstance(cache.get('devices'), dict) or \
       type(cache.get('created')) not in (int, float) or \
       not 0 <= tick - cache['created'] < _MAX_CACHE_SECONDS or \
       session is None or not isinstance(getattr(session, 'uid', None), str) or \
       not session.uid or cache.get('session_uid') != session.uid:
        return {**report, 'etat': 'cache_station_absent_ou_compte_different',
                'cache_local_12h_autorise': True}
    data = getattr(coordinator, 'data', None)
    if not isinstance(data, dict):
        return {**report, 'etat': 'inventaire_aosu_absent'}
    c9_id, mapping = _candidate(data, client, 1)
    if c9_id is None:
        return {**report, 'etat': 'inventaires_non_coherents',
                'cause': mapping.get('etat', 'inconnue')}
    bases = [(k, row) for k, row in data.items() if isinstance(row, dict)
             and row.get('model') == 'H1L' and row.get('is_camera') is False]
    if len(bases) != 1:
        return {**report, 'etat': 'station_aosu_ambigue'}
    station_matches = [(did, device) for did, device in cache['devices'].items()
                       if isinstance(device, dict) and _match_name(device, bases[0][1].get('name'))]
    if len(station_matches) != 1 or station_matches[0][0] == c9_id:
        return {**report, 'etat': 'station_tuya_ambigue'}
    raw_key = station_matches[0][1].get('localKey')
    if not isinstance(raw_key, str) or len(raw_key.encode('utf-8')) != 16:
        return {**report, 'etat': 'cle_locale_station_absente'}
    remaining = _NEXT_ALLOWED.get(ip, 0) - tick
    if remaining > 0:
        return {**report, 'etat': 'temporisation_locale',
                'secondes_restantes': int(remaining + .999)}
    if not _LOCK.acquire(blocking=False):
        return {**report, 'etat': 'autre_lecture_locale_en_cours'}
    try:
        remaining = _NEXT_ALLOWED.get(ip, 0) - tick
        if remaining > 0:
            return {**report, 'etat': 'temporisation_locale',
                    'secondes_restantes': int(remaining + .999)}
        _NEXT_ALLOWED[ip] = tick + _COOLDOWN_SECONDS
        outcome = _read_station_status_once(ip, raw_key.encode('utf-8'))
    finally:
        _LOCK.release()
    return {**report, **outcome, 'ip_station': ip, 'port_tcp': 6668,
            'cache_station_en_ram_reutilise': True,
            'session_oem_recente_non_requise': True,
            'etat': outcome.get('etat_local', 'erreur')}
