"""B105 — user-authorised single RTC configuration read for the H1L station candidate.

The local Tuya 3.4 authentication B104 established key possession at one LAN IP;
this diagnostic independently tests whether the OEM *station* exposes RTC media.
No offer, P2P connection, camera command, local key substitution, or secret output.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name
from .c9_h1l_preflight_b98 import _FRESH_SECONDS
from .tuya_rtc_inventory import _rtc_presence
from .tuya_media_bootstrap import inspect_rtc_media
from .c9_rtc_topology_b102 import _nodes, _code, _refs, _PARENT_KEYS, _NODE_KEYS

_LOCK = threading.Lock()
_NEXT_ALLOWED: dict[int, float] = {}
_COOLDOWN = 300


def audit_station_rtc_b105(coordinator: Any, *, confirm_candidate: bool,
                           confirm_rtc: bool, now: float | None = None) -> dict:
    report = {
        'diagnostic': 'aosu_h1l_rtc_station_b105',
        'lecture_seule': True,
        'candidat_station_confirme_manuellement': confirm_candidate is True,
        'lecture_rtc_autorisee': confirm_rtc is True,
        'appels_http': 0,
        'authentification_effectuee': False,
        'mot_de_passe_envoye': False,
        'offre_mqtt_envoyee': False,
        'connexion_p2p_demarre': False,
        'video_demarre': False,
        'commandes_camera_envoyees': 0,
        'commandes_ptz_envoyees': 0,
        'secret_retourne': False,
        'identifiants_retournes': False,
        'moteur_video_station_valide': False,
        'identite_station_par_serie_prouvee': False,
        'reponse_b104_utilisee_pour_video': False,
    }
    if confirm_candidate is not True or confirm_rtc is not True:
        return {**report, 'etat': 'double_confirmation_requise'}

    controller = getattr(coordinator, 'live_controller', None)
    if getattr(controller, 'running', False):
        return {**report, 'etat': 'direct_c5l_en_cours'}
    if controller is not None and callable(getattr(controller, 'status', None)):
        try:
            if controller.status().get('direct_actif') is True:
                return {**report, 'etat': 'direct_c5l_en_cours'}
        except (AttributeError, TypeError):
            return {**report, 'etat': 'etat_direct_c5l_indisponible'}

    client = getattr(coordinator, 'client', None)
    session = getattr(client, '_tuya_oem_session', None)
    cache = getattr(client, '_tuya_oem_inventory_cache', None)
    tick = time.monotonic() if now is None else now
    if (not isinstance(cache, dict) or not isinstance(cache.get('devices'), dict)
            or session is None or not isinstance(getattr(session, 'uid', None), str)
            or not session.uid or cache.get('session_uid') != session.uid
            or type(cache.get('created')) not in (int, float)
            or not 0 <= tick - cache['created'] < _FRESH_SECONDS
            or type(getattr(session, 'acquired_at', None)) not in (int, float)
            or not 0 <= tick - session.acquired_at < 1200):
        return {**report, 'etat': 'cache_oem_ou_session_absente_expiree'}

    data = getattr(coordinator, 'data', None)
    if not isinstance(data, dict):
        return {**report, 'etat': 'inventaire_aosu_absent'}
    # Validate all four AOSU ↔ OEM names and both C9 ↔ H1L associations;
    # the target remains a candidate, not an independently verified serial.
    c9did, alignment = _candidate(data, client, 1)
    if c9did is None or alignment.get('noms_uniques_concordants') != 4:
        return {**report, 'etat': 'correspondance_noms_non_coherente'}
    stations = [row for row in data.values() if isinstance(row, dict)
                and row.get('model') == 'H1L' and row.get('is_camera') is False]
    if len(stations) != 1 or not isinstance(stations[0].get('name'), str):
        return {**report, 'etat': 'station_h1l_non_unique'}
    devices = cache['devices']
    candidates = [did for did, obj in devices.items() if isinstance(obj, dict)
                  and _match_name(obj, stations[0]['name'])]
    if len(candidates) != 1 or candidates[0] == c9did:
        return {**report, 'etat': 'station_oem_ambigue'}
    station_id = candidates[0]
    local_key = devices[station_id].get('localKey')
    if not isinstance(local_key, str) or len(local_key.encode('utf-8')) != 16:
        return {**report, 'etat': 'cle_locale_station_absente'}
    report['station_candidate'] = {
        'concordance_quatre_noms': True,
        'cle_locale_station_presente': True,
        'authentification_lan_b104_non_reverifiee_ici': True,
        'camera_c9_1_cle_locale_absente': not bool(devices[c9did].get('localKey')),
    }

    from .tuya_rtc_inventory import _LOCK as OEM_LOCK, _LAST_RTC
    wait = max(_NEXT_ALLOWED.get(id(client), 0), _LAST_RTC.get(id(client), 0)) - tick
    if wait > 0:
        return {**report, 'etat': 'temporisation_rtc',
                'secondes_restantes': int(wait + .999)}
    if not _LOCK.acquire(blocking=False):
        return {**report, 'etat': 'audit_station_deja_en_cours'}
    try:
        if not OEM_LOCK.acquire(blocking=False):
            return {**report, 'etat': 'autre_action_oem_en_cours'}
        try:
            wait = max(_NEXT_ALLOWED.get(id(client), 0), _LAST_RTC.get(id(client), 0)) - tick
            if wait > 0:
                return {**report, 'etat': 'temporisation_rtc',
                        'secondes_restantes': int(wait + .999)}
            from .uid_token_probe import _ready_identity, _apk_preflight
            from .tuya_uid_gateway import TuyaAuthSession, OEMGatewayError, do_oem_read
            if not isinstance(session, TuyaAuthSession):
                return {**report, 'etat': 'session_oem_non_validee'}
            identity_ready = _ready_identity(client)
            if identity_ready is None:
                return {**report, 'etat': 'profil_oem_absent'}
            _, install_id = identity_ready
            _, apk_data = _apk_preflight(client.apk_path)
            if apk_data is None:
                return {**report, 'etat': 'ressources_oem_invalides'}
            identity, signer = apk_data
            _NEXT_ALLOWED[id(client)] = tick + _COOLDOWN
            _LAST_RTC[id(client)] = tick + _COOLDOWN
            report['appels_http'] = 1
            try:
                rtc, status = do_oem_read(
                    identity, signer, 'sha256_material', session,
                    action='thing.m.rtc.config.get', form_data={'devId': station_id},
                    ttid=f'sdk_international@{identity.app_id}',
                    device_id=install_id, endpoint='https://a1.tuyaeu.com/api.json',
                )
            except OEMGatewayError:
                return {**report, 'etat': 'erreur_api_oem'}
            except Exception:
                return {**report, 'etat': 'erreur_lecture_rtc_non_detaillee'}
            if not isinstance(status, dict) or not status.get('serveur_accepte') or status.get('rejet_explicite'):
                category = status.get('categorie_refus') if isinstance(status, dict) else None
                safe_categories = {'unsupported','busy','auth_expired','rate_limited','unauthorized'}
                return {**report, 'etat': 'rtc_station_refusee',
                        'categorie_refus': category if category in safe_categories else 'indeterminee'}
            report['structure_rtc_station'] = _rtc_presence(rtc)
            media, _private_never_exported = inspect_rtc_media(rtc, station_id, local_key, session.uid)
            # The private offer is deliberately not sent or persisted.
            report['media_station'] = media
            nodes = _nodes(rtc)
            station_mentioned = station_id in _refs(nodes, ('devId',))
            report['topologie_station'] = {
                'type_p2p_inventaire': _code(_nodes(devices[station_id]), 'p2pType'),
                'type_p2p_rtc': _code(nodes, 'p2pType'),
                'strategie_p2p_rtc': _code(nodes, 'p2pSpecifiedType'),
                'dev_id_rtc_correspond_station_candidate': station_mentioned,
                'champ_parent_present': bool(_refs(nodes, _PARENT_KEYS)),
                'champ_canal_secondaire_present': bool(_refs(nodes, _NODE_KEYS)),
                'identifiants_reels_masques': True,
            }
            report['etat'] = ('rtc_station_recue' if isinstance(rtc, dict)
                              else 'rtc_station_structure_inattendue')
            return report
        finally:
            OEM_LOCK.release()
    finally:
        _LOCK.release()
