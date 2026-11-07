"""B108: explicitly consented in-one-action OEM cache recovery + H1L LAN read.

Never persists the station local key. No silent OEM login, video, PTZ, or
network scan. The existing OEM rate limits and B107 LAN rate limit remain
in force. A cache created in an earlier Home Assistant process cannot survive
restart: "12 hours" means memory lifetime, not persistent storage.
"""
from __future__ import annotations

import time
from typing import Any

from .h1l_local_probe_b103 import _validate_target
from .h1l_local_status_b107 import audit_h1l_read_status_b107
from .tuya_rtc_inventory import run_tuya_oem_inventory

_MAX_CACHE_SECONDS = 12 * 3600


def _cache_state(client: Any, tick: float) -> str:
    """Anonymized account/cache preflight, without logging secrets."""
    if client is None:
        return 'client_absent'
    cache = getattr(client, '_tuya_oem_inventory_cache', None)
    if not isinstance(cache, dict) or not isinstance(cache.get('devices'), dict):
        return 'cache_absent'
    created = cache.get('created')
    if type(created) not in (int, float) or not 0 <= tick - created < _MAX_CACHE_SECONDS:
        return 'cache_expire'
    session = getattr(client, '_tuya_oem_session', None)
    if session is None or not isinstance(getattr(session, 'uid', None), str) or not session.uid:
        return 'session_absente'
    if cache.get('session_uid') != session.uid:
        return 'compte_different'
    return 'cache_utilisable'


def audit_h1l_local_status_b108(
    coordinator: Any, *, ip_station: object,
    confirm_station: bool, confirm_read: bool,
    autoriser_reconstitution_oem: bool = False,
    confirmation_envoi_mot_de_passe: bool = False,
    now: float | None = None,
) -> dict:
    """Validate consent, optionally repopulate OEM RAM cache, then run B107."""
    report = {
        'diagnostic': 'aosu_h1l_statut_local_b108',
        'lecture_locale_autorisee': confirm_read is True,
        'station_candidate_autorisee': confirm_station is True,
        'reconstitution_oem_autorisee': autoriser_reconstitution_oem is True,
        'envoi_mot_de_passe_autorise': confirmation_envoi_mot_de_passe is True,
        'appel_reseau_oem': 0, 'mot_de_passe_envoye': False,
        'authentification_oem_effectuee': False,
        'commande_video_envoyee': False, 'commande_ptz_envoyee': False,
        'donnees_privees_retournees': False,
        'cache_enregistre_sur_disque': False,
    }
    try:
        _validate_target(ip_station)
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
    tick = time.monotonic() if now is None else now
    state = _cache_state(client, tick)
    report['etat_cache_avant'] = state
    if state != 'cache_utilisable':
        if autoriser_reconstitution_oem is not True:
            return {**report, 'etat': 'reconstitution_oem_requise'}
        # An explicit, separate consent is required because OEM inventory may
        # have to send the configured AOSU password to Tuya over HTTPS.
        if confirmation_envoi_mot_de_passe is not True:
            return {**report, 'etat': 'confirmation_mot_de_passe_requise'}
        if client is None:
            return {**report, 'etat': 'client_absent'}
        try:
            inventory = run_tuya_oem_inventory(
                client, confirmation_envoi_mot_de_passe=True,
                tester_rtc=False, tester_mqtt=False, tester_offre_mqtt=False,
                tester_relais_tcp=False, tester_kcp=False, tester_media=False,
            )
        except Exception:
            return {**report, 'etat': 'erreur_reconstitution_oem_non_detaillee',
                    'mot_de_passe_envoye': None,
                    'note_mot_de_passe': 'envoi_indetermine_apres_erreur'}
        report['appel_reseau_oem'] = inventory.get('appel_reseau', 0)
        report['mot_de_passe_envoye'] = inventory.get('mot_de_passe_envoye') is True
        report['authentification_oem_effectuee'] = inventory.get('session_tuya_authentifiee') is True
        report['etat_reconstitution_oem'] = inventory.get('etat', 'indetermine')
        if inventory.get('etat') != 'inventaire_termine':
            return {**report, 'etat': 'reconstitution_oem_non_terminee'}
        state = _cache_state(client, time.monotonic() if now is None else now)
        report['etat_cache_apres'] = state
        if state != 'cache_utilisable':
            return {**report, 'etat': 'cache_non_valide_apres_reconstitution'}
    else:
        report['reconstitution_inutile'] = True
    # A separate B107 check revalidates the account, camera name bijection,
    # station candidate key and rate limit, then authenticates local Tuya 3.4.
    lan = audit_h1l_read_status_b107(
        coordinator, ip_station=ip_station, confirm_station=True,
        confirm_read=True, now=now,
    )
    # Whitelist B107's already-sanitized result; no OEM data is returned.
    return {**lan, **report, 'etat': lan.get('etat', 'erreur_locale')}
