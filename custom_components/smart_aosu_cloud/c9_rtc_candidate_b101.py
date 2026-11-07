"""B101: user-confirmed, ONE Tuya RTC configuration read for a C9 candidate.

Device names are not identity proofs, and this action MUST NOT enable streaming.
Require a consistent one-to-one four-name inventory; request RTC only after an
explicit per-camera consent. No credentials, account values or SDK IDs are output.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from .c9_h1l_preflight_b98 import _safe_index, _FRESH_SECONDS
from .c9_h1l_identity_structure_b99 import _match_name, _presence
from .c9_h1l_oem_detail_b100 import _TOKEN
from .tuya_rtc_inventory import _rtc_presence

_LOCK = threading.Lock()
_COOLDOWN = 300
_NEXT_ALLOWED: dict[int, float] = {}


def _candidate(data: dict, client: Any, number: int) -> tuple[str | None, dict]:
    """Return opaque OEM id only after a full, unique 4-device name alignment."""
    index = _safe_index(data, getattr(client, '_device_sn_index', None))
    rows = [(key, row) for key, row in data.items() if isinstance(row, dict)
            and key in index and row.get('model') in ('C9C3CA11', 'C5L', 'H1L')]
    if len(rows) != 4 or len(index) != len(data):
        return None, {'etat': 'inventaire_aosu_non_conforme'}
    cams = sorted(((key, row) for key, row in rows
                   if row.get('model') == 'C9C3CA11' and row.get('is_camera') is True),
                  key=lambda item: index[item[0]][0])
    bases = [(key, row) for key, row in rows if row.get('model') == 'H1L' and row.get('is_camera') is False]
    c5ls = [(key, row) for key, row in rows if row.get('model') == 'C5L' and row.get('is_camera') is True]
    if (len(cams) != 2 or len(bases) != 1 or len(c5ls) != 1
            or not all(row.get('via_device') == bases[0][0] for _, row in cams)):
        return None, {'etat': 'liaison_h1l_non_conforme'}
    cache = getattr(client, '_tuya_oem_inventory_cache', {})
    devices = cache.get('devices', {}) if isinstance(cache, dict) else {}
    if len(devices) != 4 or any(not isinstance(did, str) or not _TOKEN.fullmatch(did)
                                 or not isinstance(obj, dict) for did, obj in devices.items()):
        return None, {'etat': 'inventaire_tuya_non_conforme'}
    # Four distinct AOSU names, four distinct Tuya names and a full bijection.
    if any(not isinstance(row.get('name'), str) or not 1 <= len(row['name'].strip()) <= 100 for _, row in rows):
        return None, {'etat': 'noms_aosu_incomplets'}
    names = [row['name'].strip().casefold() for _, row in rows]
    if len(set(names)) != 4:
        return None, {'etat': 'noms_aosu_non_uniques'}
    matches = {}
    for key, row in rows:
        candidates = [did for did, item in devices.items() if _match_name(item, row['name'])]
        if len(candidates) != 1:
            return None, {'etat': 'correspondance_noms_incomplete_ou_ambigue'}
        matches[key] = candidates[0]
    if len(set(matches.values())) != 4:
        return None, {'etat': 'correspondance_noms_non_bijective'}
    target_key = cams[number-1][0]
    did = matches[target_key]
    item = devices[did]
    if not _presence(item, 'p2pType') or not _presence(item, 'skills'):
        return None, {'etat': 'candidat_sans_indice_p2p'}
    return did, {'etat': 'candidat_concordance_quatre_noms',
                 'numero_camera_aosu': number,
                 'numero_tuya_anonyme': sorted(devices).index(did)+1,
                 'noms_uniques_concordants': 4,
                 'identite_par_serie_prouvee': False,
                 'relation_base_aosu_confirmee': True,
                 'selection_automatique_pour_video_autorisee': False,
                 'cle_locale_presente': isinstance(item.get('localKey'), str) and bool(item['localKey'])}


def read_c9_rtc_b101(coordinator: Any, *, camera_number: Any,
                     confirm_candidate: bool, confirm_rtc: bool,
                     now: float | None = None) -> dict:
    """Request one RTC config for explicitly chosen probable C9; never store it."""
    report = {'diagnostic': 'aosu_rtc_c9_candidate_b101',
              'lecture_configuration_rtc': False,
              'appels_http': 0, 'nouvelle_authentification': False,
              'mot_de_passe_envoye': False, 'offre_mqtt_envoyee': False,
              'connexion_p2p_demarre': False, 'video_demarre': False,
              'commandes_camera_envoyees': 0, 'commandes_ptz_envoyees': 0,
              'identifiants_prives_retournes': False,
              'noms_prives_retournes': False, 'secret_retourne': False,
              'selection_video_autorisee': False,
              'consentement_candidat': confirm_candidate is True,
              'consentement_rtc': confirm_rtc is True}
    if type(camera_number) is not int or camera_number not in (1, 2):
        return {**report, 'etat': 'numero_camera_invalide_1_ou_2'}
    report['numero_camera_aosu'] = camera_number
    if confirm_candidate is not True or confirm_rtc is not True:
        return {**report, 'etat': 'confirmation_candidat_et_rtc_requise'}
    if getattr(getattr(coordinator, 'live_controller', None), 'running', False):
        return {**report, 'etat': 'direct_c5l_en_cours'}
    client = getattr(coordinator, 'client', None)
    cache = getattr(client, '_tuya_oem_inventory_cache', None)
    session = getattr(client, '_tuya_oem_session', None)
    tick = time.monotonic() if now is None else now
    if (not isinstance(cache, dict) or not isinstance(cache.get('devices'), dict)
            or session is None or not isinstance(getattr(session, 'uid', None), str)
            or not session.uid or cache.get('session_uid') != session.uid
            or type(cache.get('created')) not in (int, float)
            or not 0 <= tick-cache['created'] < _FRESH_SECONDS
            or type(getattr(session, 'acquired_at', None)) not in (int, float)
            or not 0 <= tick-session.acquired_at < 1200):
        return {**report, 'etat': 'cache_oem_ou_session_absente_expiree'}
    data = getattr(coordinator, 'data', None)
    if not isinstance(data, dict):
        return {**report, 'etat': 'inventaire_aosu_absent'}
    did, pairing = _candidate(data, client, camera_number)
    report['candidat'] = pairing
    if did is None:
        return {**report, 'etat': 'candidat_non_selectionnable'}
    # Share the original RTC rate limit and lock with other OEM diagnostics.
    from .tuya_rtc_inventory import _LOCK as OEM_LOCK, _LAST_RTC
    remaining = max(_NEXT_ALLOWED.get(id(client), 0), _LAST_RTC.get(id(client), 0))-tick
    if remaining > 0:
        return {**report, 'etat': 'temporisation_rtc', 'secondes_restantes': int(remaining + 0.999)}
    if not _LOCK.acquire(blocking=False):
        return {**report, 'etat': 'audit_rtc_deja_en_cours'}
    try:
        if not OEM_LOCK.acquire(blocking=False):
            return {**report, 'etat': 'autre_action_oem_en_cours'}
        try:
            remaining = max(_NEXT_ALLOWED.get(id(client), 0), _LAST_RTC.get(id(client), 0))-tick
            if remaining > 0:
                return {**report, 'etat': 'temporisation_rtc', 'secondes_restantes': int(remaining + .999)}
            from .uid_token_probe import _ready_identity, _apk_preflight
            from .tuya_uid_gateway import TuyaAuthSession, OEMGatewayError, do_oem_read
            if not isinstance(session, TuyaAuthSession):
                return {**report, 'etat': 'session_oem_non_validee'}
            ready = _ready_identity(client)
            if ready is None:
                return {**report, 'etat': 'profil_oem_absent'}
            _, install_id = ready
            _, parsed = _apk_preflight(client.apk_path)
            if parsed is None:
                return {**report, 'etat': 'ressources_oem_invalides'}
            identity, signer = parsed
            # Requesting RTC may provision a session server-side. It is not
            # a video handshake, but the user must explicitly authorize it.
            _NEXT_ALLOWED[id(client)] = tick + _COOLDOWN
            _LAST_RTC[id(client)] = tick + _COOLDOWN
            report['appels_http'] = 1
            report['lecture_configuration_rtc'] = True
            try:
                rtc, status = do_oem_read(
                    identity, signer, 'sha256_material', session,
                    action='thing.m.rtc.config.get', form_data={'devId': did},
                    ttid=f'sdk_international@{identity.app_id}', device_id=install_id,
                    endpoint='https://a1.tuyaeu.com/api.json')
            except OEMGatewayError:
                return {**report, 'etat': 'erreur_api_oem'}
            except Exception:
                return {**report, 'etat': 'erreur_lecture_rtc_non_detaillee'}
            if not status.get('serveur_accepte') or status.get('rejet_explicite'):
                return {**report, 'etat': 'rtc_refusee',
                        'categorie_refus': status.get('categorie_refus', 'indeterminee')}
            report['structure_rtc'] = _rtc_presence(rtc)
            from .tuya_media_bootstrap import inspect_rtc_media
            localkey = cache['devices'][did].get('localKey', '')
            media_report, _private_unused = inspect_rtc_media(
                rtc, did, localkey if isinstance(localkey, str) else '', session.uid)
            report['media'] = media_report
            from .c9_rtc_topology_b102 import inspect_rtc_topology_b102
            report['topologie_b102'] = inspect_rtc_topology_b102(
                rtc, did, pairing, data, cache['devices'])
            # Deliberately do not persist media bootstrap or expose any keys.
            report['etat'] = 'rtc_recue_schema_analyse' if isinstance(rtc, dict) else 'rtc_recue_structure_inattendue'
            return report
        finally:
            OEM_LOCK.release()
    finally:
        _LOCK.release()
