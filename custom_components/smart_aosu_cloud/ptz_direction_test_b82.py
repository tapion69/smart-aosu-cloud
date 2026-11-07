"""B82 – opt-in one direction PTZ probe (up/down/left), fixed STOP + watchdog.

Important: no permanent PTZ controls. Runtime DP schema not certified. STOP DP 116
was *physically observed* working by the owner with the B79 service, but cannot
be sensed by the integration. The official app is required as an emergency fallback.
No automatic startup actions, no raw identifiers or secret-bearing replies.
"""
from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

from . import ptz_stop_probe_b40 as previous_stop
from .ptz_stop_alternate_api_b79 import publish_alternate_stop_once

# The test is intentionally not a generic PTZ transmitter: no arbitrary DP,
# value, duration, API target, or number of movements are accepted.
_MOVE_DP = '119'
_DIRECTIONS = {'haut': '0', 'bas': '4', 'gauche': '6'}  # Tuya IPC standard. Only 'droite' physically proven on C5L B81.
_MOVE_DURATION_S = .35
_WATCHDOG_AFTER_S = 1.5
_MOVE_COOLDOWN_S = 300
from .ptz_right_test_b81 import _NEXT_MOVE  # Shared movement cooldown with B81; both share b40 lock.


def _session_and_camera(coordinator: Any):
    """Reuse B79's proven OEM auth and camera selection; no secrets returned."""
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_readiness import _ptz_flags
    from .uid_token_probe import _ready_identity, _apk_preflight
    from .tuya_uid_gateway import TuyaAuthSession, OEMGatewayError, do_uid_login_request
    selected, reason = select_c5l_oem(coordinator)
    if selected is None:
        raise OEMGatewayError(reason)
    dev_id, row, selection_method = selected
    if selection_method not in ('identification_exacte', 'nom_unique_confirme_par_utilisateur'):
        raise OEMGatewayError('camera_oem_non_confirmee')
    flags = _ptz_flags(row)
    if not (flags.get('code_direction_repere') and flags.get('code_arret_repere')):
        raise OEMGatewayError('codes_ptz_non_reperes')
    client = coordinator.client
    profile = _ready_identity(client)
    if profile is None:
        raise OEMGatewayError('profil_oem_absent')
    hints, install_id = profile
    _, material = _apk_preflight(client.apk_path)
    if material is None:
        raise OEMGatewayError('ressources_oem_invalides')
    identity, signer = material
    ttid = f'sdk_international@{identity.app_id}'
    now = time.monotonic()
    session = getattr(client, '_tuya_oem_session', None)
    calls = 0
    if not isinstance(session, TuyaAuthSession) or not 0 <= now - session.acquired_at < 1200:
        passwd = getattr(client, 'password', None)
        if not isinstance(passwd, str) or not passwd:
            raise OEMGatewayError('mot_de_passe_absent')
        auth, session = do_uid_login_request(identity, signer, 'sha256_material',
            uid=hints.tuya_username, country_code=hints.country_code,
            password=passwd, ttid=ttid, device_id=install_id,
            endpoint='https://a1.tuyaeu.com/api.json')
        calls += int(auth.get('appel_reseau', 0))
        if session is None:
            raise OEMGatewayError('authentification_refusee', calls)
        client._tuya_oem_session = session
    return identity, signer, session, dev_id, ttid, install_id, selection_method, calls


def _direction_once(identity: Any, signer: Any, session: Any, dev_id: str,
                    ttid: str, install_id: str, *, direction: str) -> bool:
    """Publish one preapproved direction using the B79/B81 tested HTTP API."""
    if direction not in _DIRECTIONS:
        raise ValueError("direction_invalide")
    from .tuya_uid_gateway import OEMGatewayError, TuyaAuthSession, _call_api
    if not isinstance(session, TuyaAuthSession):
        raise OEMGatewayError('session_tuya_absente')
    if not isinstance(dev_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}', dev_id):
        raise OEMGatewayError('identifiant_non_compatible')
    _outer, _decoded, status = _call_api(identity, signer, 'sha256_material',
        action='thing.m.nb.device.dp.publish', api_version='1.0',
        form_data={'devId': dev_id, 'dps': json.dumps({_MOVE_DP: _DIRECTIONS[direction]}, separators=(',', ':'))},
        ttid=ttid, device_id=install_id,
        endpoint='https://a1.tuyaeu.com/api.json', session=session)
    return status.get('acceptation_explicite') is True and status.get('rejet_explicite') is not True


def _base(direction: str):
    return {'diagnostic': 'aosu_mouvement_direction_b82',
            'essai_experimental': True, 'lecture_seule': False,
            'api_utilisee': 'thing.m.nb.device.dp.publish',
            'direction_demandee': direction if direction in _DIRECTIONS else 'invalide',
            'valeur_direction_candidat': _DIRECTIONS.get(direction), 'identifiant_direction_candidat': 119,
            'direction_envoyee': False, 'direction_acceptee_serveur': False,
            'stop_tente': False, 'stop_accepte_serveur': False,
            'stop_secours_tente': False, 'stop_secours_accepte_serveur': False,
            'stop_secours_programme': False, 'stop_secours_acheve_au_retour': False,
            'mouvement_physique_confirme': False, 'arret_physique_confirme': False,
            'camera_c5l_schema_certifie': False, 'video_modifiee': False,
            'identifiants_retournes': False, 'secrets_retournes': False,
            'appels_reseau': 0, 'duree_commande_s': _MOVE_DURATION_S,
            'watchdog_s': _WATCHDOG_AFTER_S}


def try_direction_once(coordinator: Any, *, direction: str, password_confirmed: bool = False,
                   camera_confirmed: bool = False, stop_verified_confirmed: bool = False,
                   physical_backup_confirmed: bool = False) -> dict:
    """Single bounded experiment. STOP even if direction response raises/times out.

    Watchdog independently attempts STOP if the HTTP request is delayed. It is
    *best effort*, not an absolute hardware guarantee in a network outage.
    """
    from .tuya_uid_gateway import OEMGatewayError
    out = _base(direction)
    if direction not in _DIRECTIONS:
        return {**out, 'etat': 'direction_invalide'}
    if not all(x is True for x in (password_confirmed, camera_confirmed,
                                    stop_verified_confirmed, physical_backup_confirmed)):
        return {**out, 'etat': 'quatre_confirmations_requises'}
    if getattr(getattr(coordinator, 'live_controller', None), 'running', False):
        return {**out, 'etat': 'direct_home_assistant_en_cours'}
    client = coordinator.client
    if _NEXT_MOVE.get(id(client), 0) > time.monotonic():
        return {**out, 'etat': 'temporisation_mouvement',
                'delai_restant_secondes': int(_NEXT_MOVE[id(client)] - time.monotonic()) + 1}
    if not previous_stop._LOCK.acquire(blocking=False):
        return {**out, 'etat': 'autre_essai_ptz_en_cours'}
    try:
        if _NEXT_MOVE.get(id(client), 0) > time.monotonic():
            return {**out, 'etat': 'temporisation_mouvement'}
        # Reuse existing b79 cooldown to avoid conflicts with its STOP probe.
        if previous_stop._RETRY_AFTER.get(id(client), 0) > time.monotonic():
            return {**out, 'etat': 'temporisation_essai_arret_b79'}
        try:
            params = _session_and_camera(coordinator)
            identity, signer, session, dev_id, ttid, install_id, selection, auth_calls = params
            out['appels_reseau'] += auth_calls
            out['selection_oem'] = selection
        except OEMGatewayError as exc:
            return {**out, 'etat': 'preparation_impossible', 'raison': exc.code}
        except Exception:
            return {**out, 'etat': 'preparation_impossible'}
        # Reserve the cooldown even for failures once we initiate physical motion.
        _NEXT_MOVE[id(client)] = time.monotonic() + _MOVE_COOLDOWN_S
        previous_stop._RETRY_AFTER[id(client)] = time.monotonic() + 60
        watchdog_cancel = threading.Event()
        watchdog_done = threading.Event()
        watchdog_result = {'attempted': False, 'accepted': False}

        def backup_stop():
            # Do not log any secret-bearing payload or server response.
            try:
                if not watchdog_cancel.wait(_WATCHDOG_AFTER_S):
                    watchdog_result['attempted'] = True
                    r = publish_alternate_stop_once(identity, signer, session,
                        dev_id=dev_id, ttid=ttid, device_id=install_id)
                    watchdog_result['accepted'] = bool(r.get('publication_acceptee_par_serveur'))
            except Exception:
                pass
            finally:
                watchdog_done.set()

        watchdog = threading.Thread(target=backup_stop, daemon=True, name='smart-aosu-b82-stop')
        watchdog.start()
        # Direction and STOP are never exposed as independent actions.
        try:
            out['direction_envoyee'] = True  # attempted; network request may fail
            out['appels_reseau'] += 1
            out['direction_acceptee_serveur'] = _direction_once(identity, signer, session,
                dev_id, ttid, install_id, direction=direction)
            if out['direction_acceptee_serveur']:
                time.sleep(_MOVE_DURATION_S)
                out['etat'] = 'direction_acceptee_arret_en_cours'
            else:
                out['etat'] = 'direction_non_acceptee'
        except OEMGatewayError as exc:
            out['etat'] = 'erreur_direction'; out['raison'] = exc.code
        except Exception:
            out['etat'] = 'erreur_direction'
        finally:
            # STOP even if direction rejected/exception: it may have reached camera.
            out['stop_tente'] = True
            out['appels_reseau'] += 1
            try:
                stop = publish_alternate_stop_once(identity, signer, session,
                    dev_id=dev_id, ttid=ttid, device_id=install_id)
                out['stop_accepte_serveur'] = bool(stop.get('publication_acceptee_par_serveur'))
            except Exception:
                pass
            if out['stop_accepte_serveur']:
                watchdog_cancel.set()
            else:
                out['stop_secours_programme'] = True
                # Keep backup active if main STOP fails; do not block for up to
                # 20 seconds waiting for the asynchronous attempt to finish.
                watchdog_done.wait(timeout=0.1)
            out['stop_secours_acheve_au_retour'] = watchdog_done.is_set()
            out['stop_secours_tente'] = bool(watchdog_result['attempted'])
            out['stop_secours_accepte_serveur'] = bool(watchdog_result['accepted'])
            out['appels_reseau'] += int(out['stop_secours_tente'])
        if not out['stop_accepte_serveur']:
            out['etat'] = 'stop_non_confirme_utiliser_application_aosu'
        elif out['direction_acceptee_serveur']:
            out['etat'] = 'direction_et_stop_acceptes_verifier_physiquement'
        return out
    finally:
        previous_stop._LOCK.release()


def try_direction_with_refresh(coordinator: Any, *, direction: str, **kwargs: Any) -> dict:
    """Manual-only refresh identical to B79; disabled without confirmations."""
    if direction not in _DIRECTIONS:
        return {**_base(direction), 'etat': 'direction_invalide'}
    confirmed = all(kwargs.get(k) is True for k in (
        'password_confirmed', 'camera_confirmed', 'stop_verified_confirmed',
        'physical_backup_confirmed'))
    if not confirmed or getattr(getattr(coordinator, 'live_controller', None), 'running', False):
        return try_direction_once(coordinator, direction=direction, **kwargs)
    from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
    state = audit_ptz_readiness(coordinator, coordinator.client)
    calls = 0
    if state.get('cache_oem_recent') is not True:
        fresh = refresh_ptz_inventory(coordinator, password_confirmed=True)
        calls = int(fresh.get('appels_reseau', 0))
        if fresh.get('etat') not in ('inventaire_oem_ptz_lu', 'cache_recent_reutilise'):
            return {**_base(direction), 'etat': 'actualisation_oem_impossible', 'appels_reseau': calls}
    result = try_direction_once(coordinator, direction=direction, **kwargs)
    return {**result, 'appels_reseau': result.get('appels_reseau', 0) + calls}


