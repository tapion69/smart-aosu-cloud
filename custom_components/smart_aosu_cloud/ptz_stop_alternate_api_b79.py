"""B79: strictly opt-in, single experimental STOP via SDK-observed alternate OEM API.

SDK (APK AOSU 5.10.12, classes4.dex #31068) includes an HTTP route
`thing.m.nb.device.dp.publish` v1.0 with devId + dps. Static code does NOT
prove C5L takes this route. The SDK's runtime ProductBean.capability is unknown.

This experiment never sends direction and never equates HTTP success with
motor STOP. No raw device IDs, keys, sessions, server messages or DP data
are returned. No retries, no MQTT, no video changes.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from . import ptz_stop_probe_b40 as old_stop


def publish_alternate_stop_once(identity: Any, signer: Any, session: Any, *,
                                dev_id: str, ttid: str, device_id: str) -> dict:
    """Only a single fixed STOP DP candidate; no caller-selected payload.

    In the absence of the device's actual runtime schemaMap, 116 is a *model
    abilityId candidate*, not a verified legacy DP identifier. Consequently,
    an HTTP acceptance is never reported as proof of camera execution.
    """
    from .tuya_uid_gateway import TuyaAuthSession, OEMGatewayError, _call_api, _safe_server_refusal
    if not isinstance(session, TuyaAuthSession) or not all(
            isinstance(getattr(session, key, None), str) and getattr(session, key)
            for key in ('sid', 'ecode', 'uid')):
        raise OEMGatewayError('session_tuya_absente')
    if not isinstance(dev_id, str) or re.fullmatch(r'[A-Za-z0-9_-]{5,128}', dev_id) is None:
        raise OEMGatewayError('identifiant_non_compatible')
    # SDK argument names confirmed in static analysis; the JSON-string DP
    # encoding is experimental. Never add movement, discovery or fallback.
    form_data = {'devId': dev_id,
                 'dps': json.dumps({'116': True}, separators=(',', ':'))}
    outer, decoded, status = _call_api(
        identity, signer, 'sha256_material',
        action='thing.m.nb.device.dp.publish', api_version='1.0',
        form_data=form_data, ttid=ttid, device_id=device_id,
        endpoint='https://a1.tuyaeu.com/api.json', session=session)
    accepted = status.get('acceptation_explicite') is True and status.get('rejet_explicite') is not True
    rejected = status.get('rejet_explicite') is True
    result = {'reponse_http_recue': True,
              'publication_acceptee_par_serveur': accepted,
              'publication_refusee_par_serveur': rejected,
              'arret_physique_confirme': False,
              'route_sdk_c5l_confirmee': False,
              'identifiant_dp_c5l_certifie': False,
              'type_dps_experimental': 'json_string'}
    if rejected:
        refusal = _safe_server_refusal(outer, decoded)
        result['categorie_refus'] = refusal.get('categorie_refus', 'indeterminee')
        if 'code_erreur_tuya' in refusal:
            result['code_erreur_tuya'] = refusal['code_erreur_tuya']
    return result


def test_alternate_stop_b79(coordinator: Any, *, password_confirmed: bool=False,
                            camera_confirmed: bool=False, stop_confirmed: bool=False,
                            unverified_dp_confirmed: bool=False) -> dict:
    """One STOP attempt, always manual and protected by four booleans.

    Shares b40/b45 stop lock and cooldown so experiments cannot race.
    """
    out = {'diagnostic': 'aosu_arret_api_alternative_b79',
           'lecture_seule': False, 'essai_experimental': True,
           'api_utilisee': 'thing.m.nb.device.dp.publish', 'version_api': '1.0',
           'commande_direction_envoyee': False, 'commande_arret_tentee': False,
           'commandes_arret_confirmees': 0, 'mqtt_publie': False,
           'video_modifiee': False, 'schema_dp_c5l_certifie': False,
           'branche_sdk_active_confirmee': False,
           'arret_physique_confirme': False, 'identifiants_retournes': False,
           'secrets_retournes': False, 'appels_reseau': 0}
    if not all(x is True for x in (
            password_confirmed, camera_confirmed, stop_confirmed,
            unverified_dp_confirmed)):
        return {**out, 'etat': 'quatre_confirmations_requises'}
    if getattr(getattr(coordinator, 'live_controller', None), 'running', False):
        return {**out, 'etat': 'direct_home_assistant_en_cours'}

    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_readiness import _ptz_flags
    from .tuya_uid_gateway import (TuyaAuthSession, OEMGatewayError, do_uid_login_request)
    from .uid_token_probe import _ready_identity, _apk_preflight
    selected, reason = select_c5l_oem(coordinator)
    if selected is None:
        return {**out, 'etat': reason}
    dev_id, row, method = selected
    if method not in ('identification_exacte', 'nom_unique_confirme_par_utilisateur'):
        return {**out, 'etat': 'camera_oem_non_confirmee'}
    flags = _ptz_flags(row)
    if not (flags['code_arret_repere'] and flags['code_direction_repere']):
        return {**out, 'etat': 'codes_ptz_non_reperes'}

    now = time.monotonic()
    retry_after = old_stop._RETRY_AFTER.get(id(coordinator.client), 0)
    if retry_after > now:
        return {**out, 'etat': 'temporisation_essai_arret',
                'delai_restant_secondes': int(retry_after - now) + 1}
    if not old_stop._LOCK.acquire(blocking=False):
        return {**out, 'etat': 'autre_essai_arret_en_cours'}
    try:
        now = time.monotonic()
        if old_stop._RETRY_AFTER.get(id(coordinator.client), 0) > now:
            return {**out, 'etat': 'temporisation_essai_arret'}
        if getattr(getattr(coordinator, 'live_controller', None), 'running', False):
            return {**out, 'etat': 'direct_home_assistant_en_cours'}
        # Reserve a ten-minute stop-experiment interval, including failures.
        old_stop._RETRY_AFTER[id(coordinator.client)] = now + 600
        client = coordinator.client
        profile = _ready_identity(client)
        if profile is None:
            return {**out, 'etat': 'profil_oem_absent'}
        hints, install_id = profile
        _, material = _apk_preflight(client.apk_path)
        if material is None:
            return {**out, 'etat': 'ressources_oem_invalides'}
        identity, signer = material
        ttid = f'sdk_international@{identity.app_id}'
        session = getattr(client, '_tuya_oem_session', None)
        if not isinstance(session, TuyaAuthSession) or not 0 <= now - session.acquired_at < 1200:
            session = None
        if session is None:
            password = getattr(client, 'password', None)
            if not isinstance(password, str) or not password:
                return {**out, 'etat': 'mot_de_passe_absent'}
            auth, session = do_uid_login_request(
                identity, signer, 'sha256_material', uid=hints.tuya_username,
                country_code=hints.country_code, password=password, ttid=ttid,
                device_id=install_id, endpoint='https://a1.tuyaeu.com/api.json')
            out['appels_reseau'] += int(auth.get('appel_reseau', 0))
            if session is None:
                return {**out, 'etat': 'authentification_refusee'}
            client._tuya_oem_session = session
        out['commande_arret_tentee'] = True
        out['appels_reseau'] += 1
        response = publish_alternate_stop_once(identity, signer, session,
            dev_id=dev_id, ttid=ttid, device_id=install_id)
        return {**out, **response, 'selection_oem': method,
                'etat': ('serveur_accepte_sans_preuve_camera' if response.get('publication_acceptee_par_serveur')
                         else 'serveur_refuse_ou_resultat_non_concluant')}
    except OEMGatewayError as exc:
        return {**out, 'etat': 'erreur_api_oem', 'raison': exc.code}
    except Exception:
        return {**out, 'etat': 'erreur_sans_details'}
    finally:
        old_stop._LOCK.release()


def test_alternate_stop_b79_with_refresh(coordinator: Any, *, password_confirmed=False,
                                          camera_confirmed=False, stop_confirmed=False,
                                          unverified_dp_confirmed=False) -> dict:
    """Consent before OEM refresh; otherwise no network calls at all."""
    confirmed = all(x is True for x in (
        password_confirmed, camera_confirmed, stop_confirmed, unverified_dp_confirmed))
    if not confirmed or getattr(getattr(coordinator, 'live_controller', None), 'running', False):
        return test_alternate_stop_b79(coordinator, password_confirmed=password_confirmed,
            camera_confirmed=camera_confirmed, stop_confirmed=stop_confirmed,
            unverified_dp_confirmed=unverified_dp_confirmed)
    from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
    state = audit_ptz_readiness(coordinator, coordinator.client)
    calls = 0
    if state.get('cache_oem_recent') is not True:
        refreshed = refresh_ptz_inventory(coordinator, password_confirmed=True)
        calls = int(refreshed.get('appels_reseau', 0))
        if refreshed.get('etat') not in ('inventaire_oem_ptz_lu', 'cache_recent_reutilise'):
            return {'diagnostic': 'aosu_arret_api_alternative_b79',
                    'etat': 'actualisation_oem_impossible',
                    'appels_reseau': calls, 'commande_arret_tentee': False,
                    'commande_direction_envoyee': False, 'video_modifiee': False,
                    'arret_physique_confirme': False, 'secrets_retournes': False}
    result = test_alternate_stop_b79(coordinator, password_confirmed=True,
        camera_confirmed=True, stop_confirmed=True, unverified_dp_confirmed=True)
    return {**result, 'appels_reseau': calls + int(result.get('appels_reseau', 0))}
