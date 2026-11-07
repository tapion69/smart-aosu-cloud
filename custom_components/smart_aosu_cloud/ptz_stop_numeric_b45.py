"""b45: carefully bounded STOP-only numeric DP experiment. No PTZ movement.

Never claim success on a remote response alone. In particular this HTTP route
is NOT the Android SDK MQTT publication path, and it may be rejected.
"""
from __future__ import annotations
from . import ptz_stop_probe_b40 as previous


def test_stop_dp116(coordinator, *, password_confirmed=False, camera_confirmed=False,
                    stop_confirmed=False, numeric_confirmed=False):
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_readiness import _ptz_flags
    from .tuya_uid_gateway import (TuyaAuthSession, OEMGatewayError,
                                    do_uid_login_request, publish_ptz_stop_dp116_once)
    from .uid_token_probe import _ready_identity, _apk_preflight
    import time
    base = {'diagnostic': 'aosu_stop_dp116_b45', 'lecture_seule': False,
            'test_experimental': True, 'dp_id': 116, 'stop_c5l_id_certifie': False,
            'commande_arret_tentee': False, 'commande_direction_envoyee': False,
            'arret_moteur_physiquement_verifie': False, 'mouvement_autorise': False,
            'video_demarre': False, 'offre_mqtt': False, 'reconnexion_rtc': False,
            'identifiants_retournes': False, 'secrets_retournes': False,
            'appels_reseau': 0}
    if not (password_confirmed is True and camera_confirmed is True and
            stop_confirmed is True and numeric_confirmed is True):
        return {**base, 'etat': 'quatre_confirmations_requises'}
    controller = getattr(coordinator, 'live_controller', None)
    if controller is not None and getattr(controller, 'running', False):
        return {**base, 'etat': 'direct_home_assistant_en_cours'}
    selected, reason = select_c5l_oem(coordinator)
    if selected is None:
        return {**base, 'etat': reason}
    dev_id, row, method = selected
    if method not in ('identification_exacte', 'nom_unique_confirme_par_utilisateur'):
        return {**base, 'etat': 'camera_oem_non_confirmee'}
    flags = _ptz_flags(row)
    if not (flags['code_direction_repere'] and flags['code_arret_repere']):
        return {**base, 'etat': 'codes_ptz_non_reperes'}
    now = time.monotonic()
    retry_after = previous._RETRY_AFTER.get(id(coordinator.client), 0)
    if now < retry_after:
        return {**base, 'etat': 'temporisation_essai_arret',
                'delai_restant_secondes': int(retry_after - now) + 1}
    if not previous._LOCK.acquire(blocking=False):
        return {**base, 'etat': 'autre_essai_arret_en_cours'}
    try:
        now = time.monotonic()
        if now < previous._RETRY_AFTER.get(id(coordinator.client), 0):
            return {**base, 'etat': 'temporisation_essai_arret'}
        # Share cooldown with b40 even if this experiment is refused.
        previous._RETRY_AFTER[id(coordinator.client)] = now + previous._INTERVAL
        client = coordinator.client
        profile = _ready_identity(client)
        if profile is None:
            return {**base, 'etat': 'profil_oem_absent'}
        hints, install_id = profile
        _, parsed = _apk_preflight(client.apk_path)
        if parsed is None:
            return {**base, 'etat': 'ressources_oem_invalides'}
        identity, signer = parsed
        ttid = f'sdk_international@{identity.app_id}'
        session = getattr(client, '_tuya_oem_session', None)
        if not isinstance(session, TuyaAuthSession) or now-session.acquired_at > 1200:
            session = None
        if session is None:
            password = getattr(client, 'password', None)
            if not isinstance(password, str) or not password:
                return {**base, 'etat': 'mot_de_passe_absent'}
            auth, session = do_uid_login_request(identity, signer, 'sha256_material',
                uid=hints.tuya_username, country_code=hints.country_code,
                password=password, ttid=ttid, device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            base['appels_reseau'] += int(auth.get('appel_reseau', 0))
            if session is None:
                return {**base, 'etat': 'authentification_refusee_ou_expiree'}
            client._tuya_oem_session = session
        base['commande_arret_tentee'] = True
        base['appels_reseau'] += 1
        reply = publish_ptz_stop_dp116_once(identity, signer, 'sha256_material',
                   session, dev_id=dev_id, ttid=ttid, device_id=install_id,
                   endpoint='https://a1.tuyaeu.com/api.json')
        return {**base, **reply, 'methode_selection': method,
                'etat': ('serveur_accepte_arret_physique_non_verifie'
                         if reply.get('publication_acceptee_par_serveur')
                         else 'serveur_refuse_ou_publication_non_confirmee')}
    except OEMGatewayError as exc:
        return {**base, 'etat': 'erreur_api_oem', 'raison': exc.code}
    except Exception:
        return {**base, 'etat': 'erreur_sans_details'}
    finally:
        previous._LOCK.release()


def test_stop_dp116_with_refresh(coordinator, *, password_confirmed=False,
                                   camera_confirmed=False, stop_confirmed=False,
                                   numeric_confirmed=False):
    if not all((password_confirmed is True, camera_confirmed is True,
                stop_confirmed is True, numeric_confirmed is True)):
        return test_stop_dp116(coordinator, password_confirmed=password_confirmed,
            camera_confirmed=camera_confirmed, stop_confirmed=stop_confirmed,
            numeric_confirmed=numeric_confirmed)
    controller = getattr(coordinator, 'live_controller', None)
    if controller is not None and getattr(controller, 'running', False):
        return test_stop_dp116(coordinator, password_confirmed=True,
            camera_confirmed=True, stop_confirmed=True, numeric_confirmed=True)
    from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
    snapshot = audit_ptz_readiness(coordinator, coordinator.client)
    calls = 0
    if not snapshot.get('cache_oem_recent'):
        updated = refresh_ptz_inventory(coordinator, password_confirmed=True)
        calls = int(updated.get('appels_reseau', 0))
        if updated.get('etat') not in ('inventaire_oem_ptz_lu', 'cache_recent_reutilise'):
            return {'diagnostic': 'aosu_stop_dp116_b45', 'lecture_seule': False,
                    'etat': 'actualisation_oem_impossible',
                    'etat_actualisation': updated.get('etat', 'indetermine'),
                    'commande_arret_tentee': False, 'commande_direction_envoyee': False,
                    'arret_moteur_physiquement_verifie': False, 'mouvement_autorise': False,
                    'appels_reseau': calls, 'secrets_retournes': False}
    result = test_stop_dp116(coordinator, password_confirmed=True,
        camera_confirmed=True, stop_confirmed=True, numeric_confirmed=True)
    return {**result, 'appels_reseau': calls + int(result.get('appels_reseau', 0))}
