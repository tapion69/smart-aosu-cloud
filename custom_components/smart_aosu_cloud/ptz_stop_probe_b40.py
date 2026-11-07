"""Explicit, one-shot Tuya PTZ STOP-only test. NO DIRECTION COMMANDS.

This deliberately tests transport acknowledgement only. It does not infer
physical motor state, movement success, or a valid C5L direction mapping.
"""
from __future__ import annotations
import threading
import time

_LOCK=threading.Lock()
_RETRY_AFTER:dict[int,float]={}
_INTERVAL=120

def probe_ptz_stop_only(coordinator, *, password_confirmed=False,
                        camera_confirmed=False, stop_confirmed=False):
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_readiness import _ptz_flags
    from .tuya_uid_gateway import (TuyaAuthSession, OEMGatewayError,
            do_uid_login_request, publish_ptz_stop_once)
    from .uid_token_probe import _ready_identity,_apk_preflight

    base={'diagnostic':'aosu_ptz_stop_transport_b40',
          'commande_direction_envoyee':False,
          'commande_arret_tentee':False,
          'arret_moteur_physiquement_verifie':False,
          'mouvement_autorise':False,'direct_video_demarre':False,
          'reconnexion_rtc':False,'offre_mqtt':False,
          'identifiants_retournes':False,'secrets_retournes':False,
          'appels_reseau':0,'codage_dp':'code_ptz_stop_sans_id_invente'}
    if not (password_confirmed is True and camera_confirmed is True
            and stop_confirmed is True):
        return {**base,'etat':'trois_confirmations_requises'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**base,'etat':'direct_video_en_cours'}
    selected,reason=select_c5l_oem(coordinator)
    if selected is None:return {**base,'etat':reason}
    did,row,method=selected
    flags=_ptz_flags(row)
    if not flags['code_arret_repere'] or not flags['code_direction_repere']:
        return {**base,'etat':'capacites_ptz_absentes'}
    base['methode_selection']=method
    now=time.monotonic()
    if _RETRY_AFTER.get(id(coordinator.client),0)>now:
        return {**base,'etat':'temporisation_essai_arret',
          'delai_restant_secondes':int(_RETRY_AFTER[id(coordinator.client)]-now)+1}
    if not _LOCK.acquire(blocking=False):
        return {**base,'etat':'autre_essai_arret_en_cours'}
    try:
        now=time.monotonic()
        if _RETRY_AFTER.get(id(coordinator.client),0)>now:
            return {**base,'etat':'temporisation_essai_arret'}
        _RETRY_AFTER[id(coordinator.client)]=now+_INTERVAL
        client=coordinator.client
        profile=_ready_identity(client)
        if profile is None:return {**base,'etat':'profil_oem_absent'}
        hints,install_id=profile
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**base,'etat':'ressources_oem_invalides'}
        identity,signer=parsed
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or now-session.acquired_at>1200:
            session=None
        if session is None:
            password=getattr(client,'password',None)
            if not isinstance(password,str) or not password:
                return {**base,'etat':'mot_de_passe_absent'}
            login,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                password=password,ttid=ttid,device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            base['appels_reseau']+=int(login.get('appel_reseau',0))
            if session is None:return {**base,'etat':'authentification_refusee_ou_expiree'}
            client._tuya_oem_session=session
        # One publish, no direction and no second strategy/fallback.
        base['commande_arret_tentee']=True
        base['appels_reseau']+=1
        result=publish_ptz_stop_once(identity,signer,'sha256_material',session,
            dev_id=did,ttid=ttid,device_id=install_id,
            endpoint='https://a1.tuyaeu.com/api.json')
        return {**base,**result, 'etat':
            'publication_stop_acceptee_arret_physique_non_verifie'
            if result.get('publication_acceptee_par_serveur')
            else 'publication_stop_refusee_ou_non_confirmee'}
    except OEMGatewayError as exc:
        return {**base,'etat':'erreur_publication_oem',
                'raison':exc.code,'appels_reseau':base['appels_reseau']+max(0,exc.calls-1)}
    except Exception:
        return {**base,'etat':'erreur_sans_details'}
    finally:
        _LOCK.release()


def probe_ptz_stop_with_refresh(coordinator, *, password_confirmed=False,
                                camera_confirmed=False, stop_confirmed=False):
    """Refresh OEM only after all confirmations, then single STOP-only test."""
    if not (password_confirmed is True and camera_confirmed is True and stop_confirmed is True):
        return probe_ptz_stop_only(coordinator,
            password_confirmed=password_confirmed,
            camera_confirmed=camera_confirmed,
            stop_confirmed=stop_confirmed)
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return probe_ptz_stop_only(coordinator,
            password_confirmed=True,camera_confirmed=True,stop_confirmed=True)
    from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
    report=audit_ptz_readiness(coordinator,coordinator.client)
    refresh='cache_recent_reutilise'
    calls=0
    if not report.get('cache_oem_recent'):
        updated=refresh_ptz_inventory(coordinator,password_confirmed=True)
        refresh=updated.get('etat','erreur_sans_details')
        calls=int(updated.get('appels_reseau',0))
        if refresh not in ('inventaire_oem_ptz_lu','cache_recent_reutilise'):
            return {'diagnostic':'aosu_ptz_stop_transport_b40',
                    'etat':'actualisation_oem_impossible',
                    'etat_actualisation':refresh,'appels_reseau':calls,
                    'commande_arret_tentee':False,
                    'commande_direction_envoyee':False,
                    'arret_moteur_physiquement_verifie':False,
                    'mouvement_autorise':False,
                    'identifiants_retournes':False,'secrets_retournes':False}
    result=probe_ptz_stop_only(coordinator,
        password_confirmed=True,camera_confirmed=True,stop_confirmed=True)
    return {**result,'actualisation_cache':refresh,
            'appels_reseau':calls+int(result.get('appels_reseau',0))}
