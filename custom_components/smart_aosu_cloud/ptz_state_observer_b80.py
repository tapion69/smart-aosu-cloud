"""B80 -- compare two read-only OEM snapshots around a movement in the official app.

No PTZ command, publishing, MQTT connection, media change or persistent data.
The comparison detects *possible* state reporting only; it cannot establish
that any proposed STOP packet was delivered or that a legacy DP ID is valid.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from .tuya_uid_gateway import (TuyaAuthSession, OEMGatewayError,
                               do_oem_read, do_uid_login_request)

_ALLOWED = {'ptz_control': 'code_ptz_control', 'ptz_stop': 'code_ptz_stop',
            '119': 'id119_candidat', '116': 'id116_candidat'}
_CONTAINERS = ('result', 'data', 'device', 'deviceInfo', 'status',
               'dps', 'dp', 'dpValues', 'dpStatus', 'statusData', 'statusMap')
_STATUS_CONTAINERS = {'status','dps','dp','dpValues','dpStatus','statusData','statusMap'}
_LOCK = threading.Lock()
_LAST_CALL: dict[int, float] = {}
_SNAPSHOTS: dict[int, tuple[float, dict[str,tuple[str,str]], str]] = {}
_TTL = 180
_MIN_INTERVAL = 6


def _parse_container(value: Any) -> Any:
    if not isinstance(value, str) or len(value) > 65536 or not value.lstrip().startswith(('{','[')):
        return value
    try:
        value = json.loads(value)
    except (ValueError, TypeError, RecursionError):
        return None
    return value if isinstance(value, (dict,list)) else None


def _private_fingerprint(value: Any) -> tuple[str,str] | None:
    """No vendor value or hash leaves the integration. Ignore complex values."""
    if type(value) is bool:
        kind='bool'
    elif type(value) in (int,float):
        kind='nombre'
    elif isinstance(value,str) and len(value)<=256:
        kind='texte'
    else:
        return None
    raw=json.dumps([kind,value],ensure_ascii=True,separators=(',',':'),allow_nan=False)
    return kind, hashlib.sha256(raw.encode()).hexdigest()


def summarize_oem_ptz_status(payload: Any) -> dict[str, tuple[str,str]]:
    """Only status containers. Never confuse schema definitions with runtime values."""
    states: dict[str, set[tuple[str,str]]] = {v:set() for v in _ALLOWED.values()}
    stack=[(payload, 0, False)]
    n=0
    while stack and n<500:
        obj, depth, is_status = stack.pop()
        n+=1
        if depth>9:continue
        if isinstance(obj, list):
            for child in obj[:100]:
                if isinstance(child,(dict,list)):
                    stack.append((child,depth+1,is_status))
            continue
        if not isinstance(obj,dict):continue
        if is_status:
            # Example: [{"code":"ptz_stop","value":true}]
            code=obj.get('code',obj.get('dpCode'))
            if code is None:code=obj.get('dpId')
            if isinstance(code,(int,str)) and not isinstance(code,bool):
                label=_ALLOWED.get(str(code))
                if label and 'value' in obj:
                    fp=_private_fingerprint(obj['value'])
                    if fp:states[label].add(fp)
            # Example: {"dps":{"116":true}} or {"status":{"ptz_stop":true}}
            for name,label in _ALLOWED.items():
                if name in obj:
                    fp=_private_fingerprint(obj[name])
                    if fp:states[label].add(fp)
        for key in _CONTAINERS:
            if key not in obj:continue
            child = _parse_container(obj[key])
            if isinstance(child,(dict,list)):
                stack.append((child,depth+1,is_status or key in _STATUS_CONTAINERS))
    return {k:next(iter(v)) for k,v in states.items() if len(v)==1}


def compare_ptz_status(before:dict, after:dict)->dict:
    common=set(before)&set(after)
    changed=sorted(k for k in common if before[k]!=after[k])
    return {'valeurs_communes':len(common), 'valeurs_avant':len(before),
            'valeurs_apres':len(after),
            'cles_de_valeur_modifiee':changed,
            'changement_etat_observe':bool(changed),
            'dp_schema_certifie':False, 'arret_physique_confirme':False,
            'commande_ptz_identifiee':False,
            'verdict':('variation_etat_ptz_candidate_non_probante' if changed
                      else 'aucune_variation_etat_ptz_demontrable')}


def audit_ptz_state_b80(coordinator: Any, *, phase:str='',
                         password_confirmed:bool=False, camera_confirmed:bool=False)->dict:
    result={'diagnostic':'aosu_observation_etat_ptz_b80', 'lecture_seule':True,
            'phase':phase if phase in ('avant','apres') else 'invalide',
            'api_lue':'thing.m.device.get','version_api':'4.1',
            'appels_reseau':0,'commandes_ptz_envoyees':0,
            'commandes_stop_envoyees':0,'publications_mqtt':0,
            'publications_http':0,'video_modifiee':False,
            'identifiants_retournes':False,'secrets_retournes':False,
            'donnees_brutes_retournees':False,'valeurs_dp_retournees':False,
            'id_116_certifie':False,'arret_physique_confirme':False,
            'branche_sdk_active_confirmee':False}
    if phase not in ('avant','apres'):
        return {**result, 'etat':'phase_avant_ou_apres_requise'}
    if password_confirmed is not True or camera_confirmed is not True:
        return {**result,'etat':'deux_confirmations_requises'}
    if getattr(getattr(coordinator,'live_controller',None),'running',False):
        return {**result,'etat':'direct_home_assistant_en_cours'}
    client=coordinator.client
    key=id(client)
    now=time.monotonic()
    baseline=_SNAPSHOTS.get(key)
    if phase=='apres' and (baseline is None or not 0<=now-baseline[0]<_TTL):
        _SNAPSHOTS.pop(key,None)
        return {**result,'etat':'lecture_avant_absente_ou_expiree'}
    if now < _LAST_CALL.get(key,0):
        return {**result,'etat':'temporisation_entre_lectures',
                'delai_restant_secondes':int(_LAST_CALL[key]-now)+1}
    if not _LOCK.acquire(blocking=False):
        return {**result,'etat':'autre_lecture_en_cours'}
    try:
        now=time.monotonic()
        if now < _LAST_CALL.get(key,0):
            return {**result,'etat':'temporisation_entre_lectures'}
        # Read-only inventory refresh is permitted in phase 'avant' only.
        from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
        from .ptz_device_detail_b39 import select_c5l_oem
        readiness=audit_ptz_readiness(coordinator,client)
        if not readiness.get('cache_oem_recent'):
            if phase=='apres':
                return {**result,'etat':'inventaire_oem_expire_pendant_comparaison'}
            refreshed=refresh_ptz_inventory(coordinator,password_confirmed=True)
            result['appels_reseau']+=int(refreshed.get('appels_reseau',0))
            if refreshed.get('etat') not in ('inventaire_oem_ptz_lu','cache_recent_reutilise'):
                return {**result,'etat':'actualisation_oem_impossible',
                        'etat_actualisation':refreshed.get('etat','inconnu')}
        selection,reason=select_c5l_oem(coordinator)
        if selection is None:
            return {**result,'etat':reason}
        dev_id,_,method=selection
        if method not in ('identification_exacte','nom_unique_confirme_par_utilisateur'):
            return {**result,'etat':'cible_oem_non_confirmee'}
        if phase=='apres' and baseline and baseline[2]!=dev_id:
            _SNAPSHOTS.pop(key,None)
            return {**result,'etat':'camera_selectionnee_a_change'}
        from .uid_token_probe import _ready_identity,_apk_preflight
        profile=_ready_identity(client)
        if profile is None:return {**result,'etat':'profil_oem_absent'}
        hints,install_id=profile
        _,materials=_apk_preflight(client.apk_path)
        if materials is None:return {**result,'etat':'ressources_oem_invalides'}
        identity,signer=materials
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or not 0<=now-session.acquired_at<1200:
            password=getattr(client,'password',None)
            if not isinstance(password,str) or not password:
                return {**result,'etat':'mot_de_passe_absent'}
            login,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                password=password,ttid=ttid,device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            result['appels_reseau']+=int(login.get('appel_reseau',0))
            if session is None:return {**result,'etat':'authentification_refusee'}
            client._tuya_oem_session=session
        _LAST_CALL[key]=now+_MIN_INTERVAL
        result['appels_reseau']+=1
        response,status=do_oem_read(identity,signer,'sha256_material',session,
            action='thing.m.device.get',form_data={'devId':dev_id},
            ttid=ttid,device_id=install_id,endpoint='https://a1.tuyaeu.com/api.json')
        if status.get('rejet_explicite') or not status.get('serveur_accepte'):
            return {**result,'etat':'lecture_etat_refusee'}
        state=summarize_oem_ptz_status(response)
        result['champs_etat_ptz_reperes']=sorted(state)
        result['nombre_champs_etat_ptz']=len(state)
        result['selection_oem']=method
        if phase=='avant':
            if not state:
                return {**result,'etat':'aucune_valeur_etat_ptz_dans_fiche',
                        'suite':'aucune_comparaison_possible_avec_cette_api'}
            _SNAPSHOTS[key]=(time.monotonic(),state,dev_id)
            return {**result,'etat':'reference_avant_enregistree',
                    'expiration_secondes':_TTL}
        # phase == apres; reread snapshot under lock and never return DP values
        old=_SNAPSHOTS.pop(key,None)
        if old is None or not 0<=time.monotonic()-old[0]<_TTL or old[2]!=dev_id:
            return {**result,'etat':'lecture_avant_absente_ou_expiree'}
        return {**result,'etat':'comparaison_terminee',
                'analyse':compare_ptz_status(old[1],state)}
    except OEMGatewayError as exc:
        return {**result,'etat':'erreur_api_oem','raison':exc.code}
    except Exception:
        return {**result,'etat':'erreur_sans_details'}
    finally:
        _LOCK.release()
