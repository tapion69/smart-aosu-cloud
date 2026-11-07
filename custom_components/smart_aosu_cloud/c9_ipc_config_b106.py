"""B106: inspect documented IPC camera configuration for a C9 candidate.

Single, explicitly-authorized HTTPS read of thing.m.ipc.config.get v2.0.
Unlike the rejected station RTC request, this addresses the C9 sub-device.
Never start video, save the response, return raw IDs/keys, or substitute hub keys.
"""
from __future__ import annotations

import threading
import time
from typing import Any

from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_preflight_b98 import _FRESH_SECONDS
from .c9_h1l_identity_structure_b99 import _match_name

_LOCK = threading.Lock()
_NEXT_ALLOWED: dict[int, float] = {}
_COOLDOWN = 300


def _dicts(value: Any, depth: int = 0):
    """Bounded traversal over decrypted OEM response; never serialize values."""
    if depth > 6:
        return
    if isinstance(value, dict):
        yield value
        for item in list(value.values())[:80]:
            yield from _dicts(item, depth+1)
    elif isinstance(value, (tuple, list)):
        for item in value[:80]:
            yield from _dicts(item, depth+1)


def _presence(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def inspect_ipc_config_b106(raw: Any, *, candidate_id: str, station_id: str,
                            camera_key_present: bool, station_key_present: bool) -> dict:
    """Interpret known Tuya IPC config fields without returning secrets."""
    nodes = list(_dicts(raw))[:250]
    subdics = [node['subDic'] for node in nodes if isinstance(node.get('subDic'), dict)]
    def has_value(key: str) -> bool:
        return any(key in node and node[key] is not None for node in nodes)
    def explicit_eq(obj: dict, key: str, reference: str) -> bool:
        value = obj.get(key)
        return isinstance(value, str) and value == reference
    sub_station = any(explicit_eq(d, 'did', station_id) for d in subdics)
    sub_camera = any(explicit_eq(d, 'subDid', candidate_id) for d in subdics)
    exact_pair = any(explicit_eq(d, 'did', station_id) and explicit_eq(d, 'subDid', candidate_id)
                     for d in subdics)
    cfgs = [node.get('p2pConfig') for node in nodes if isinstance(node.get('p2pConfig'), dict)]
    return {
        'reponse_objet': isinstance(raw, dict) and bool(raw),
        'p2p_config_present': bool(cfgs),
        'p2p_id_present': any(_presence(node.get('p2pId')) for node in nodes),
        'p2p_specified_type_present': has_value('p2pSpecifiedType'),
        'sub_dic_present': bool(subdics),
        'sub_dic_station_correspond_candidate': sub_station,
        'sub_dic_camera_correspond_candidate': sub_camera,
        'sub_dic_couple_station_camera_exact': exact_pair,
        'sub_dic_present_mais_indirect': bool(subdics) and not exact_pair,
        'champ_canal_present': any(has_value(k) for k in ('channelId','channel','nodeId','subNodeId')),
        'local_key_dans_reponse_present': any(_presence(node.get('localKey')) for node in nodes),
        'local_key_camera_cache_presente': camera_key_present,
        'local_key_station_cache_presente': station_key_present,
        'station_key_utilisee_pour_camera': False,
        'configuration_media_non_validee': True,
        'identifiants_et_secrets_masques': True,
    }


def audit_c9_ipc_config_b106(coordinator: Any, *, camera_number: Any,
                             confirm_candidate: bool, confirm_ipc: bool,
                             now: float | None = None) -> dict:
    report = {
        'diagnostic': 'aosu_c9_ipc_config_b106',
        'lecture_seule': True, 'appels_http': 0,
        'authentification_effectuee': False, 'mot_de_passe_envoye': False,
        'demarrage_video': False, 'rtc_station_demande': False,
        'offre_mqtt_envoyee': False, 'connexion_p2p_demarre': False,
        'commande_camera_envoyee': False, 'commande_ptz_envoyee': False,
        'selection_video_autorisee': False, 'association_par_nom_non_prouvee': True,
        'identifiants_retournes': False, 'noms_retournes': False,
        'valeurs_privees_retournees': False,
        'consentement_candidat': confirm_candidate is True,
        'consentement_ipc': confirm_ipc is True,
    }
    if type(camera_number) is not int or camera_number not in (1,2):
        return {**report, 'etat':'numero_camera_invalide_1_ou_2'}
    report['numero_camera_aosu']=camera_number
    if confirm_candidate is not True or confirm_ipc is not True:
        return {**report,'etat':'double_confirmation_requise'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**report,'etat':'direct_c5l_en_cours'}
    if controller is not None and callable(getattr(controller,'status',None)):
        try:
            if controller.status().get('direct_actif') is True:
                return {**report,'etat':'direct_c5l_en_cours'}
        except (AttributeError,TypeError):
            return {**report,'etat':'etat_direct_c5l_indisponible'}
    client=getattr(coordinator,'client',None)
    cache=getattr(client,'_tuya_oem_inventory_cache',None)
    session=getattr(client,'_tuya_oem_session',None)
    tick=time.monotonic() if now is None else now
    if (not isinstance(cache,dict) or not isinstance(cache.get('devices'),dict)
            or session is None or not isinstance(getattr(session,'uid',None),str)
            or not session.uid or cache.get('session_uid') != session.uid
            or type(cache.get('created')) not in (int,float)
            or not 0 <= tick-cache['created'] < _FRESH_SECONDS
            or type(getattr(session,'acquired_at',None)) not in (int,float)
            or not 0 <= tick-session.acquired_at < 1200):
        return {**report,'etat':'cache_oem_ou_session_absente_expiree'}
    data=getattr(coordinator,'data',None)
    if not isinstance(data,dict):
        return {**report,'etat':'inventaire_aosu_absent'}
    candidate,alignment=_candidate(data,client,camera_number)
    report['candidat']=alignment
    if candidate is None:
        return {**report,'etat':'candidat_non_selectionnable'}
    stations=[row for row in data.values() if isinstance(row,dict)
              and row.get('model')=='H1L' and row.get('is_camera') is False]
    devices=cache['devices']
    if len(stations)!=1 or not isinstance(stations[0].get('name'),str):
        return {**report,'etat':'station_h1l_ambigue'}
    station_candidates=[did for did,item in devices.items()
                        if isinstance(item,dict) and _match_name(item,stations[0]['name'])]
    if len(station_candidates)!=1 or station_candidates[0]==candidate:
        return {**report,'etat':'station_h1l_ambigue'}
    station=station_candidates[0]
    from .tuya_rtc_inventory import _LOCK as OEM_LOCK, _LAST_RTC
    remaining=max(_NEXT_ALLOWED.get(id(client),0),_LAST_RTC.get(id(client),0))-tick
    if remaining>0:
        return {**report,'etat':'temporisation_ipc','secondes_restantes':int(remaining+.999)}
    if not _LOCK.acquire(blocking=False):
        return {**report,'etat':'audit_ipc_deja_en_cours'}
    try:
        if not OEM_LOCK.acquire(blocking=False):
            return {**report,'etat':'autre_action_oem_en_cours'}
        try:
            remaining=max(_NEXT_ALLOWED.get(id(client),0),_LAST_RTC.get(id(client),0))-tick
            if remaining>0:
                return {**report,'etat':'temporisation_ipc','secondes_restantes':int(remaining+.999)}
            from .uid_token_probe import _ready_identity,_apk_preflight
            from .tuya_uid_gateway import TuyaAuthSession,OEMGatewayError,do_oem_read
            if not isinstance(session,TuyaAuthSession):
                return {**report,'etat':'session_oem_non_validee'}
            ready=_ready_identity(client)
            if ready is None:
                return {**report,'etat':'profil_oem_absent'}
            _,install_id=ready
            _,parsed=_apk_preflight(client.apk_path)
            if parsed is None:
                return {**report,'etat':'ressources_oem_invalides'}
            identity,signer=parsed
            _NEXT_ALLOWED[id(client)]=tick+_COOLDOWN
            _LAST_RTC[id(client)]=tick+_COOLDOWN
            report['appels_http']=1
            try:
                ipc,status=do_oem_read(identity,signer,'sha256_material',session,
                    action='thing.m.ipc.config.get',form_data={'devId':candidate},
                    ttid=f'sdk_international@{identity.app_id}',device_id=install_id,
                    endpoint='https://a1.tuyaeu.com/api.json')
            except OEMGatewayError as exc:
                return {**report,'etat':'erreur_api_oem','categorie_erreur':exc.code if exc.code in (
                    'http_non_200','reseau_ou_reponse_invalide','reponse_non_chiffree_ou_absente',
                    'session_tuya_absente','api_lecture_non_autorisee') else 'autre'}
            except Exception:
                return {**report,'etat':'erreur_lecture_ipc_non_detaillee'}
            accepted=bool(status.get('serveur_accepte')) and not status.get('rejet_explicite')
            if not accepted:
                return {**report,'etat':'config_ipc_non_acceptee',
                    'rejet_explicite':bool(status.get('rejet_explicite')),
                    'categorie_refus':status.get('categorie_refus','indeterminee'),
                    'code_erreur_tuya':status.get('code_erreur_tuya') if
                        isinstance(status.get('code_erreur_tuya'),str) else None}
            report['structure_ipc']=inspect_ipc_config_b106(ipc,
                candidate_id=candidate, station_id=station,
                camera_key_present=bool(devices[candidate].get('localKey')),
                station_key_present=bool(devices[station].get('localKey')))
            report['etat']='config_ipc_recue' if isinstance(ipc,dict) else 'config_ipc_structure_inattendue'
            return report
        finally:
            OEM_LOCK.release()
    finally:
        _LOCK.release()
