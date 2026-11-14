"""Manual Tuya OEM inventory, optional RTC probes and consented experiments.

The OEM session is held only in RAM; identifiers, local keys, tokens, media and
decrypted response bodies must never be serialized into HA service results.
Normal inventory is read-only. A C9C-only HTTP offer is possible exclusively
through one manually confirmed, rate-limited state-changing test; it does
not send a video command, MQTT message, camera wake or PTZ.
"""
from __future__ import annotations
import threading
import time
from typing import Any
from .uid_token_probe import _ready_identity, _apk_preflight
from .tuya_uid_gateway import (TuyaAuthSession, OEMGatewayError,
                               do_uid_login_request, do_oem_read,
                               do_oem_thing4_session_offer_once)
from .tuya_media_bootstrap import inspect_rtc_media
from .tuya_mqtt_signaling import run_tuya_mqtt_signalisation
from .tuya_mqtt_offer import run_tuya_mqtt_offer, _media_payload
from .camera_topology import (select_tuya_standalone_target,
                             select_tuya_standalone_target_typed)
from .c9c_rtc_schema import summarize_c9c_rtc_schema
from .c9c_moto_signal import resolve_rtc_moto_id
from .c9c_mqtt_classify import inspect_sleep_dp149
from .c9c_mqtt_passive import observe_mqtt_for_c9c
from .c9c_wake_probe import try_wake_c9c_once
from .c9c_webrtc_probe_b23 import inspect_webrtc_hints
from .c9c_webrtc_channel_b23 import subscribe_webrtc_once
from .c9c_tuya_device_b27 import summarize_tuya_device_b27
from .c9c_full_audit_b31 import run_full_c9c_audit_b31
from .c9c_cp_reverse_read import extract_tuya_detail_cp_candidates
from .c9c_ty_detail_hydration import resolve_aosu_ty_cp_uuid
from .c9c_thing4_http_once import (manual_target_gate, validate_type4_rtc,
                                    native_http_form, safe_http_result)
from .c9c_sdk_preflight_b37 import summarize_native_prerequisites_b37, compare_rtc_sdk_b38, summarize_thing4_media_alignment_b40

_LOCK = threading.Lock()
_LAST_RUN: dict[int, float] = {}
_LAST_LOGIN: dict[int, float] = {}
_LAST_C9C_DETAIL_LOGIN: dict[int, float] = {}
_LAST_RTC: dict[int, float] = {}
_LAST_C9C_HTTP: dict[int, float] = {}  # one explicit state-changing test/hour
_COOLDOWN = 1800  # prevent manual repetitive discovery while developing
_ENDPOINT = 'https://a1.tuyaeu.com/api.json'


def _c9c_detail_login_allowed(now: float, global_expiry: float,
                              detail_expiry: float) -> bool:
    """Manual read-only C9C detail: at least 20 min between UID login attempts.

    Regular inventory/video still obeys the 60 min login limit. This safe
    exception only applies after the 20 min in-RAM session lifetime has
    elapsed and the user explicitly clicks Fiche Tuya. No retries.
    """
    return (now >= detail_expiry and now >= global_expiry - 2400)


def _walk(root: Any, *, depth: int = 0):
    if depth > 7:
        return
    if isinstance(root, dict):
        yield root
        for child in list(root.values())[:100]:
            yield from _walk(child, depth=depth+1)
    elif isinstance(root, list):
        for child in root[:100]:
            yield from _walk(child, depth=depth+1)


def _home_groups(response: Any) -> list[str]:
    found: set[str] = set()
    for item in _walk(response):
        for key in ('gid','groupId','homeId'):
            v = item.get(key)
            if type(v) in (str,int) and 1<=len(str(v))<=20 and str(v).isdigit():
                found.add(str(v))
    return sorted(found)[:4]


def _devices(response: Any) -> list[dict]:
    found: dict[str, dict] = {}
    for item in _walk(response):
        did = item.get('devId') or item.get('deviceId')
        if not isinstance(did,str) or not 5<=len(did)<=128:
            continue
        if not any(k in item for k in ('category','localKey','name','productId','productName','isOnline','deviceType')):
            continue
        found[did] = item
        if len(found)>=100:break
    return list(found.values())


def _device_objects(item: dict) -> list[dict]:
    """Only named containers from the Tuya DeviceBean structure.

    In particular, the Android IPC SDK documents category at
    DeviceBean.productBean.category, not necessarily DeviceBean.category.
    """
    objects = [item]
    for name in ('productBean', 'product', 'productInfo', 'deviceBean', 'deviceInfo'):
        obj = item.get(name)
        if isinstance(obj, dict):
            objects.append(obj)
    return objects


def _c5l_match(item: dict, c5l_sn: str | None, c5l_coop: str | None) -> str | None:
    """Strong exact model/serial/vendor link; never compare user-defined names."""
    objects = _device_objects(item)
    for obj in objects:
        for key in ('model','productModel','modelName','productType','deviceModel','productName'):
            val = obj.get(key)
            if isinstance(val, str) and val.strip().upper() == 'C5L':
                return 'c5l_confirmed_model'
    if c5l_sn:
        for obj in objects:
            for key in ('sn','deviceSn','serialNumber','serialNo'):
                val = obj.get(key)
                if isinstance(val,str) and val == c5l_sn:
                    return 'c5l_confirmed_serial'
    if c5l_coop:
        for obj in objects:
            for key in ('devId','deviceId','uuid','devUuid','deviceUuid','cpDeviceId'):
                val = obj.get(key)
                if isinstance(val,str) and val == c5l_coop:
                    return 'c5l_confirmed_coop'
    return None


def _has_camera_category(item:dict) -> bool:
    for obj in _device_objects(item):
        category=obj.get('category')
        if isinstance(category,str) and category.strip().lower() in ('sp','ipc','camera','smart_camera'):
            return True
    return False


def _classify(item:dict, c5l_sn: str|None, c5l_coop: str|None=None,
              c5l_name: str|None=None) -> str:
    strong=_c5l_match(item,c5l_sn,c5l_coop)
    if strong:
        return strong
    if _has_camera_category(item):
        return 'camera_candidate'
    # User-defined names are NEVER proof of identity; flag as a candidate only.
    name=item.get('name')
    if (isinstance(name,str) and isinstance(c5l_name,str) and c5l_name.strip()
            and name.strip().casefold()==c5l_name.strip().casefold()):
        return 'camera_candidate_name'
    return 'unknown'


def _safe_category(value:object) -> str:
    # Only predefined public category codes; never echo an arbitrary server value.
    if not isinstance(value,str) or not value.strip():
        return 'absente'
    normalized=value.strip().lower()
    return normalized if normalized in ('sp','ipc','camera','smart_camera','gateway','gw') else 'autre_valeur'


def _safe_device_report(item:dict, number:int, kind:str, c5l_name:str|None) -> dict:
    """Bounded field-PRESENCE report: no real IDs, names or JSON values."""
    pb=item.get('productBean')
    pb=pb if isinstance(pb,dict) else {}
    skills=item.get('skills')
    skills=skills if isinstance(skills,dict) else {}
    name=item.get('name')
    same_name=(isinstance(name,str) and isinstance(c5l_name,str)
               and bool(c5l_name.strip()) and name.strip().casefold()==c5l_name.strip().casefold())
    return {
        'numero':number,
        'classement':kind,
        'categorie_racine':_safe_category(item.get('category')),
        'categorie_productBean':_safe_category(pb.get('category')),
        'camera_categorie_sp_reconnue':_has_camera_category(item),
        'modele_racine_present':any(isinstance(item.get(k),str) and bool(item[k])
                                      for k in ('model','productModel','modelName')),
        'modele_productBean_present':any(isinstance(pb.get(k),str) and bool(pb[k])
                                         for k in ('model','productModel','modelName','productName')),
        'skills_p2p_type_present':('p2pType' in skills),
        'nom_correspond_c5l':same_name,
        'cle_locale_presente':isinstance(item.get('localKey'),str) and bool(item['localKey']),
    }


def _rtc_presence(payload: Any)->dict[str, Any]:
    nodes=list(_walk(payload))
    keys=set()
    for node in nodes[:100]:
        keys.update(k for k in node if isinstance(k,str))
    return {
        'reponse_non_vide': bool(nodes) and any(bool(n) for n in nodes),
        'session_id_present': bool(keys & {'sessionId','session_id','p2pSessionId'}),
        'ice_present': bool(keys & {'iceServers','iceServer','ice','iceUfrag','icePwd'}),
        'relais_present': bool(keys & {'relayToken','relay','tcpRelay','relayServers'}),
        'parametre_media_present': bool(keys & {'aesKey','aes-key','mediaKey','encryptKey'}),
        'noms_champs_analyses': min(len(keys),250),
    }


def run_tuya_oem_inventory(client, *, confirmation_envoi_mot_de_passe:bool=False,
                           tester_rtc:bool=False, autoriser_candidat_unique:bool=False,
                           autoriser_correspondance_nom_unique:bool=False,
                           tester_mqtt:bool=False,
                           tester_offre_mqtt:bool=False,
                           confirmation_offre_mqtt:bool=False,
                           tester_relais_tcp:bool=False,
                           confirmation_relais_tcp:bool=False,
                           tester_kcp:bool=False,confirmation_kcp:bool=False,
                           tester_media:bool=False,confirmation_media:bool=False,
                           capturer_media_localement:bool=False,
                           confirmation_capture_locale:bool=False,
                           repertoire_capture_locale:str|None=None,live_preview=None, interactive_live:bool=False,
                           standalone_c9c_video_test:bool=False,
                           standalone_c9c_rtc_audit:bool=False,
                           standalone_c9c_mqtt_watch:bool=False,
                           standalone_c9c_v4_rtc_audit:bool=False,
                           standalone_c9c_wake_only:bool=False,
                           standalone_c9c_wake_then_video:bool=False,
                           standalone_c9c_webrtc_audit:bool=False,
                           standalone_c9c_webrtc_channel:bool=False,
                           standalone_c9c_ipc_v2_audit:bool=False,
                           standalone_c9c_tuya_detail_audit:bool=False,
                           standalone_c9c_full_audit_b31:bool=False,
                           standalone_c9c_sdk_b37_audit:bool=False,
                           standalone_c9c_http_offer_test:bool=False,
                           confirmation_offre_http:bool=False,
                           confirmation_cible_unique_non_prouvee:bool=False):
    """Explicitly consented camera stream, or conservative manual one-shot diagnostic.

    interactive_live is an internal flag: it is accepted only with the real
    LivePreview and explicit active-media confirmations. Diagnostics retain all
    historical rate limits. External errors never leak secrets to results.
    """
    interactive_live = (interactive_live is True and live_preview is not None
        and tester_rtc is True and tester_media is True
        and confirmation_envoi_mot_de_passe is True
        and confirmation_offre_mqtt is True and confirmation_relais_tcp is True
        and confirmation_kcp is True and confirmation_media is True)
    if standalone_c9c_video_test and not interactive_live:
        return {'etat': 'essai_autonome_reserve_au_direct_manuel', 'appel_reseau': 0,
                'commande_camera': 0, 'secrets_retournes': False}
    if standalone_c9c_http_offer_test:
        # One explicit, never background/automatic action; do not combine
        # a cloud HTTP offer with MQTT/relay/video, wake or other diagnostics.
        if (tester_rtc is not True or
                confirmation_envoi_mot_de_passe is not True or
                confirmation_offre_http is not True or interactive_live or
                standalone_c9c_video_test or standalone_c9c_wake_then_video or
                standalone_c9c_wake_only or standalone_c9c_rtc_audit or
                standalone_c9c_v4_rtc_audit or standalone_c9c_mqtt_watch or
                standalone_c9c_webrtc_audit or standalone_c9c_ipc_v2_audit or
                standalone_c9c_tuya_detail_audit or standalone_c9c_full_audit_b31 or
                standalone_c9c_sdk_b37_audit or tester_mqtt or tester_offre_mqtt or
                tester_relais_tcp or tester_kcp or tester_media or
                capturer_media_localement):
            return {'etat':'offre_http_c9c_confirmation_et_exclusivite_requises',
                    'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    elif confirmation_offre_http or confirmation_cible_unique_non_prouvee:
        return {'etat':'offre_http_hors_mode_interdite',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_rtc_audit and (
        standalone_c9c_video_test or interactive_live or tester_rtc is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp or tester_kcp
        or tester_media or capturer_media_localement):
        return {'etat': 'audit_rtc_c9c_lecture_seule_uniquement',
                'appel_reseau': 0, 'commande_camera': 0,
                'secrets_retournes': False}
    if standalone_c9c_mqtt_watch and (
        standalone_c9c_video_test or standalone_c9c_rtc_audit
        or interactive_live or tester_rtc is not True
        or tester_mqtt is not True or confirmation_envoi_mot_de_passe is not True
        or tester_offre_mqtt or tester_relais_tcp or tester_kcp or tester_media
        or capturer_media_localement):
        return {'etat':'observer_mqtt_c9c_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_v4_rtc_audit and (
        standalone_c9c_video_test or standalone_c9c_rtc_audit or standalone_c9c_mqtt_watch
        or interactive_live or tester_rtc is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp or tester_kcp
        or tester_media or capturer_media_localement):
        return {'etat':'audit_rtc_v4_c9c_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_wake_only and (
        standalone_c9c_video_test or standalone_c9c_rtc_audit
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or interactive_live or tester_rtc is not True or tester_mqtt is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_offre_mqtt or tester_relais_tcp or tester_kcp or tester_media
        or capturer_media_localement):
        return {'etat':'test_reveil_c9c_manuel_uniquement',
                'appel_reseau':0,'commande_camera':0,
                'secrets_retournes':False}
    if standalone_c9c_wake_then_video and (
        standalone_c9c_video_test is not True or interactive_live is not True
        or standalone_c9c_wake_only or standalone_c9c_rtc_audit
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or tester_rtc is not True or tester_mqtt is not True
        or tester_offre_mqtt is not True or tester_media is not True
        or confirmation_envoi_mot_de_passe is not True
        or confirmation_offre_mqtt is not True):
        return {'etat':'reveil_video_c9c_manuel_uniquement',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_webrtc_audit and (
        standalone_c9c_video_test or standalone_c9c_wake_then_video
        or standalone_c9c_wake_only or standalone_c9c_rtc_audit
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or interactive_live or tester_rtc is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp
        or tester_kcp or tester_media or capturer_media_localement):
        return {'etat':'audit_webrtc_c9c_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_webrtc_channel and not standalone_c9c_webrtc_audit:
        return {'etat':'canal_webrtc_requiert_audit',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_ipc_v2_audit and (
        standalone_c9c_video_test or standalone_c9c_wake_then_video
        or standalone_c9c_wake_only or standalone_c9c_rtc_audit
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or standalone_c9c_webrtc_audit or standalone_c9c_webrtc_channel
        or interactive_live or tester_rtc is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp or tester_kcp
        or tester_media or capturer_media_localement):
        return {'etat':'ipc_v2_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,'secrets_retournes':False}
    if standalone_c9c_tuya_detail_audit and (
        standalone_c9c_video_test or standalone_c9c_wake_then_video
        or standalone_c9c_wake_only or standalone_c9c_rtc_audit
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or standalone_c9c_webrtc_audit or standalone_c9c_webrtc_channel
        or standalone_c9c_ipc_v2_audit or interactive_live
        or tester_rtc is not True or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp
        or tester_kcp or tester_media or capturer_media_localement):
        return {'etat':'fiche_tuya_c9c_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,
                'secrets_retournes':False}
    if standalone_c9c_sdk_b37_audit and (
        standalone_c9c_video_test or standalone_c9c_rtc_audit
        or standalone_c9c_wake_only or standalone_c9c_wake_then_video
        or standalone_c9c_webrtc_audit or standalone_c9c_webrtc_channel
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or standalone_c9c_ipc_v2_audit or standalone_c9c_tuya_detail_audit
        or standalone_c9c_full_audit_b31 or interactive_live
        or tester_rtc is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp
        or tester_kcp or tester_media or capturer_media_localement):
        return {'etat':'sdk_b37_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,
                'secrets_retournes':False}
    if standalone_c9c_full_audit_b31 and (
        standalone_c9c_video_test or standalone_c9c_wake_then_video
        or standalone_c9c_wake_only or standalone_c9c_rtc_audit
        or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
        or standalone_c9c_webrtc_audit or standalone_c9c_webrtc_channel
        or standalone_c9c_ipc_v2_audit or standalone_c9c_tuya_detail_audit
        or interactive_live or tester_rtc is not True
        or confirmation_envoi_mot_de_passe is not True
        or tester_mqtt or tester_offre_mqtt or tester_relais_tcp
        or tester_kcp or tester_media or capturer_media_localement):
        return {'etat':'diagnostic_complet_lecture_seule_uniquement',
                'appel_reseau':0,'commande_camera':0,
                'secrets_retournes':False}
    out={'diagnostic':'aosu_tuya_oem_inventory_b27','session_tuya_authentifiee':False,
         'appel_reseau':0,'mot_de_passe_envoye':False,
         'commande_camera':0,'session_video_creee':False,'secrets_retournes':False,
         'demande_rtc': tester_rtc is True, 'demande_mqtt':tester_mqtt is True,
         'demande_offre_mqtt':tester_offre_mqtt is True, 'demande_relais_tcp':tester_relais_tcp is True, 'demande_kcp': tester_kcp is True, 'demande_media': tester_media is True,
         'demande_capture_locale': capturer_media_localement is True, 'login_explicitement_autorise': confirmation_envoi_mot_de_passe is True,
         'api_inventaire_confirmee_apk':True,'api_rtc_confirmee_apk':True}
    if not _LOCK.acquire(blocking=False):return {**out,'etat':'test_deja_en_cours'}
    try:
        now=time.monotonic()
        client_key=id(client)
        if standalone_c9c_http_offer_test and now < _LAST_C9C_HTTP.get(client_key,0):
            return {**out,'etat':'limite_offre_http_une_heure'}
        cache=getattr(client,'_tuya_oem_inventory_cache',None)
        cache_fresh=isinstance(cache,dict) and now-cache.get('created',0)<600
        if (standalone_c9c_tuya_detail_audit or standalone_c9c_full_audit_b31) and isinstance(cache,dict):
            # Read-only detail only: keep a verified same-account inventory
            # for at most 30 min, avoiding duplicate Tuya inventory calls.
            created=cache.get('created')
            cache_fresh=(type(created) in (int,float)
                         and 0 <= now-created < 1800
                         and isinstance(cache.get('devices'),dict)
                         and isinstance(cache.get('summary'),dict))
        if (not interactive_live and not standalone_c9c_http_offer_test
                and now < _LAST_RUN.get(client_key,0) and not (tester_rtc and cache_fresh)):
            return {**out,'etat':'limite_inventaire_30_minutes'}
        if capturer_media_localement and (not tester_media or confirmation_media is not True
                or confirmation_capture_locale is not True or not repertoire_capture_locale):
            return {**out,'etat':'capture_locale_confirmation_expresse_requise'}
        if tester_media and (not tester_kcp or confirmation_media is not True or confirmation_kcp is not True or confirmation_relais_tcp is not True or confirmation_offre_mqtt is not True):
            return {**out,'etat':'media_confirmation_expresse_requise'}
        if tester_kcp and (not tester_relais_tcp or confirmation_kcp is not True or confirmation_relais_tcp is not True):
            return {**out,'etat':'kcp_confirmation_expresse_requise'}
        if (tester_mqtt or tester_offre_mqtt) and not tester_rtc:
            return {**out,'etat':'mqtt_requiert_rtc_dans_meme_action'}
        if tester_relais_tcp and (not tester_offre_mqtt or confirmation_relais_tcp is not True):
            return {**out,'etat':'relais_tcp_confirmation_expresse_requise'}
        if tester_offre_mqtt and (not tester_mqtt or confirmation_offre_mqtt is not True):
            return {**out,'etat':'offre_mqtt_confirmation_expresse_requise'}
        identity_data=_ready_identity(client)
        if identity_data is None:return {**out,'etat':'session_AOSU_ou_profil_absent'}
        hints,install_id=identity_data
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**out,'etat':'preflight_OEM_invalide'}
        identity,signer=parsed
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or now-session.acquired_at>1200:
            session=None
        if session is None:
            if confirmation_envoi_mot_de_passe is not True:
                return {**out,'etat':'session_perdue_ou_expiree_confirmation_login_requise'}
            if not interactive_live:
                if standalone_c9c_tuya_detail_audit or standalone_c9c_full_audit_b31:
                    if not _c9c_detail_login_allowed(
                            now, _LAST_LOGIN.get(client_key,0),
                            _LAST_C9C_DETAIL_LOGIN.get(client_key,0)):
                        return {**out,'etat':'limite_reconnexion_fiche_tuya_20_minutes'}
                elif now < _LAST_LOGIN.get(client_key,0) and not standalone_c9c_http_offer_test:
                    return {**out,'etat':'limite_login_une_heure'}
            if not isinstance(client.password,str) or not client.password:
                return {**out,'etat':'mot_de_passe_AOSU_absent'}
            if not interactive_live:
                _LAST_LOGIN[client_key]=now+3600
                if standalone_c9c_tuya_detail_audit or standalone_c9c_full_audit_b31:
                    _LAST_C9C_DETAIL_LOGIN[client_key]=now+1200
            login,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                password=client.password,ttid=f'sdk_international@{identity.app_id}',
                device_id=install_id,endpoint=_ENDPOINT)
            out['appel_reseau']+=login.get('appel_reseau',0) if type(login.get('appel_reseau')) is int else 0
            out['mot_de_passe_envoye']=login.get('mot_de_passe_envoye') is True
            if session is None:
                return {**out,'etat':'login_UID_non_reussi',
                        'categorie_refus':login.get('categorie_refus','non_determinee')}
            client._tuya_oem_session=session
        out['session_tuya_authentifiee']=True
        def read(action,body):
            out['appel_reseau']+=1
            return do_oem_read(identity,signer,'sha256_material',session,action=action,
                form_data=body,ttid=f'sdk_international@{identity.app_id}',
                device_id=install_id,endpoint=_ENDPOINT)
        try:
            if tester_rtc and cache_fresh and cache.get('session_uid') == session.uid:
                all_devices=cache['devices']
                out.update(cache['summary'])
                out['inventaire_cache_utilise']=True
            else:
                if not interactive_live:
                    _LAST_RUN[client_key]=now+_COOLDOWN
                home,safe=read('m.life.home.space.list',{})
                out['inventaire_maisons_accepte']=safe['serveur_accepte']
                if not safe['serveur_accepte'] or safe['rejet_explicite']:
                    return {**out,'etat':'lecture_maisons_refusee',
                            'categorie_refus':safe.get('categorie_refus','indeterminee')}
                gids=_home_groups(home)
                out['nombre_groupes']=len(gids)
                if not gids:return {**out,'etat':'groupes_non_identifies'}
                all_devices={}
                accepted=0
                errors=[]
                for gid in gids:
                    device_response,dstatus=read('m.life.my.group.device.list',{'gid':gid})
                    if dstatus['serveur_accepte'] and not dstatus['rejet_explicite']:
                        accepted+=1
                        for item in _devices(device_response):
                            did=item.get('devId') or item.get('deviceId')
                            if did not in all_devices:all_devices[did]=item
                    else:
                        errors.append(dstatus.get('categorie_refus','indeterminee'))
                out['groupes_lus']=accepted
                out['nombre_appareils_tuya']=len(all_devices)
                out['refus_inventaire']=len(errors)
                if errors:out['categorie_refus']=errors[0]
                out['inventaire_cache_utilise']=False
            statuses={did:_classify(item,getattr(client,'_c5l_sn',None),
                                          getattr(client,'_c5l_coop_id',None),
                                          getattr(client,'_c5l_name',None))
                      for did,item in all_devices.items()}
            # Stable, anonymous per-device slots. This inventory is never
            # persisted; raw objects and IDs never enter the service result.
            out['appareils_anonymises']=[
                _safe_device_report(all_devices[did], i+1, statuses[did],
                                    getattr(client,'_c5l_name',None))
                for i,did in enumerate(sorted(all_devices))][:20]
            confirmed=[did for did,kind in statuses.items() if kind.startswith('c5l_confirmed_')]
            candidates=[did for did,kind in statuses.items() if kind in ('camera_candidate','camera_candidate_name')]
            out['c5l_identification_exacte']=len(confirmed)==1
            out['cameras_candidates']=len(candidates)
            # Safe counts only: no device IDs or names returned to Home Assistant.
            out['cameras_tuya_categorie_video']=sum(
                _has_camera_category(item) for item in all_devices.values())
            out['cameras_c5l_confirmees']=len(confirmed)
            out['cameras_categorie_productBean']=sum(
                bool(isinstance(item.get('productBean'),dict) and
                     str(item['productBean'].get('category','')).strip().lower()=='sp')
                for item in all_devices.values())
            out['cameras_correspondance_nom']=sum(
                bool(isinstance(item.get('name'),str) and
                     isinstance(getattr(client,'_c5l_name',None),str) and
                     getattr(client,'_c5l_name').strip() and
                     item['name'].strip().casefold()==getattr(client,'_c5l_name').strip().casefold())
                for item in all_devices.values())
            if not out['inventaire_cache_utilise']:
                public_summary={k:out[k] for k in ('inventaire_maisons_accepte','nombre_groupes',
                    'groupes_lus','nombre_appareils_tuya','refus_inventaire')}
                client._tuya_oem_inventory_cache={'created':now,'session_uid':session.uid,
                    'devices':all_devices,'summary':public_summary}
            if not tester_rtc:
                return {**out,'etat':'inventaire_termine'}
            name_matches=[did for did,item in all_devices.items()
                if isinstance(item.get('name'),str)
                and isinstance(getattr(client,'_c5l_name',None),str)
                and getattr(client,'_c5l_name').strip()
                and item['name'].strip().casefold()==getattr(client,'_c5l_name').strip().casefold()]
            if (standalone_c9c_video_test or standalone_c9c_http_offer_test or standalone_c9c_rtc_audit
                    or standalone_c9c_mqtt_watch or standalone_c9c_v4_rtc_audit
                    or standalone_c9c_wake_only or standalone_c9c_webrtc_audit
                    or standalone_c9c_ipc_v2_audit
                    or standalone_c9c_tuya_detail_audit
                    or standalone_c9c_full_audit_b31
                    or standalone_c9c_sdk_b37_audit):
                # The C5L-specific selector is intentionally NOT reused here:
                # any unrelated C5L match must never override a C9C selection.
                if (standalone_c9c_video_test or standalone_c9c_http_offer_test or standalone_c9c_wake_only
                        or standalone_c9c_wake_then_video):
                    # Android uses GzDeviceInfo.cpDeviceInfo.cpUuid for
                    # platform Ty; a CP deviceId is NOT a Tuya devId/uuid.
                    # Never authorize traffic from a weak matching heuristic.
                    target, selection = select_tuya_standalone_target_typed(
                        all_devices,
                        camera_sn=getattr(client, '_standalone_c9c_sn', None),
                        camera_cp_device_id=getattr(
                            client, '_standalone_c9c_coop_id', None),
                        camera_ty_cp_uuid=resolve_aosu_ty_cp_uuid(client)[0])
                else:
                    target, selection = select_tuya_standalone_target(
                        all_devices,
                        camera_sn=getattr(client, '_standalone_c9c_sn', None),
                        camera_coop=getattr(client, '_standalone_c9c_coop_id', None))
                if not target or not getattr(client, '_standalone_c9c_sn', None):
                    return {**out, 'etat': 'rtc_non_lance_c9c_non_identifiee',
                            'methode_selection_rtc': selection}
                # The unique-Tuya-device heuristic is good enough for
                # consented READS, never for active camera traffic. The
                # beta39 Thing-4 RTC id match only proves a Tuya-to-Tuya
                # relationship, not the AOSU C9C serial's identity.
                if ((standalone_c9c_video_test or standalone_c9c_wake_only
                     or standalone_c9c_wake_then_video)
                        and selection not in (
                            'identite_exacte_serie',
                            'identite_exacte_cp_device_id',
                            'identite_exacte_cp_device_id_dev_id',
                            'identite_exacte_ty_cp_uuid')):
                    # Never reuse credentials from an earlier manual probe.
                    client._tuya_oem_media_bootstrap=None
                    return {**out,
                            'etat':'c9c_identite_aosu_tuya_non_prouvee',
                            'methode_selection_rtc':selection,
                            'offre_sdp_envoyee':False,
                            'commande_camera':0,
                            'commandes_ptz':0,
                            'session_video_creee':False,
                            'secrets_retournes':False}
                if standalone_c9c_http_offer_test:
                    # Explicit one-shot candidate permission is NOT proof of
                    # identity and NEVER propagates to the live/video selector.
                    target, approval = manual_target_gate(
                        all_devices,
                        aosu_sn=getattr(client,'_standalone_c9c_sn',None),
                        typed_target=target,typed_selection=selection,
                        allow_one_unproven=(
                            confirmation_cible_unique_non_prouvee is True))
                    if target is None:
                        return {**out,'etat':'offre_http_cible_non_autorisee',
                                'motif_cible':approval,'commande_camera':0,
                                'requete_http_effectuee':False}
                    selection=approval
                out['methode_selection_rtc'] = selection
                if standalone_c9c_mqtt_watch:
                    # Only cached/loaded Tuya metadata, no extra network call.
                    # This never establishes the state of a sleeping camera.
                    out['veille_inventaire_c9c'] = inspect_sleep_dp149(
                        all_devices.get(target), inventory=True)
            elif len(confirmed)==1:
                target=confirmed[0]
                out['methode_selection_rtc']='correspondance_exacte'
            elif len(confirmed)==0 and len(candidates)==1 and autoriser_candidat_unique is True:
                target=candidates[0]
                out['methode_selection_rtc']='candidat_camera_unique_non_confirme'
            elif (len(confirmed)==0 and len(name_matches)==1
                  and autoriser_correspondance_nom_unique is True):
                target=name_matches[0]
                out['methode_selection_rtc']='correspondance_nom_unique_non_confirmee'
            else:
                return {**out,'etat':'rtc_non_lance_c5l_non_identifiee',
                        'methode_selection_rtc':'aucune'}
            if standalone_c9c_sdk_b37_audit:
                # Three bounded read-only Tuya account GET-style methods:
                # device detail, IPC-v4 RTC config and the classic RTC config
                # used by Android CameraBusiness.requestCameraInfo.
                # NEVER call thing.m.rtc.session.init: it can create a session.
                # No MQTT, SDP, P2P, wake, video or PTZ command.
                if not interactive_live and now < _LAST_RTC.get(client_key,0):
                    return {**out,'etat':'limite_sdk_b37_cinq_minutes'}
                _LAST_RTC[client_key]=now+300
                detail,detail_safe=read('thing.m.device.get',{'devId':target})
                accepted_detail=(detail_safe.get('serveur_accepte') is True
                                 and detail_safe.get('rejet_explicite') is not True)
                rtc,rtc_safe=read('m.ipc.v4.rtc.config.get',{'devId':target})
                accepted_rtc=(rtc_safe.get('serveur_accepte') is True
                              and rtc_safe.get('rejet_explicite') is not True)
                out['sdk_preparation_b37']=summarize_native_prerequisites_b37(
                    tuya_device=all_devices.get(target,{}) or {},
                    tuya_detail=detail if accepted_detail else None,
                    rtc_response=rtc if accepted_rtc else None,
                    expected_tuya_id=target,
                    detail_accepted=accepted_detail,
                    rtc_accepted=accepted_rtc)
                # Already accepted in the independent beta31 cloud audit.
                # Treat any failure as a partial result, never expose it.
                try:
                    classic,classic_safe=read(
                        'thing.m.rtc.config.get',{'devId':target})
                    accepted_classic=(
                        classic_safe.get('serveur_accepte') is True
                        and classic_safe.get('rejet_explicite') is not True)
                except Exception:
                    classic=None
                    accepted_classic=False
                out['sdk_comparaison_b38']=compare_rtc_sdk_b38(
                    rtc if accepted_rtc else None,
                    classic if accepted_classic else None,
                    ipc_accepted=accepted_rtc,
                    classic_accepted=accepted_classic)
                # Use the actual Python media-bootstrap validator on both
                # already fetched configs. No publish, no camera, no transport.
                # The SDP is generated transiently in RAM and NEVER returned
                # to the card or saved on the client.
                def _media_flags_b40(payload, valid):
                    if not valid:
                        return {}
                    try:
                        report, _volatile = inspect_rtc_media(
                            payload, target,
                            all_devices.get(target, {}).get('localKey',''),
                            session.uid)
                        return {'offre_sdp_aes_kcp_preparee':
                                report.get('offre_sdp_aes_kcp_preparee') is True}
                    except (ValueError, TypeError, KeyError, AttributeError):
                        return {}
                out['sdk_alignment_b40']=summarize_thing4_media_alignment_b40(
                    classic=classic if accepted_classic else None,
                    target=target,classic_accepted=accepted_classic,
                    v4_media=_media_flags_b40(rtc,accepted_rtc),
                    classic_media=_media_flags_b40(classic,accepted_classic))
                return {**out,'etat':'sdk_b37_lecture_terminee'}
            if standalone_c9c_full_audit_b31:
                # One explicit manual diagnostic; no MQTT, wake, media or PTZ.
                if not interactive_live and now < _LAST_RTC.get(client_key,0):
                    return {**out,'etat':'limite_diagnostic_complet_cinq_minutes'}
                _LAST_RTC[client_key]=now+300
                out['audit_complet_b31']=run_full_c9c_audit_b31(
                    read,target=target,inventory=all_devices.get(target,{}) or {},
                    aosu_sn=getattr(client,'_standalone_c9c_sn',None),
                    aosu_coop=getattr(client,'_standalone_c9c_coop_id',None),
                    parse_device=summarize_tuya_device_b27,
                    parse_hints=inspect_webrtc_hints,
                    parse_rtc=summarize_c9c_rtc_schema)
                return {**out,'etat':(
                    'diagnostic_complet_termine'
                    if out['audit_complet_b31']['etat']=='termine'
                    else 'diagnostic_complet_partiel')}
            if standalone_c9c_tuya_detail_audit:
                # One explicitly confirmed Tuya account read, no RTC, wake,
                # MQTT offer, P2P, video, recording or PTZ.
                if not interactive_live and now < _LAST_RTC.get(client_key,0):
                    return {**out,'etat':'limite_fiche_tuya_cinq_minutes'}
                _LAST_RTC[client_key]=now+300
                # Replace, never append, previous private UUID evidence.
                # Only one account-authenticated detail response is retained
                # as up to four validated ID strings, TTL 10 min, no secrets.
                client._c9c_reverse_uuid_cache=None
                detail,detail_safe=read('thing.m.device.get',{'devId':target})
                out['fiche_tuya_api_acceptee']=detail_safe['serveur_accepte']
                if not detail_safe['serveur_accepte'] or detail_safe['rejet_explicite']:
                    return {**out,'etat':'fiche_tuya_refusee'}
                out['fiche_tuya_b27']=summarize_tuya_device_b27(
                    detail,expected_device_id=target,
                    aosu_sn=getattr(client,'_standalone_c9c_sn',None),
                    aosu_coop=getattr(client,'_standalone_c9c_coop_id',None))
                client._c9c_reverse_uuid_cache={
                    'created':time.monotonic(),
                    'session_uid':session.uid,
                    'target':target,
                    'candidates':extract_tuya_detail_cp_candidates(
                        detail,target)}
                return {**out,'etat':'fiche_tuya_obtenue'}
            # Drop previous provisional media credentials before minting any new RTC config.
            client._tuya_oem_media_bootstrap=None
            if (not interactive_live and not standalone_c9c_http_offer_test
                    and now < _LAST_RTC.get(client_key,0)):
                return {**out,'etat':'limite_rtc_cinq_minutes'}
            if not interactive_live:
                _LAST_RTC[client_key]=now+300
            # The native AOSU Thing-4 CameraBusiness.requestCameraInfo
            # reads thing.m.rtc.config.get, not m.ipc.v4.rtc.config.get.
            # Use this SDK route ONLY for standalone C9C video. Keep IPC-v4
            # for its explicit read-only diagnostic and wake-only probes.
            # C5L and H1L retain their original classic RTC route.
            if standalone_c9c_ipc_v2_audit:
                # Approved OEM method; explicit one-off read, no RTC/MQTT/P2P.
                ipc,ipc_safe=read('thing.m.ipc.config.get',{'devId':target})
                out['ipc_v2_acceptee']=ipc_safe['serveur_accepte']
                if not ipc_safe['serveur_accepte'] or ipc_safe['rejet_explicite']:
                    return {**out,'etat':'ipc_v2_refusee'}
                webrtc,_unused_msid=inspect_webrtc_hints(ipc,{})
                ipc_schema=summarize_c9c_rtc_schema(ipc,{})
                out['ipc_v2_b24']={
                    'moto_id_present':webrtc['moto_id_present'],
                    'auth_present':webrtc['auth_webrtc_present'],
                    'msid_present':webrtc['msid_explicite_present'],
                    'msid_ambigu':webrtc['msid_ambigu'],
                    'webrtc_declare':webrtc['webrtc_declare_oui'],
                    'webrtc_refuse_explicitement':webrtc['webrtc_declare_non'],
                    'p2p_config_present':ipc_schema['p2p_config_presente'],
                    'serveurs_ice_presents':ipc_schema['serveurs_ice_presents'],
                    'rtc_session_presente':ipc_schema['session_presente'],
                }
                return {**out,'etat':'ipc_v2_obtenue'}
            rtc_ipc_v4 = (standalone_c9c_v4_rtc_audit is True or
                          standalone_c9c_wake_only is True or
                          standalone_c9c_webrtc_audit is True)
            rtc_method=('m.ipc.v4.rtc.config.get' if rtc_ipc_v4
                        else 'thing.m.rtc.config.get')
            out['rtc_api_source']='ipc_v4' if rtc_ipc_v4 else 'thing_rtc'
            rtc,rtcsafe=read(rtc_method,{'devId':target})
            out['configuration_rtc_acceptee']=rtcsafe['serveur_accepte']
            if not rtcsafe['serveur_accepte'] or rtcsafe['rejet_explicite']:
                return {**out,'etat':'configuration_rtc_refusee',
                        'categorie_refus':rtcsafe.get('categorie_refus','indeterminee')}
            out['rtc']=_rtc_presence(rtc)
            if standalone_c9c_rtc_audit:
                out['rtc_c9c_schema']=summarize_c9c_rtc_schema(rtc, all_devices[target])
            if standalone_c9c_v4_rtc_audit:
                out['rtc_v4_schema']=summarize_c9c_rtc_schema(rtc, all_devices[target])
            if standalone_c9c_webrtc_audit:
                schema, private_msid = inspect_webrtc_hints(rtc, all_devices[target])
                out['webrtc_b23']=schema
                if standalone_c9c_webrtc_channel:
                    out['webrtc_canal_b23']=subscribe_webrtc_once(
                        client,identity,signer,session,install_id,target,private_msid)
            media,private=inspect_rtc_media(
                rtc,target,all_devices[target].get('localKey',''),session.uid,
                standalone_c9c=(standalone_c9c_video_test is True))
            out['media_bootstrap']=media
            if standalone_c9c_v4_rtc_audit:
                out['media_v4_pret']=private is not None
            if standalone_c9c_video_test:
                # Keep the legacy C9C video branch unchanged.
                moto_value, moto_source=resolve_rtc_moto_id(rtc)
                out['moto_id_source_rtc']=moto_source
                out['moto_id_rtc_exploitable']=bool(moto_value)
                if private is not None:
                    private.moto_id=moto_value
            if standalone_c9c_http_offer_test:
                # HTTP-only experiment never activates the video branch.
                moto_value, moto_source=resolve_rtc_moto_id(rtc)
                out['moto_id_source_rtc']=moto_source
                out['moto_id_rtc_exploitable']=bool(moto_value)
                if private is not None:
                    private.moto_id=moto_value

            # Retain only briefly in RAM. RTC sessions are minted per request; never persist.
            if private is not None:
                client._tuya_oem_media_bootstrap=private
            else:
                client._tuya_oem_media_bootstrap=None
            if standalone_c9c_http_offer_test:
                # This probe intentionally DOES NOT send MQTT/ICE, wake or PTZ.
                # Its only possible state change is ONE authenticated HTTP offer.
                if not validate_type4_rtc(rtc,target):
                    client._tuya_oem_media_bootstrap=None
                    return {**out,'etat':'offre_http_type4_non_prouve',
                            'requete_http_effectuee':False}
                if private is None:
                    client._tuya_oem_media_bootstrap=None
                    return {**out,'etat':'offre_http_rtc_incompatible',
                            'requete_http_effectuee':False}
                try:
                    _key,signal_offer=_media_payload(private,session.uid,
                                                      use_moto_id=True)
                    form=native_http_form(signal_offer,target=target)
                except (ValueError,TypeError,AttributeError,KeyError):
                    client._tuya_oem_media_bootstrap=None
                    return {**out,'etat':'offre_http_preparation_refusee',
                            'requete_http_effectuee':False}
                # Consume the per-installation permission BEFORE sending.
                _LAST_C9C_HTTP[client_key]=time.monotonic()+3600
                out['appel_reseau']+=1
                out['requete_http_effectuee']=True
                try:
                    result=do_oem_thing4_session_offer_once(
                        identity,signer,'sha256_material',session,target=target,
                        form_data=form,ttid=f'sdk_international@{identity.app_id}',
                        device_id=install_id,endpoint=_ENDPOINT,
                        explicit_consent=True)
                finally:
                    client._tuya_oem_media_bootstrap=None
                out['offre_http_c9c']=safe_http_result(result)
                out['etat']='offre_http_test_termine'
                return out
            if standalone_c9c_wake_then_video and private is None:
                out['etat']='reveil_video_rtc_incompatible'
                return out
            if tester_offre_mqtt is True and private is not None:
                # Shared MQTT session creates its own wake report first.
                # Read it only after run_tuya_mqtt_offer completes.
                out['signalisation_mqtt']=run_tuya_mqtt_offer(
                    client,identity,signer,session,install_id,private,
                    tester_relais_tcp=tester_relais_tcp,tester_kcp=tester_kcp, tester_media=tester_media,
                    local_capture_directory=(repertoire_capture_locale if capturer_media_localement else None),
                    live_preview=live_preview, interactive_live=interactive_live,
                    use_standalone_c9c_moto_id=(standalone_c9c_video_test is True),
                    wake_before_offer=standalone_c9c_wake_then_video)
                if standalone_c9c_wake_then_video:
                    out['reveil_et_video'] = (
                        out['signalisation_mqtt'].get('reveil_et_video') or
                        {'etat':'offre_non_initialisee',
                         'offre_autorisee':False,'offre_effectuee':False})
                # A startup burst is a camera command; report it honestly, unlike read-only stages.
                try:
                    media_result=(out['signalisation_mqtt'].get('relais_tcp') or {}).get('kcp',{}).get('media_start',{})
                    command_count=media_result.get('commandes_controle_envoyees',0)
                    if type(command_count) is int and command_count>0:
                        out['commande_camera']=command_count
                        out['commandes_demarrage_video']=command_count
                        out['session_video_creee']=bool(media_result.get('conversation_video_detectee'))
                except (TypeError,AttributeError):
                    pass
            elif tester_mqtt is True and private is not None:
                if standalone_c9c_wake_only:
                    out['reveil_c9c']=try_wake_c9c_once(
                        client,identity,signer,session,install_id,private)
                elif standalone_c9c_mqtt_watch:
                    out['signalisation_mqtt']=observe_mqtt_for_c9c(
                        client,identity,signer,session,install_id,private)
                else:
                    out['signalisation_mqtt']=run_tuya_mqtt_signalisation(
                        client,identity,signer,session,install_id,private)
            elif tester_mqtt is True:
                out['signalisation_mqtt']={'etat':'mqtt_non_lance_rtc_non_valide',
                    'appel_http_supplementaire':0,'commande_camera':0,
                    'session_video_creee':False,'secrets_retournes':False}
            out['etat']='configuration_rtc_obtenue'
            if (standalone_c9c_rtc_audit or standalone_c9c_mqtt_watch
                    or standalone_c9c_v4_rtc_audit or standalone_c9c_wake_only
                    or standalone_c9c_webrtc_audit):
                # These manual checks do not retain provisional media
                # keys from an audit that cannot produce an offer.
                client._tuya_oem_media_bootstrap=None
            return out
        except OEMGatewayError as exc:
            return {**out,'etat':'erreur_api_tuya','raison':exc.code}
        except Exception:
            return {**out,'etat':'erreur_execution_sans_details'}
    finally:
        _LOCK.release()
