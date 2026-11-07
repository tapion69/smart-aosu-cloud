"""Manual, opt-in read-only inventory and optional RTC configuration probe.

The OEM Tuya session is held only in memory. Never expose device identifiers,
local keys, session tokens, network endpoints, or decrypted server bodies.
No camera command, P2P connection or streaming is initiated here.
"""
from __future__ import annotations
import threading
import time
from typing import Any
from .uid_token_probe import _ready_identity, _apk_preflight
from .tuya_uid_gateway import (TuyaAuthSession, OEMGatewayError,
                               do_uid_login_request, do_oem_read)
from .tuya_media_bootstrap import inspect_rtc_media
from .tuya_mqtt_signaling import run_tuya_mqtt_signalisation
from .tuya_mqtt_offer import run_tuya_mqtt_offer
from .camera_topology import select_tuya_standalone_target

_LOCK = threading.Lock()
_LAST_RUN: dict[int, float] = {}
_LAST_LOGIN: dict[int, float] = {}
_LAST_RTC: dict[int, float] = {}
_COOLDOWN = 1800  # prevent manual repetitive discovery while developing
_ENDPOINT = 'https://a1.tuyaeu.com/api.json'


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
                           standalone_c9c_video_test:bool=False):
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
        cache=getattr(client,'_tuya_oem_inventory_cache',None)
        cache_fresh=isinstance(cache,dict) and now-cache.get('created',0)<600
        if not interactive_live and now < _LAST_RUN.get(client_key,0) and not (tester_rtc and cache_fresh):
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
            if not interactive_live and now < _LAST_LOGIN.get(client_key,0):
                return {**out,'etat':'limite_login_une_heure'}
            if not isinstance(client.password,str) or not client.password:
                return {**out,'etat':'mot_de_passe_AOSU_absent'}
            if not interactive_live:
                _LAST_LOGIN[client_key]=now+3600
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
            if standalone_c9c_video_test:
                # The C5L-specific selector is intentionally NOT reused here:
                # any unrelated C5L match must never override a C9C selection.
                target, selection = select_tuya_standalone_target(
                    all_devices,
                    camera_sn=getattr(client, '_standalone_c9c_sn', None),
                    camera_coop=getattr(client, '_standalone_c9c_coop_id', None))
                if not target or not getattr(client, '_standalone_c9c_sn', None):
                    return {**out, 'etat': 'rtc_non_lance_c9c_non_identifiee',
                            'methode_selection_rtc': selection}
                out['methode_selection_rtc'] = selection
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
            # Drop previous provisional media credentials before minting any new RTC config.
            client._tuya_oem_media_bootstrap=None
            if not interactive_live and now < _LAST_RTC.get(client_key,0):
                return {**out,'etat':'limite_rtc_cinq_minutes'}
            if not interactive_live:
                _LAST_RTC[client_key]=now+300
            rtc,rtcsafe=read('thing.m.rtc.config.get',{'devId':target})
            out['configuration_rtc_acceptee']=rtcsafe['serveur_accepte']
            if not rtcsafe['serveur_accepte'] or rtcsafe['rejet_explicite']:
                return {**out,'etat':'configuration_rtc_refusee',
                        'categorie_refus':rtcsafe.get('categorie_refus','indeterminee')}
            out['rtc']=_rtc_presence(rtc)
            media,private=inspect_rtc_media(rtc,target,all_devices[target].get('localKey',''),session.uid)
            out['media_bootstrap']=media
            # Retain only briefly in RAM. RTC sessions are minted per request; never persist.
            if private is not None:
                client._tuya_oem_media_bootstrap=private
            else:
                client._tuya_oem_media_bootstrap=None
            if tester_offre_mqtt is True and private is not None:
                out['signalisation_mqtt']=run_tuya_mqtt_offer(
                    client,identity,signer,session,install_id,private,
                    tester_relais_tcp=tester_relais_tcp,tester_kcp=tester_kcp, tester_media=tester_media,
                    local_capture_directory=(repertoire_capture_locale if capturer_media_localement else None),
                    live_preview=live_preview, interactive_live=interactive_live)
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
                out['signalisation_mqtt']=run_tuya_mqtt_signalisation(
                    client,identity,signer,session,install_id,private)
            elif tester_mqtt is True:
                out['signalisation_mqtt']={'etat':'mqtt_non_lance_rtc_non_valide',
                    'appel_http_supplementaire':0,'commande_camera':0,
                    'session_video_creee':False,'secrets_retournes':False}
            out['etat']='configuration_rtc_obtenue'
            return out
        except OEMGatewayError as exc:
            return {**out,'etat':'erreur_api_tuya','raison':exc.code}
        except Exception:
            return {**out,'etat':'erreur_execution_sans_details'}
    finally:
        _LOCK.release()
