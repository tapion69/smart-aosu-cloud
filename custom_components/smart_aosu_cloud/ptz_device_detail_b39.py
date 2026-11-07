"""PTZ OEM device DETAIL read (thing.m.device.get v4.1 from AOSU SDK).

The APK contains SDK device.get v4.1 with one `devId` field; this is an
explicit, strictly read-only diagnostic. The device's internal identifiers and
all raw response data must never leave volatile RAM. No motor commands.
"""
from __future__ import annotations
import re
import threading
import time

_LOCK=threading.Lock()
_LAST_CALL:dict[int,float]={}
_INTERVAL=120


def select_c5l_oem(coordinator):
    """Return exactly one C5L candidate, or nothing (do not trust name alone)."""
    from .live_device import select_live_camera_key
    from .tuya_rtc_inventory import _c5l_match
    client=coordinator.client
    selected=select_live_camera_key(coordinator)
    d=getattr(coordinator,'data',None)
    rows=d if isinstance(d,dict) else {}
    normalized=rows.get(selected) if selected is not None else None
    if not isinstance(normalized,dict) or str(normalized.get('model','')).upper()!='C5L':
        return None,'appareil_aosu_non_confirme'
    cache=getattr(client,'_tuya_oem_inventory_cache',None)
    if not isinstance(cache,dict) or not 0 <= time.monotonic()-cache.get('created',0) < 600:
        return None,'cache_oem_absent_ou_expire'
    devices=cache.get('devices',{})
    if not isinstance(devices,dict):return None,'cache_oem_non_structure'
    name=getattr(client,'_c5l_name',None)
    matches=[];strong=[]
    for did,row in list(devices.items())[:30]:
        if not isinstance(row,dict):continue
        if isinstance(name,str) and name.strip() and isinstance(row.get('name'),str) and row['name'].strip().casefold()==name.strip().casefold():
            matches.append((did,row))
        if _c5l_match(row,getattr(client,'_c5l_sn',None),getattr(client,'_c5l_coop_id',None)):
            strong.append((did,row))
    if len(strong)==1:chosen=strong[0];method='identification_exacte'
    elif len(matches)==1:chosen=matches[0];method='nom_unique_confirme_par_utilisateur'
    else:return None,'selection_ambigue'
    did,row=chosen
    if not isinstance(did,str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}',did):
        return None,'identifiant_non_compatible'
    from .ptz_readiness import _ptz_flags
    flags=_ptz_flags(row)
    if not flags['code_direction_repere'] or not flags['code_arret_repere']:
        return None,'ptz_absent_fiche_cible'
    return (did,row,method),'ok'


def audit_ptz_device_detail(coordinator,*,password_confirmed=False,camera_confirmed=False,include_structure=False,include_sdk_structure=False):
    """Bounded GET on one selected C5L; never publishDps or motor actions."""
    from .tuya_uid_gateway import TuyaAuthSession, OEMGatewayError, do_uid_login_request,do_oem_read
    from .uid_token_probe import _ready_identity,_apk_preflight
    from .ptz_schema_b38 import inspect_ptz_schema
    base={'diagnostic':'aosu_ptz_device_detail_b39','lecture_seule':True,
          'commandes_ptz_envoyees':0,'commandes_camera_envoyees':0,
          'video_demarre':False,'demande_mqtt':False,'demande_rtc':False,
          'arret_moteur_verifie':False,'mouvement_autorise':False,
          'secrets_retournes':False,'identifiants_retournes':False,
          'appels_reseau':0,'action_sdk_verifiee_dans_apk':True,
          'api_lue':'thing.m.device.get','version_api':'4.1'}
    if password_confirmed is not True or camera_confirmed is not True:
        return {**base,'etat':'deux_confirmations_requises'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**base,'etat':'direct_en_cours_reessayer_apres_arret'}
    selected,why=select_c5l_oem(coordinator)
    if selected is None:return {**base,'etat':why,'conseil':'actualiser_oem_avec_audit_ptz_c5l'}
    did,row,method=selected
    base['selection_oem']=method
    now=time.monotonic()
    remaining=_LAST_CALL.get(id(coordinator.client),0)-now
    if remaining>0:
        return {**base,'etat':'temporisation_diagnostic','delai_restant_secondes':int(remaining)+1}
    if not _LOCK.acquire(blocking=False):return {**base,'etat':'autre_audit_ptz_en_cours'}
    try:
        now=time.monotonic()
        if _LAST_CALL.get(id(coordinator.client),0)>now:
            return {**base,'etat':'temporisation_diagnostic'}
        _LAST_CALL[id(coordinator.client)]=now+_INTERVAL
        client=coordinator.client
        raw=_ready_identity(client)
        if raw is None:return {**base,'etat':'profil_oem_absent'}
        hints,install_id=raw
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**base,'etat':'ressources_oem_invalides'}
        identity,signer=parsed
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or now-session.acquired_at>1200:
            session=None
        if session is None:
            password=getattr(client,'password',None)
            if not isinstance(password,str) or not password:return {**base,'etat':'mot_de_passe_absent'}
            login,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                password=password,ttid=ttid,device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            base['appels_reseau']+=int(login.get('appel_reseau',0))
            if session is None:return {**base,'etat':'authentification_refusee_ou_expiree'}
            client._tuya_oem_session=session
        base['appels_reseau']+=1
        response,status=do_oem_read(identity,signer,'sha256_material',session,
            action='thing.m.device.get',form_data={'devId':did},
            ttid=ttid,device_id=install_id,endpoint='https://a1.tuyaeu.com/api.json')
        if status.get('rejet_explicite') or not status.get('serveur_accepte'):
            return {**base,'etat':'lecture_fiche_refusee_ou_non_confirmee',
                    'categorie_refus':status.get('categorie_refus','indeterminee')}
        # Raw data stays local, including hidden device IDs and DP status values.
        detail=inspect_ptz_schema(response)
        from .ptz_schema_map_b67 import inspect_sdk_schema_map
        sdk_schema_map=inspect_sdk_schema_map(response)
        sdk_schema_oem=inspect_sdk_schema_map(row)
        from .ptz_publication_route_b70 import inspect_publication_route_b70
        route_oem=inspect_publication_route_b70(row)
        route_fiche=inspect_publication_route_b70(response)
        available_oem=route_oem['valeurs_data_model']
        available_fiche=route_fiche['valeurs_data_model']
        if available_oem and available_fiche:
            comparatif='concordance' if available_oem == available_fiche else 'divergence'
        elif available_oem or available_fiche:
            comparatif='une_source_seulement'
        else:
            comparatif='absent_des_deux_sources'
        publication_route={
            'apk_preuve': 'AbsThingDevice_publishDps_32865_et_DataModelType_clinit_14053',
            'enum_sdk': {'thing_dp': 1, 'thing_model': 2},
            'inventaire_oem': route_oem,
            'fiche_detaillee': route_fiche,
            'comparaison_sources': comparatif,
            'publication_camera_confirmee': False,
        }
        from .ptz_cadv_evidence_b64 import inspect_cadv
        preuves_cadv={'inventaire_oem':inspect_cadv(row), 'fiche_detaillee':inspect_cadv(response)}
        provenance_cadv_b65={
            'source_sdk':'DeviceRespBean.getGatewayVerCAD_vers_DeviceBean.setCadv',
            'champ_recherche':'gatewayVerCAD',
            'champ_sdk_observe_dans_inventaire':preuves_cadv['inventaire_oem']['champ_sdk_gatewayVerCAD_present'],
            'champ_sdk_observe_dans_fiche':preuves_cadv['fiche_detaillee']['champ_sdk_gatewayVerCAD_present'],
            'valeur_sdk_certifiee':False,
            'lecture_seule':True,
            'commandes_ptz_emises':0,
            'secrets_retournes':False,
            'identifiants_retournes':False,
        }
        if (preuves_cadv['fiche_detaillee']['champ_sdk_gatewayVerCAD_present']
                and preuves_cadv['fiche_detaillee']['valeur_confirmee'] is not None
                and not preuves_cadv['fiche_detaillee']['plusieurs_valeurs_contradictoires']):
            provenance_cadv_b65['valeur_sdk_certifiee']=True
        shape = None
        if include_structure:
            from .ptz_shape_b44 import summarize_ptz_oem_shape
            shape=summarize_ptz_oem_shape(response)
        sdk_sources = None
        if include_sdk_structure:
            from .ptz_sdk_sources_b47 import inspect_sdk_properties
            sdk_sources=inspect_sdk_properties(response)
        return {**base,'etat':'fiche_detaillee_lue',
                'schema_ptz_detaille':detail,
                'schema_map_sdk_b67':sdk_schema_map,
                'schema_map_inventaire_b68':sdk_schema_oem,
                'publication_sdk_b70':publication_route,
                'preuves_cadv_b64':preuves_cadv,
                'provenance_cadv_b65':provenance_cadv_b65,
                'format_reponse':'objet' if isinstance(response,dict) else 'autre',
                'nombre_champs_racine':min(250,len(response)) if isinstance(response,dict) else 0,
                'preuve_publication':False,
                **({'structure_ptz_b44':shape} if include_structure else {}),
                **({'sdk_sources_b47':sdk_sources} if include_sdk_structure else {})}
    except OEMGatewayError as exc:
        return {**base,'etat':'erreur_api_oem','raison':exc.code}
    except Exception:
        return {**base,'etat':'erreur_sans_details'}
    finally:_LOCK.release()


def audit_ptz_device_detail_with_refresh(coordinator,*,password_confirmed=False,camera_confirmed=False,include_structure=False):
    """One opt-in diagnostic: refresh stale OEM inventory then GET device detail.

    Both phases use documented read-only API calls. A rejected first phase never
    triggers the second phase, and no motor controls are permitted.
    """
    base={'diagnostic':'aosu_ptz_device_detail_b39','lecture_seule':True,
          'commandes_ptz_envoyees':0,'commandes_camera_envoyees':0,
          'secrets_retournes':False,'identifiants_retournes':False,
          'appels_reseau':0,'mouvement_autorise':False}
    if password_confirmed is not True or camera_confirmed is not True:
        return {**base,'etat':'deux_confirmations_requises'}
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**base,'etat':'direct_en_cours_reessayer_apres_arret'}
    from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
    pre=audit_ptz_readiness(coordinator,coordinator.client)
    total=0;refresh_status='cache_recent_reutilise'
    if not pre.get('cache_oem_recent'):
        updated=refresh_ptz_inventory(coordinator,password_confirmed=True)
        refresh_status=updated.get('etat','erreur_sans_details')
        total=updated.get('appels_reseau',0)
        if refresh_status not in ('inventaire_oem_ptz_lu','cache_recent_reutilise'):
            return {**base,'etat':'actualisation_oem_impossible',
                    'etat_actualisation':refresh_status,'appels_reseau':total}
    result=audit_ptz_device_detail(coordinator,
              password_confirmed=True,camera_confirmed=True,include_structure=include_structure)
    return {**result,'cache_oem':'actualise' if refresh_status=='inventaire_oem_ptz_lu' else 'reutilise',
            'appels_reseau':result.get('appels_reseau',0)+total}
