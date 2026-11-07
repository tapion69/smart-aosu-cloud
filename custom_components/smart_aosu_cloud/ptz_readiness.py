"""Read-only Tuya PTZ capability discovery for AOSU C5L (b37).

This module deliberately does NOT infer PTZ packet framing from the media
channel. AOSU 5.10.12 invokes ThingIPCSdk.getPTZInstance(cpDeviceId) for Ty
models; the corresponding DP publisher is not implemented in this integration.
No raw Tuya IDs, local keys, tokens or camera names are returned.
"""
from __future__ import annotations
import time
import threading

# Tuya Smart App SDK documented codepoint mapping, not a verified AOSU wire protocol.
DIRECTIONS = {'haut': '0', 'droite': '2', 'bas': '4', 'gauche': '6'}
DP_CONTROL = 'ptz_control'
DP_STOP = 'ptz_stop'


def _ptz_flags(item: object) -> dict:
    """Bounded walk of only known, explicit DP identifiers; no raw values."""
    found = set()
    nodes = [item]
    visited = 0
    while nodes and visited < 120:
        node = nodes.pop()
        visited += 1
        if isinstance(node, dict):
            for name in ('ptz_control', 'ptz_stop'):
                if name in node:
                    found.add(name)
            for key in ('dpCode', 'code', 'name', 'identifier'):
                value = node.get(key)
                if isinstance(value, str) and value in (DP_CONTROL, DP_STOP):
                    found.add(value)
            if '119' in node:
                found.add(DP_CONTROL)
            if '116' in node:
                found.add(DP_STOP)
            for val in list(node.values())[:60]:
                if isinstance(val, (dict, list)):
                    nodes.append(val)
        elif isinstance(node, list):
            for val in node[:60]:
                if isinstance(val, (dict, list)):
                    nodes.append(val)
    return {'code_direction_repere': DP_CONTROL in found,
            'code_arret_repere': DP_STOP in found,
            'objets_examines': visited}


def audit_ptz_readiness(coordinator, client) -> dict:
    """Offline local snapshot; never initiate connection or control movement."""
    from .live_device import select_live_camera_key
    from .transport_audit import audit_cached_platforms
    selected = select_live_camera_key(coordinator)
    data = getattr(coordinator, 'data', None)
    devices = data if isinstance(data, dict) else {}
    normalized = devices.get(selected) if selected is not None else None
    cache = getattr(client, '_tuya_oem_inventory_cache', None)
    stale = not (isinstance(cache, dict) and 0 <= time.monotonic()-cache.get('created', 0) < 600)
    matches = []
    raw_devices = cache.get('devices', {}) if isinstance(cache, dict) else {}
    name = getattr(client, '_c5l_name', None)
    if isinstance(raw_devices, dict) and isinstance(name, str) and name.strip():
        for row in raw_devices.values():
            if not isinstance(row, dict):
                continue
            if isinstance(row.get('name'), str) and row['name'].strip().casefold() == name.strip().casefold():
                matches.append(row)
    # An exact model/serial/coop link (if available) takes priority over a name.
    from .tuya_rtc_inventory import _c5l_match
    strong_matches = []
    if isinstance(raw_devices, dict):
        for candidate in raw_devices.values():
            if isinstance(candidate, dict) and _c5l_match(
                candidate, getattr(client, '_c5l_sn', None),
                getattr(client, '_c5l_coop_id', None)):
                strong_matches.append(candidate)
    exact = len(strong_matches) == 1
    selection = ('correspondance_exacte_modele_serie' if exact
                 else 'nom_unique_non_certifie' if len(matches) == 1
                 else 'aucune_ou_ambigue')
    row = (strong_matches[0] if exact else matches[0] if len(matches)==1 else None) if not stale else None
    dp = _ptz_flags(row) if row else _ptz_flags({})
    from .ptz_schema_b38 import inspect_ptz_schema
    dp_schema = inspect_ptz_schema(row)
    platform = audit_cached_platforms(devices)
    return {
        'diagnostic': 'aosu_ptz_c5l_b38',
        'appareil_c5l_identifie': bool(selected and normalized),
        'modele_c5l_c5l': bool(normalized and str(normalized.get('model', '')).upper() == 'C5L'),
        'cache_oem_disponible': isinstance(cache, dict),
        'cache_oem_recent': not stale,
        'correspondance_nom_unique_oem': len(matches) == 1,
        'identification_exacte_oem': exact,
        'selection_oem': selection,
        'codes_ptz_cache': dp,
        'schema_ptz_b38': dp_schema,
        'plateforme_c5l_connue': platform.get('c5l_plateforme', 'indeterminee'),
        'reference_tuya_racine_connue': platform.get('c5l_reference_racine_disponible', False),
        'documentation_tuya': {
            'dp_mouvement': DP_CONTROL, 'dp_arret': DP_STOP,
            'mapping_directionnel': 'varie_selon_les_versions_du_sdk_tuya',
            'directions_de_la_c5l_confirmees': False,
            'ordres_p2p_biz_aosulife': 'encodage_non_valide_sur_C5L',
            'valeurs_directionnelles_verifiees_sur_c5l': False,
        },
        'transport_ptz_verifie': False,
        'arret_moteur_verifie': False,
        'mouvement_autorise_par_integration': False,
        'commandes_ptz_envoyees': 0,
        'appels_reseau': 0,
        'secrets_retournes': False,
        'prochaine_validation': ('valider_transport_publication_et_arret_ptz'
                                if row else 'selectionner_unique_C5L_et_verifier_capacites'),
    }


# Active inspection is a *separate*, explicitly authorized, read-only action.
# No guessed Tuya endpoint or camera movement is used. Calls are capped and
# throttled independently from the interactive video connection.
_PTZ_REFRESH_LOCK = threading.Lock()
_PTZ_LAST_REFRESH: dict[int, float] = {}
_PTZ_REFRESH_INTERVAL = 120


def refresh_ptz_inventory(coordinator, *, password_confirmed: bool = False,
                          allow_during_live: bool = False) -> dict:
    """Read current OEM device-list schema without RTC, MQTT, media or PTZ.

    The API names are already validated by previous C5L video sessions.
    Device IDs, session data, local keys and metadata stay in volatile RAM.
    """
    from .tuya_uid_gateway import (
        TuyaAuthSession, OEMGatewayError, do_uid_login_request, do_oem_read)
    from .uid_token_probe import _ready_identity, _apk_preflight
    from .tuya_rtc_inventory import _home_groups, _devices
    client = coordinator.client
    before = audit_ptz_readiness(coordinator, client)
    prefix = {'diagnostic': 'aosu_ptz_refresh_b37', 'commandes_ptz_envoyees': 0,
              'commandes_camera_envoyees': 0, 'demande_rtc': False,
              'demande_mqtt': False, 'video_demarre': False,
              'secrets_retournes': False, 'lecture_seule': True,
              'authentification_confirmee': password_confirmed is True,
              'appels_reseau': 0}
    if before['cache_oem_recent']:
        return {**prefix, 'etat': 'cache_recent_reutilise', 'capacites': before}
    if not password_confirmed:
        return {**prefix, 'etat': 'confirmation_login_requise_si_session_expiree',
                'capacites': before}
    controller=getattr(coordinator,'live_controller',None)
    if not allow_during_live and controller is not None and getattr(controller,'running',False):
        return {**prefix, 'etat':'direct_en_cours_reessayer_hors_direct',
                'capacites':before}
    now=time.monotonic()
    remaining=max(0, _PTZ_LAST_REFRESH.get(id(client),0)-now)
    if remaining:
        return {**prefix, 'etat':'limitation_diagnostic_ptz',
                'delai_restant_secondes':int(remaining+0.999), 'capacites':before}
    if not _PTZ_REFRESH_LOCK.acquire(blocking=False):
        return {**prefix, 'etat':'autre_diagnostic_ptz_en_cours',
                'capacites':before}
    # Allow one explicit refresh per 120 s, even if it fails; no automatic retry.
    try:
        now=time.monotonic()
        cache=getattr(client, '_tuya_oem_inventory_cache', None)
        if isinstance(cache,dict) and 0<=now-cache.get('created',0)<600:
            return {**prefix, 'etat':'cache_recent_reutilise',
                    'capacites':audit_ptz_readiness(coordinator,client)}
        _PTZ_LAST_REFRESH[id(client)]=now+_PTZ_REFRESH_INTERVAL
        raw=_ready_identity(client)
        if raw is None:
            return {**prefix, 'etat':'profil_oem_absent','capacites':before}
        hints,install_id=raw
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:
            return {**prefix,'etat':'apk_oem_invalide','capacites':before}
        identity,signer=parsed
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or now-session.acquired_at>1200:
            session=None
        if session is None:
            if not isinstance(getattr(client,'password',None),str) or not client.password:
                return {**prefix,'etat':'mot_de_passe_absent','capacites':before}
            login,session=do_uid_login_request(
                identity,signer,'sha256_material',uid=hints.tuya_username,
                country_code=hints.country_code,password=client.password,
                ttid=ttid,device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            prefix['appels_reseau'] += login.get('appel_reseau',0) if isinstance(login,dict) else 0
            if session is None:
                return {**prefix, 'etat':'login_non_reussi',
                        'categorie_refus':login.get('categorie_refus','indeterminee'),
                        'capacites':before}
            client._tuya_oem_session=session
        def read(action,form):
            prefix['appels_reseau']+=1
            return do_oem_read(identity,signer,'sha256_material',session,
                               action=action,form_data=form,ttid=ttid,
                               device_id=install_id,
                               endpoint='https://a1.tuyaeu.com/api.json')
        homes,st=read('m.life.home.space.list',{})
        if not st.get('serveur_accepte') or st.get('rejet_explicite'):
            return {**prefix,'etat':'lecture_maisons_refusee','capacites':before}
        gids=_home_groups(homes)
        if not gids:
            return {**prefix,'etat':'aucun_groupe_oem','capacites':before}
        devices={}
        successful=0
        for gid in gids[:4]:
            payload,status=read('m.life.my.group.device.list',{'gid':gid})
            if status.get('serveur_accepte') and not status.get('rejet_explicite'):
                successful+=1
                for item in _devices(payload):
                    did=item.get('devId') or item.get('deviceId')
                    if isinstance(did,str):devices[did]=item
        if successful!=len(gids[:4]):
            return {**prefix,'etat':'lecture_appareils_incomplete',
                    'groupes_lus':successful,'capacites':before}
        client._tuya_oem_inventory_cache={
            'created':time.monotonic(), 'session_uid':session.uid,
            'devices':devices, 'summary':{
                'inventaire_maisons_accepte':True,'nombre_groupes':len(gids),
                'groupes_lus':successful,'nombre_appareils_tuya':len(devices),
                'refus_inventaire':0}}
        report=audit_ptz_readiness(coordinator,client)
        return {**prefix,'etat':'inventaire_oem_ptz_lu',
                'appareils_oem_examines':len(devices),
                'capacites':report}
    except OEMGatewayError as exc:
        return {**prefix,'etat':'erreur_api_oem','raison':exc.code,
                'capacites':before}
    except Exception:
        return {**prefix,'etat':'erreur_sans_details','capacites':before}
    finally:
        _PTZ_REFRESH_LOCK.release()
