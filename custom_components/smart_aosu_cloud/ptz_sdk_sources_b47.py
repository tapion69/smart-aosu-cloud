"""b47 — Compare SDK prerequisites in the OEM inventory and device detail.

All output is a bounded, allowlisted structural report. Never return IDs,
credentials, localKey, communicationNode, schema contents or SDK payloads.
No motor commands, RTC, MQTT, publication or unrequested network activity.
"""
from __future__ import annotations

import json
from typing import Any

_SUPPORTED_PV = frozenset(('1.1', '2.1', '2.2', '2.3'))
_CODES = (('ptz_control', 119, 'ptz_control_119'), ('ptz_stop', 116, 'ptz_stop_116'))
_VERSION_KEYS = frozenset(('pv', 'protocolVersion', 'protocol_version'))
_KEY_KEYS = frozenset(('localKey',))
_NODE_KEYS = frozenset(('communicationNode',))
_SCHEMA_KEYS = frozenset(('schemaMap',))
_ALLOWED_SECTIONS = ('skills','productBean','deviceBean','communication','datapoints',
                     'functions','status','schemaMap','deviceInfo','result')


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str) and len(value) <= 8192 and value.lstrip().startswith(('{','[')):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, (dict, list)):
                return parsed
        except (ValueError, TypeError):
            pass
    return value


def _walk(root: Any):
    """Bounded discovery over nested structures, including compact JSON strings."""
    pending = [(root,0)]
    visited = set()
    count = 0
    while pending and count < 350:
        value, depth = pending.pop()
        value = _maybe_json(value)
        if depth > 8 or not isinstance(value,(dict,list)) or id(value) in visited:
            continue
        visited.add(id(value))
        count += 1
        yield value
        if isinstance(value, dict):
            children = list(value.values())[:70]
        else:
            children = value[:70]
        for child in reversed(children):
            if isinstance(child, (dict, list)) or (isinstance(child,str) and child.lstrip().startswith(('{','['))):
                pending.append((child,depth+1))


def _contains_value(value: Any) -> bool:
    return isinstance(value,str) and len(value)>0 or isinstance(value,(dict,list)) and bool(value)


def inspect_sdk_properties(payload: Any) -> dict:
    """Return only static field labels and presence flags, never sensitive values."""
    result = {
        'pv': 'non_publiee', 'pv_etat': 'champ_absent',
        'local_key_presente': False, 'communication_node_present': False,
        'schema_map_present': False,
        'dp_numeriques': {'ptz_control_119':False,'ptz_stop_116':False},
        'sections_reconnues': [], 'noeuds_examines': 0,
        'secrets_retournes': False, 'identifiants_retournes': False,
    }
    pv_values = set()
    sections = set()
    for node in _walk(payload):
        result['noeuds_examines'] += 1
        if not isinstance(node,dict):
            continue
        sections.update(k for k in _ALLOWED_SECTIONS if k in node)
        for field in _VERSION_KEYS:
            raw=node.get(field)
            if isinstance(raw,(int,float,str)) and not isinstance(raw,bool):
                val=str(raw).strip()
                if len(val) <= 5 and len(val.split('.')) == 2 and all(x.isdigit() and len(x)<=2 for x in val.split('.')):
                    pv_values.add(val)
        for field in _KEY_KEYS:
            if field in node and _contains_value(node[field]):result['local_key_presente']=True
        for field in _NODE_KEYS:
            if field in node and _contains_value(node[field]):result['communication_node_present']=True
        for field in _SCHEMA_KEYS:
            if field in node and isinstance(_maybe_json(node[field]),(dict,list)) and bool(_maybe_json(node[field])):
                result['schema_map_present']=True
        for code, expected, label in _CODES:
            if node.get('code',node.get('dpCode')) == code:
                dp = node.get('id',node.get('dpId'))
                if type(dp) is int and dp==expected or isinstance(dp,str) and dp==str(expected):
                    result['dp_numeriques'][label]=True
            entry = node.get(code)
            entry = _maybe_json(entry)
            if isinstance(entry,dict):
                dp=entry.get('id',entry.get('dpId'))
                if type(dp) is int and dp==expected or isinstance(dp,str) and dp==str(expected):
                    result['dp_numeriques'][label]=True
            # Tuya's numeric schemaMap can have keys "116" / "119" and a code inside.
            numeric_entry=_maybe_json(node.get(str(expected),node.get(expected)))
            if isinstance(numeric_entry,dict) and numeric_entry.get('code',numeric_entry.get('dpCode'))==code:
                result['dp_numeriques'][label]=True
    result['sections_reconnues']=[k for k in _ALLOWED_SECTIONS if k in sections]
    if len(pv_values)==1:
        version=next(iter(pv_values))
        result['pv']=version
        result['pv_etat']='codec_apk_identifie' if version in _SUPPORTED_PV else 'version_hors_codecs_identifies'
    elif len(pv_values)>1:
        result['pv_etat']='versions_multiples_non_attribuables'
    return result


def audit_sources_ptz_c5l(coordinator: Any, *, password_confirmed:bool=False,
                           camera_confirmed:bool=False) -> dict:
    """One opted-in OEM refresh plus one existing read-only device.get.

    If an OEM cache exists, this never refreshes it needlessly; if the device
    detail call is throttled, returns an explicit partial result, not guesses.
    """
    from .ptz_readiness import audit_ptz_readiness,refresh_ptz_inventory
    from .ptz_device_detail_b39 import select_c5l_oem,audit_ptz_device_detail

    report = {'diagnostic':'aosu_sdk_sources_ptz_b47',
        'lecture_seule':True, 'appels_reseau':0,
        'commandes_ptz_envoyees':0, 'commandes_arret_envoyees':0,
        'mouvement_autorise':False, 'arret_physique_valide':False,
        'connexion_mqtt_nouvelle':False, 'video_modifiee':False,
        'secrets_retournes':False, 'identifiants_retournes':False,
        'sources':{'inventaire_oem':'non_lu','fiche_detaillee':'non_lue'},
        'publication_ptz_disponible':False}
    if password_confirmed is not True or camera_confirmed is not True:
        return {**report,'etat':'deux_confirmations_requises'}
    controller = getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**report,'etat':'direct_en_cours_reessayer_apres_arret'}
    before = audit_ptz_readiness(coordinator,coordinator.client)
    if before.get('cache_oem_recent') is not True:
        refresh=refresh_ptz_inventory(coordinator,password_confirmed=True)
        report['appels_reseau'] += int(refresh.get('appels_reseau',0))
        if refresh.get('etat') not in ('inventaire_oem_ptz_lu','cache_recent_reutilise'):
            return {**report,'etat':'actualisation_oem_impossible',
                    'etat_actualisation':refresh.get('etat','erreur_sans_details')}
        report['cache_oem']='actualise'
    else:
        report['cache_oem']='reutilise'
    selected,why=select_c5l_oem(coordinator)
    if selected is None:
        return {**report,'etat':why}
    _id,row,method=selected
    report['selection_oem']=method
    report['sources']['inventaire_oem']=inspect_sdk_properties(row)
    detail=audit_ptz_device_detail(coordinator,password_confirmed=True,
            camera_confirmed=True,include_sdk_structure=True)
    report['appels_reseau'] += int(detail.get('appels_reseau',0))
    if detail.get('etat')!='fiche_detaillee_lue':
        report['sources']['fiche_detaillee']='non_lue'
        report['etat']='lecture_detail_impossible'
        report['etat_detail']=detail.get('etat','erreur_sans_details')
        return report
    report['sources']['fiche_detaillee']=detail['sdk_sources_b47']
    found=any(result.get('pv')!='non_publiee' or
              result.get('local_key_presente') or result.get('communication_node_present') or
              result.get('schema_map_present') or any(result.get('dp_numeriques',{}).values())
              for result in report['sources'].values() if isinstance(result,dict))
    report['etat']='indices_sdk_retrouves' if found else 'donnees_sdk_absentes_des_deux_sources'
    report['prochaine_etape']=('verifier_correspondance_et_transport_avec_sdk' if found
                               else 'ne_pas_repeter_oem_analyser_session_sdk_ou_transport_lan')
    return report
