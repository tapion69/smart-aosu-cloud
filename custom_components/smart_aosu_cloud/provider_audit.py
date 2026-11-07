"""Privacy-preserving diagnostic of AOSU inventory vs Tuya DeviceBean fields.

This module performs NO HTTP calls. Raw IDs, account credentials and responses
are never copied into its returned structures. AOSU inventory is not Tuya's
live DeviceBean: reported provider values are only observations, not proof of
which camera implementation runs on the Android device.
"""
from __future__ import annotations

_ALLOWED_MODELS = frozenset({'C5L', 'C9C3CA11', 'H1L'})
_ALLOWED_PROVIDERS = {1: 'TUTK', 2: 'THING', 3: 'THING_STATION',
                      4: 'FISHEYE', 9: 'VIRTUAL'}
_MAX_DEVICES = 20
_MAX_NODES = 80


def _bounded_number(value):
    if type(value) is int and 0 <= value <= 9:
        return value
    if isinstance(value, str) and len(value) == 1 and value.isascii() and value.isdecimal():
        return int(value)
    return None


def _valid_identifier(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 256


def _observe_one(record):
    """Return only whitelisted enums, booleans and ID *comparisons*."""
    skills = record.get('skills')
    if not isinstance(skills, dict):
        skills = {}
    value = record.get('sdkProvider')
    sdk = _bounded_number(value)
    if sdk not in _ALLOWED_PROVIDERS:
        sdk = None
    a, b = record.get('devId'), record.get('communicationId')
    compared = _valid_identifier(a) and _valid_identifier(b)
    equal = a == b if compared else None
    p2p_root = _bounded_number(record.get('p2pType'))
    p2p_skills = _bounded_number(skills.get('p2pType'))
    conflict = p2p_root is not None and p2p_skills is not None and p2p_root != p2p_skills
    p2p = None if conflict else p2p_skills if p2p_skills is not None else p2p_root
    virtual = record.get('isVirtual') if type(record.get('isVirtual')) is bool else None
    result = {
        'sdk_provider_declare': sdk if sdk is not None else 'absent',
        'sdk_provider_declare_nom': _ALLOWED_PROVIDERS.get(sdk, 'INDETERMINE'),
        'p2p_type_declare': p2p if p2p is not None else 'absent',
        'p2p_type_conflit_sources': conflict,
        'is_virtual_disponible': virtual is not None,
        'is_virtual': virtual if virtual is not None else 'inconnu',
        'comparaison_identifiants_disponible': bool(compared),
        'dev_et_communication_identiques': equal if compared else 'inconnu',
        'reference_type': 'REPONSE_AOSU_PAS_DEVICEBEAN_TUYA',
        'moteur_runtime_confirme': False,
    }
    if sdk is not None:
        result['conclusion'] = 'PROVIDER_DECLARE_NON_CONFIRME_RUNTIME'
    elif virtual is True:
        result['conclusion'] = 'VIRTUAL_CONDITIONNEL_DEVICEBEAN'
    elif equal is False:
        result['conclusion'] = 'STATION_CONDITIONNEL_DEVICEBEAN'
    elif p2p is not None and not conflict:
        result['conclusion'] = 'P2PTYPE_CONDITIONNEL_DEVICEBEAN'
    else:
        result['conclusion'] = 'CHAMPS_TUYA_ABSENTS_OU_INSUFFISANTS'
    return result


def summarize_getlist_provider(records):
    """Called only on already received /v1/dev/getList records during polling."""
    if not isinstance(records, list):
        return {'resultat': 'inventaire_indisponible', 'appels_http_supplementaires': 0,
                'moteur_runtime_confirme': False, 'appareils': []}
    summary=[]
    for index, item in enumerate(records[:_MAX_DEVICES], 1):
        if not isinstance(item, dict):
            continue
        model = item.get('model')
        model = model if isinstance(model,str) and model in _ALLOWED_MODELS else 'autre_modele'
        if model == 'H1L':
            continue
        summary.append({'numero_temporaire':index, 'modele':model, **_observe_one(item)})
    return {'resultat': 'ANALYSE_CACHEE_AOSU', 'source': '/v1/dev/getList',
            'appels_http_supplementaires': 0, 'commandes_camera': 0,
            'moteur_runtime_confirme': False, 'appareils': summary,
            'note': 'Les champs AOSU ne prouvent pas le DeviceBean utilise dans Android.'}


def summarize_detail_provider(payload):
    """Inspect the response of the existing manual /v1/dev/getInfoBySn call.

    Never infer a provider from model or baseSn. Return a safe summary even if
    the server returns an unexpected or excessively nested object.
    """
    empty = {'resultat': 'CHAMPS_TUYA_ABSENTS_OU_INSUFFISANTS',
             'moteur_runtime_confirme': False, 'objets_examimes': 0,
             'appels_http_supplementaires': 0}
    if not isinstance(payload,dict) or payload.get('errno') != 0:
        return {**empty, 'resultat': 'REPONSE_NON_EXPLOITABLE'}
    data=payload.get('data')
    stack=[(data,0)]
    examined=0
    seen=[]
    while stack and examined < _MAX_NODES:
        obj,depth=stack.pop()
        if isinstance(obj, dict):
            examined+=1
            summary=_observe_one(obj)
            if summary['conclusion'] != 'CHAMPS_TUYA_ABSENTS_OU_INSUFFISANTS':
                seen.append(summary)
            if depth < 5:
                stack.extend((v,depth+1) for v in list(obj.values())[:30] if isinstance(v,(dict,list)))
        elif isinstance(obj, list) and depth < 5:
            stack.extend((v,depth+1) for v in obj[:20] if isinstance(v,(dict,list)))
    if not seen:
        return {**empty, 'objets_examines':examined}
    # Distinct matching candidates may describe different nested structures;
    # do not arbitrarily select one or leak their content.
    types={str((x['sdk_provider_declare'],x['p2p_type_declare'],x['conclusion'])) for x in seen}
    return {'resultat': 'CANDIDAT_PRESENT' if len(types)==1 else 'CANDIDATS_MULTIPLES_A_VERIFIER',
            'nombre_candidats':len(seen), 'objets_examines':examined,
            'moteur_runtime_confirme':False, 'appels_http_supplementaires':0,
            'candidat':seen[0] if len(types)==1 else None}
