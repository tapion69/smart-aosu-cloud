"""Read-only SDK SchemaBean (code, id) evidence in Tuya device detail.

APK AOSU 5.10.12:
* classes4.dex #32703 GwDevResp.DevResp.schema -> ProductBean.SchemaInfo
  -> getSchemaMap() -> DeviceBean.setSchemaMap()
* classes6.dex #4657 DpHelper.getDPIdByCode() iterates schemaMap.values(),
  matches SchemaBean.code and returns SchemaBean.id.

Do not conflate product Thing Model abilityId with SchemaBean.id, and do not
conflate live dps values with schema definitions. Never expose raw response.
"""
from __future__ import annotations
import json
from typing import Any

CODES=('ptz_control','ptz_stop')
SCHEMA_FIELDS=('schemaMap','schema','schemaInfo')
CONTAINERS=('result','data','device','deviceInfo','productBean','productInfo',
            'devices','devResp','gwResp','gateway','product','model','thingModel',
            'services','properties','functions','datapoints','dpCodes')
# b68: the device-detail response has vendor-specific containers. The b67
# allowlist skipped all 16 nested nodes (b38 traversed 17); traverse bounded
# JSON objects/lists irrespective of key. Never parse arbitrary strings or
# expose the device response. Exact SDK schema names alone establish proof.
BLOCKED=('password','localKey','token','accessToken','refreshToken','privateKey',
         'sessionKey','secret','credentials','credential')
MAX_DEPTH=11
MAX_NODES=1400


def _json_safe(value:Any)->Any:
    if not isinstance(value,str) or not 1<=len(value)<=131072:
        return value
    if not value.lstrip().startswith(('[','{')):
        return value
    try:
        parsed=json.loads(value)
    except (ValueError,TypeError,RecursionError):
        return value
    return parsed if isinstance(parsed,(list,dict)) else value


def _dp_int(value:Any)->int|None:
    if type(value) is int and 1<=value<=999:return value
    if isinstance(value,str) and value.isascii() and value.isdigit() and len(value)<=3:
        num=int(value)
        return num if 1<=num<=999 else None
    return None


def inspect_sdk_schema_map(response:Any)->dict:
    """Require a structural SchemaInfo/SchemaMap proof for confirmed IDs.

    Nested JSON strings are decoded exclusively under schema-like field names.
    The report exports only fixed labels and numeric DP IDs, never raw text,
    credentials, device identifiers or enumerated properties.
    """
    ids={code:set() for code in CODES}
    candidates={code:set() for code in CODES}
    sources={code:set() for code in CODES}
    ability={code:set() for code in CODES}
    schema_seen=set()
    nodes=0
    nested_generic=0
    nested_known=0
    stack=[(response,0,'root',False,None)]
    visited=set()
    while stack and nodes<MAX_NODES:
        node,depth,origin,is_schema,keyhint=stack.pop()
        if depth>MAX_DEPTH:continue
        if isinstance(node,str) and is_schema:
            node=_json_safe(node)
        if not isinstance(node,(dict,list)) or id(node) in visited:continue
        visited.add(id(node));nodes+=1
        if isinstance(node,list):
            for child in node[:150]:
                if isinstance(child,(dict,list)) or (is_schema and isinstance(child,str)):
                    stack.append((child,depth+1,origin,is_schema,None))
            continue
        if is_schema:
            schema_seen.add(origin)
        code=None
        for name in ('code','dpCode'):
            if isinstance(node.get(name),str) and node[name] in CODES:
                code=node[name];break
        if code is None and keyhint in CODES:code=keyhint
        if code is not None:
            numeric_id=None
            for field in ('id','dpId','dp_id'):
                if field in node:
                    numeric_id=_dp_int(node[field]);break
            if numeric_id is None and keyhint is not None:
                numeric_id=_dp_int(keyhint)
            if numeric_id is not None:
                if is_schema and origin in SCHEMA_FIELDS:
                    ids[code].add(numeric_id);sources[code].add(origin)
                else:
                    candidates[code].add(numeric_id)
            if 'abilityId' in node:
                aid=_dp_int(node['abilityId'])
                if aid is not None:ability[code].add(aid)
        # SchemaMap keyed by DP numeric or by code.
        for key,child in list(node.items())[:160]:
            if key in SCHEMA_FIELDS:
                schema_seen.add(key)
                stack.append((child,depth+1,key,True,None))
            elif is_schema:
                if isinstance(child,(dict,list,str)):
                    stack.append((child,depth+1,origin,True,str(key)))
            elif key not in BLOCKED and isinstance(child,(dict,list)):
                # Preserve provenance: a DP candidate under datapoints does not
                # become a certified SchemaBean unless a schema field appears.
                if key in CONTAINERS:nested_known+=1
                else:nested_generic+=1
                stack.append((child,depth+1,origin,False,None))
            elif key in ('model','thingModel') and isinstance(child,str):
                stack.append((_json_safe(child),depth+1,'model',False,None))
    result={}
    for code in CODES:
        confirmed=sorted(ids[code]);other=sorted(candidates[code]);aid=sorted(ability[code])
        result[code]={
            'id_schema_sdk_confirme':confirmed[0] if len(confirmed)==1 else None,
            'ids_schema_contradictoires':len(confirmed)>1,
            'id_hors_schema_observe':other[0] if len(other)==1 else None,
            'ability_id_candidat':aid[0] if len(aid)==1 else None,
            'sources_schema':[name for name in SCHEMA_FIELDS if name in sources[code]],
        }
    confirmed=all(result[c]['id_schema_sdk_confirme'] is not None for c in CODES)
    conflicting=any(result[c]['ids_schema_contradictoires'] for c in CODES)
    if conflicting:verdict='ids_schema_contradictoires'
    elif confirmed and (result['ptz_control']['id_schema_sdk_confirme'] != result['ptz_stop']['id_schema_sdk_confirme']):
        verdict='deux_ids_schema_sdk_confirmes'
    elif confirmed:verdict='conflit_ids_identiques'
    elif schema_seen:verdict='schema_trouve_mapping_incomplet'
    else:verdict='schema_sdk_absent_de_la_fiche'
    return {
        'diagnostic':'aosu_schema_map_b68',
        'parcours_b68':{'objets_imbriques_connus':nested_known,
                        'objets_imbriques_fournisseur':nested_generic,
                        'profondeur_maximum':MAX_DEPTH,
                        'limite_noeuds_atteinte':nodes>=MAX_NODES},
        'source_sdk':'DeviceBean.schemaMap_vers_SchemaBean.getId',
        'lecture_seule':True,'noeuds_examines':nodes,
        'schema_trouve':bool(schema_seen),
        'sources_schema':[name for name in SCHEMA_FIELDS if name in schema_seen],
        'datapoints':result,'verdict':verdict,
        'mouvement_autorise':False,'arret_physique_confirme':False,
        'commandes_ptz_envoyees':0,'connexions_mqtt':0,
        'secrets_retournes':False,'identifiants_appareil_retournes':False,
        'reponse_brute_retournee':False,
    }
