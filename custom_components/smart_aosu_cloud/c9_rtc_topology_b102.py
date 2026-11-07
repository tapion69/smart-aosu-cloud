"""B102: RAM-only topology/credential-provenance report for a C9 RTC candidate.

Only fixed-key booleans and bounded public protocol codes leave the process.
Station association through OEM name is only a clue, never an authentication proof.
No session or secret is saved, exported, or used for media signaling.
"""
from __future__ import annotations
from typing import Any
from .c9_h1l_identity_structure_b99 import _match_name

_KEYS = (
    'devId','deviceId','p2pId','p2pType','p2pSpecifiedType',
    'parentId','nodeId','gatewayId','communicationId','baseDevId',
    'localKey','password','sessionId','channel','channelId','subDeviceId',
    'nvrDevId','gwId','subDevId'
)
_PARENT_KEYS = ('parentId','gatewayId','baseDevId','communicationId','nvrDevId','gwId')
_NODE_KEYS = ('nodeId','subDevId','subDeviceId','channelId','channel')


def _nodes(obj: Any) -> list[dict]:
    pending=[(obj, 0)]
    out=[]
    while pending and len(out)<128:
        current,depth=pending.pop(0)
        if isinstance(current,dict):
            out.append(current)
            if depth<6:
                for child in list(current.values())[:36]:
                    if isinstance(child,(list,dict)):
                        pending.append((child,depth+1))
        elif isinstance(current,list) and depth<6:
            for child in current[:24]:
                if isinstance(child,(dict,list)):
                    pending.append((child,depth+1))
    return out


def _valid_string(val: Any) -> bool:
    return isinstance(val,str) and 0<len(val)<=8192


def _has(nodes:list[dict], key:str) -> bool:
    return any(_valid_string(n.get(key)) for n in nodes)


def _code(nodes:list[dict], key:str) -> int | None:
    for node in nodes:
        val=node.get(key)
        if type(val) is int and 0 <= val <= 99: return val
        if isinstance(val,str) and len(val)<3 and val.isdecimal():
            number=int(val)
            if number<=99: return number
    return None


def _refs(nodes:list[dict], fields:tuple[str,...]) -> list[str]:
    return [n[field] for n in nodes for field in fields if _valid_string(n.get(field))]


def inspect_rtc_topology_b102(rtc:Any, candidate_did:str,
                              candidate:dict, aosu_data:Any, tuya_devices:Any) -> dict:
    report={
        'diagnostic':'aosu_topologie_rtc_c9_b102',
        'lecture_seule':True, 'appel_reseau_supplementaire':0,
        'commande_camera':0,'offre_mqtt_envoyee':False,
        'video_demarre':False,'identifiants_retournes':False,
        'valeurs_cles_retournees':False,
        'identite_par_nom_non_prouvee':True,
        'selection_video_autorisee':False,
        'utilisation_cle_station_autorisee':False,
    }
    devices=tuya_devices if isinstance(tuya_devices,dict) else {}
    item=devices.get(candidate_did, {})
    item=item if isinstance(item,dict) else {}
    nodes=_nodes(rtc)
    inventory_nodes=_nodes(item)
    report['strategie_p2p']={
        'code_type_inventaire':_code(inventory_nodes, 'p2pType'),
        'code_type_rtc':_code(nodes,'p2pType'),
        'code_strategie_rtc':_code(nodes,'p2pSpecifiedType'),
        'p2p_id_rtc_present':_has(nodes,'p2pId'),
        'dev_id_rtc_present':_has(nodes,'devId'),
        'dev_id_rtc_correspond_candidat':candidate_did in _refs(nodes,('devId',)) if candidate_did else False,
        'id_parent_present':bool(_refs(nodes,_PARENT_KEYS)),
        'id_noeud_ou_canal_present':bool(_refs(nodes,_NODE_KEYS)),
        'champs_parent_present':{key:_has(nodes,key) for key in _PARENT_KEYS},
        'champs_noeud_present':{key:_has(nodes,key) for key in _NODE_KEYS},
    }
    station_names=[v.get('name') for v in aosu_data.values()
                   if isinstance(v,dict) and v.get('model')=='H1L'] if isinstance(aosu_data,dict) else []
    station_candidates=[did for did,dev in devices.items()
                        if isinstance(did,str) and isinstance(dev,dict)
                        and len(station_names)==1 and _match_name(dev,station_names[0])]
    station_did=station_candidates[0] if len(station_candidates)==1 else None
    station_item=devices.get(station_did, {}) if station_did is not None else {}
    station_item=station_item if isinstance(station_item,dict) else {}
    report['station_h1l']={
        'correspondance_station_par_nom_unique':station_did is not None,
        'parent_rtc_egal_candidat_station_par_nom': bool(
            station_did and station_did in _refs(nodes,_PARENT_KEYS)),
        'cle_locale_station_en_cache_presente':_has(_nodes(station_item),'localKey'),
        'relation_station_dans_aosu_confirmee':candidate.get('relation_base_aosu_confirmee') is True,
        'correspondance_identifiants_exacts_confirmee':False,
    }
    report['cles']={
        'cle_locale_camera_en_cache_presente':_has(inventory_nodes,'localKey'),
        'cle_locale_rtc_presente':_has(nodes,'localKey'),
        'mot_de_passe_rtc_present':_has(nodes,'password'),
        'cle_locale_validee_pour_signaux_camera':_has(inventory_nodes,'localKey'),
        'cle_station_non_substituee_a_la_cle_camera':True,
    }
    report['etat']= ('parent_et_noeud_a_etudier' if report['strategie_p2p']['id_parent_present']
                     and report['strategie_p2p']['id_noeud_ou_canal_present'] else
                     'strategie_p2p_detectee_cle_camera_absente' if
                     not report['cles']['cle_locale_camera_en_cache_presente'] else
                     'strategie_p2p_detectee_cle_camera_presente')
    return report
