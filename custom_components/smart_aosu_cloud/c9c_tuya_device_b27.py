"""Read-only Tuya device detail identity comparison for ONE standalone C9C.

Only exact equality of known identifier fields, booleans and fixed status flags
are returned. The OEM response, device identifiers and secrets stay in memory.
A model match is NEVER treated as a proven AOSU-to-Tuya identity.
"""
from __future__ import annotations
from typing import Any

_CONTAINERS=("data","result","device","deviceBean","deviceInfo",
             "product","productBean","productInfo","skills","capabilities")
_SN=("sn","deviceSn","serialNumber","serialNo")
_COOP=("coopUUID","cpDeviceId","deviceUuid","devUuid","uuid","cpUuid")
_MODELS=("model","modelName","productModel","deviceModel","productType")
_CATEGORIES=frozenset(("sp","ipc","camera","smart_camera"))
_NONVIDEO=frozenset(("gw","gateway","hub","switch","socket","sensor","light",
                    "plug","cz","kg","dj","cl","pir","wsdcg"))


def summarize_tuya_device_b27(payload:Any, *, expected_device_id:str,
                              aosu_sn:str, aosu_coop:str|None)->dict:
    """Bounded schema read. No guessed IDs, hashes, network activity or writes."""
    todo=[(payload,0)] if isinstance(payload,dict) else []
    seen=set()
    nodes=[]
    while todo and len(nodes)<64:
        node,depth=todo.pop(0)
        if id(node) in seen:
            continue
        seen.add(id(node))
        nodes.append(node)
        if depth<4:
            for key in _CONTAINERS:
                val=node.get(key)
                if isinstance(val,dict):
                    todo.append((val,depth+1))
    valid=lambda v:isinstance(v,str) and 1<=len(v)<=256
    sn_confirmed=bool(valid(aosu_sn)) and any(
        obj.get(key)==aosu_sn for obj in nodes for key in _SN)
    coop_confirmed=bool(valid(aosu_coop)) and any(
        obj.get(key)==aosu_coop for obj in nodes for key in _COOP)
    sn_fields_present=any(valid(obj.get(key)) for obj in nodes for key in _SN)
    coop_fields_present=any(valid(obj.get(key)) for obj in nodes for key in _COOP)
    model_present=any(valid(obj.get(key)) for obj in nodes for key in _MODELS)
    model_c9c=any(isinstance(obj.get(key),str) and
                  obj[key].strip().upper()=="C9C"
                  for obj in nodes for key in _MODELS)
    categories={obj[key].strip().lower() for obj in nodes
                for key in ("category","categoryCode")
                if valid(obj.get(key))}
    details_id=any(obj.get(key)==expected_device_id
        for obj in nodes for key in ("devId","deviceId","id")
        if valid(expected_device_id))
    product=any(valid(obj.get("productId")) for obj in nodes)
    product_root_present=valid(payload.get("productId")) if isinstance(payload,dict) else False
    product_in_productbean=any(
        isinstance(obj.get("productBean"),dict) and
        valid(obj["productBean"].get("productId")) for obj in nodes)
    productbean_present=any(isinstance(obj.get("productBean"),dict) for obj in nodes)
    uuid_present=any(valid(obj.get(key)) for obj in nodes
                     for key in ("uuid","devUuid","deviceUuid","coopUUID"))
    # Keep absence, non-equality and proof of exact equality distinct.
    # A distinct serial/reference might be in another namespace, so no
    # "wrong camera" claim can be inferred from a non-equality alone.
    sn_state=("aosu_sn_indisponible" if not valid(aosu_sn)
              else "egal" if sn_confirmed
              else "present_sans_egalite" if sn_fields_present
              else "absent_dans_tuya")
    ref_state=("aosu_reference_indisponible" if not valid(aosu_coop)
               else "egale" if coop_confirmed
               else "presente_sans_egalite" if coop_fields_present
               else "absente_dans_tuya")
    model_state=("c9c_exact" if model_c9c
                 else "present_autre_ou_inconnu" if model_present
                 else "absent")
    category_state=("camera_reconnue" if categories&_CATEGORIES
                    else "non_video_reconnue" if categories&_NONVIDEO
                    else "autre_non_identifiee" if categories
                    else "absente")
    skills_present=any(isinstance(obj.get("skills"),dict) for obj in nodes)
    capabilities_present=any(isinstance(obj.get("capabilities"),(dict,list))
                             for obj in nodes)
    p2p_type_present=any(obj.get("p2pType") is not None
                         for obj in nodes)
    p2p_config_present=any(isinstance(obj.get("p2pConfig"),dict) for obj in nodes)
    p2p_flag_present=any(type(obj.get(key)) is bool
        for obj in nodes for key in ("supportP2p","supportsP2P","isP2pEnabled"))
    if sn_confirmed or coop_confirmed:
        status="identite_exacte_dans_fiche_tuya"
    elif model_c9c:
        status="modele_c9c_seulement_non_confirmant"
    elif sn_fields_present or coop_fields_present or model_present:
        status="champs_presents_sans_correspondance"
    else:
        status="aucun_identifiant_concluant"
    return {
        "etat_correspondance":status,
        "fiche_structure_presente":bool(nodes),
        "numero_serie_present":sn_fields_present,
        "numero_serie_exact":sn_confirmed,
        "etat_sn_b29":sn_state,
        "etat_reference_b29":ref_state,
        "etat_modele_b29":model_state,
        "etat_categorie_b29":category_state,
        "references_presentes":coop_fields_present,
        "reference_coop_exacte":coop_confirmed,
        "modele_present":model_present,
        "modele_c9c_exact":model_c9c,
        "categorie_video_reconnue":bool(categories&_CATEGORIES),
        "categorie_non_video_reconnue":bool(categories&_NONVIDEO),
        "categorie_absente":not bool(categories),
        "id_tuya_de_la_reponse_correspond_a_la_requete":details_id,
        "product_id_present":product,
        "product_id_racine_present":product_root_present,
        "product_bean_present":productbean_present,
        "product_id_dans_product_bean":product_in_productbean,
        "skills_bloc_present":skills_present,
        "capacites_bloc_present":capabilities_present,
        "p2p_type_champ_present":p2p_type_present,
        "p2p_config_bloc_present":p2p_config_present,
        "p2p_support_bool_present":p2p_flag_present,
        "uuid_present":uuid_present,
        "identite_aosu_tuya_etablie":bool(sn_confirmed or coop_confirmed),
        "lecture_seule":True,"requetes_mqtt":0,
        "offres_envoyees":0,"commandes_camera":0,
        "commandes_ptz":0,"video_lancee":False,
        "identifiants_retournes":False,"secrets_retournes":False,
    }
