"""One-shot, read-only standalone C9C identity/product/RTC audit.

Strictly bounded, sequential Tuya OEM reads on ONE authenticated session.
All raw values, product IDs, credentials, RTC secrets and identifiers remain
in memory. Public output is fixed enum labels, bounded counts, booleans.
No MQTT, PTZ, wake, streaming, SDK mutation, recording or filesystem writes.
"""
from __future__ import annotations
import re
from typing import Any, Callable

_PRODUCT_ID = re.compile(r"[A-Za-z0-9_-]{5,128}\Z")
_PRODUCT_VERSION = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")
_PATHS = ("data", "result", "device", "deviceInfo", "deviceBean",
          "product", "productInfo", "productBean", "thingModel",
          "modelInfo", "config", "p2pConfig", "webrtcConfig", "rtcConfig",
          "session", "skills", "capabilities")
_CAMERA = frozenset(("sp", "ipc", "camera", "smart_camera"))
_NON_CAMERA = frozenset(("gw", "gateway", "hub", "socket", "plug",
                        "sensor", "light", "switch", "cz", "kg"))


def _objects(raw: Any) -> list[dict]:
    todo=[(raw,0)] if isinstance(raw,dict) else []
    seen=set()
    out=[]
    while todo and len(out)<70:
        node,depth=todo.pop(0)
        if id(node) in seen:
            continue
        seen.add(id(node))
        out.append(node)
        if depth<5:
            for key in _PATHS:
                child=node.get(key)
                if isinstance(child,dict):
                    todo.append((child,depth+1))
    return out


def _explicit_values(raw: Any, keys: tuple[str,...], valid: Callable) -> set[str]:
    return {value for node in _objects(raw) for key in keys
            if isinstance((value:=node.get(key)),str) and valid(value)}


def _product_identity(device: Any, inventory: Any, info: Any=None) -> tuple[str|None,str|None,dict]:
    values_device=_explicit_values(device,("productId",),lambda x: bool(_PRODUCT_ID.fullmatch(x)))
    values_inventory=_explicit_values(inventory,("productId",),lambda x: bool(_PRODUCT_ID.fullmatch(x)))
    products=values_device | values_inventory
    versions=set()
    for raw in (device,inventory,info):
        versions |= _explicit_values(
            raw,("productVersion",),lambda x: bool(_PRODUCT_VERSION.fullmatch(x)))
    pid=next(iter(products)) if len(products)==1 else None
    version=next(iter(versions)) if len(versions)==1 else None
    source=("concordant" if values_device and values_inventory
            and values_device==values_inventory and pid else
            "fiche_tuya" if pid and values_device else
            "inventaire_tuya" if pid else
            "ambigu" if len(products)>1 else "absent")
    return pid,version,{
        "source_product_id":source,
        "product_id_explicite":pid is not None,
        "product_id_ambigu":len(products)>1,
        "version_produit_presente":version is not None,
        "version_produit_ambigue":len(versions)>1,
    }


def _product_report(raw: Any) -> dict:
    nodes=_objects(raw)
    categories={v.strip().lower() for node in nodes
                for key in ("category","categoryCode","productCategory")
                if isinstance((v:=node.get(key)),str) and 0<len(v)<=128}
    if categories & _CAMERA and categories & _NON_CAMERA:
        category="ambigue"
    elif categories & _CAMERA:
        category="camera"
    elif categories & _NON_CAMERA:
        category="non_camera"
    elif categories:
        category="autre"
    else:
        category="absente"
    models=[v.strip() for node in nodes
            for key in ("model","modelName","productModel","deviceModel")
            if isinstance((v:=node.get(key)),str) and 0<len(v)<=128]
    model=("c9c" if any(v.upper()=="C9C" for v in models)
           else "autre" if models else "absent")
    return {
        "categorie":category,
        "modele":model,
        "product_id_champ_present":any(isinstance(node.get("productId"),str)
                                       for node in nodes),
        "capacites_bloc_present":any(isinstance(node.get("capabilities"),(dict,list))
                                    for node in nodes),
        "skills_bloc_present":any(isinstance(node.get("skills"),(dict,list))
                                 for node in nodes),
        "p2p_bloc_present":any(isinstance(node.get("p2pConfig"),dict)
                              for node in nodes),
        "webrtc_bloc_present":any(isinstance(node.get("webrtcConfig"),dict)
                                 for node in nodes),
        "video_indice_present":any(key in node for node in nodes
                                  for key in ("video", "videoAbility",
                                              "supportVideo","supportsVideo",
                                              "videoCapability")),
        "version_produit_presente":bool(_explicit_values(
            raw,("productVersion",),
            lambda x:bool(_PRODUCT_VERSION.fullmatch(x)))),
    }


def _rtc_report(raw:Any, hints:Callable, rtc_schema:Callable)->dict:
    # Ignore private returned msid: the public report is never used to
    # open a WebRTC channel and never emits any JWT, URL, key or token.
    flags,_private_msid=hints(raw,{})
    schema=rtc_schema(raw,{})
    return {
        "moto_id":flags.get("moto_id_present") is True,
        "auth_webrtc":flags.get("auth_webrtc_present") is True,
        "msid":flags.get("msid_explicite_present") is True,
        "msid_ambigu":flags.get("msid_ambigu") is True,
        "webrtc_declare":flags.get("webrtc_declare_oui") is True,
        "aes_kcp":flags.get("ipc_aes_kcp_present") is True,
        "p2p_config":schema.get("p2p_config_presente") is True,
        "session":schema.get("session_presente") is True,
        "ice":schema.get("serveurs_ice_presents") is True,
        "turn":schema.get("serveur_turn_dans_ices") is True,
        "relais_tcp":schema.get("relais_tcp_declare") is True,
    }


def run_full_c9c_audit_b31(read:Callable, *, target:str, inventory:dict,
                            aosu_sn:str|None, aosu_coop:str|None,
                            parse_device:Callable, parse_hints:Callable,
                            parse_rtc:Callable)->dict:
    """Six at most, no retries. The caller handles login/inventory throttling."""
    actions={
        "fiche_tuya":"thing.m.device.get",
        "produit":"thing.m.product.info.get",
        "modele_produit":"thing.m.product.thing.model",
        "ipc_v2":"thing.m.ipc.config.get",
        "rtc_v4":"m.ipc.v4.rtc.config.get",
        "rtc_classique":"thing.m.rtc.config.get",
    }
    etapes={key:"non_tentee" for key in actions}
    result={
        "etat":"partiel",
        "etapes":etapes,
        "identite":{
            "sn":"inconnu","reference":"inconnu","p2p_sdk":"inconnu",
            "product_id_inventaire":isinstance(inventory.get("productId"),str),
            "aosu_sn_present":isinstance(aosu_sn,str) and bool(aosu_sn),
            "aosu_reference_presente":isinstance(aosu_coop,str) and bool(aosu_coop),
            "identite_exacte":False},
        "produit":_product_report({}),
        "reference_produit":{
            "source_product_id":"absent","product_id_explicite":False,
            "product_id_ambigu":False,"version_produit_presente":False,
            "version_produit_ambigue":False},
        "rtc":{k:_rtc_report({},parse_hints,parse_rtc)
               for k in ("ipc_v2","rtc_v4","rtc_classique")},
        "appels_api":0,"echecs":0,
        "aucune_commande":True,"identifiants_retournes":False,
        "secrets_retournes":False,"video_lancee":False,
        "mqtt_publications":0,"commandes_ptz":0,
    }

    def once(label:str, parameters:dict)->Any:
        # No retry on network failure. Keep processing the remaining read-only
        # endpoints if a single method is unsupported, with a six-call cap.
        if result["appels_api"]>=6:
            etapes[label]="limite_six_appels"
            return None
        result["appels_api"]+=1
        try:
            raw,safe=read(actions[label],parameters)
            if (not isinstance(safe,dict)
                    or safe.get("serveur_accepte") is not True
                    or safe.get("rejet_explicite") is True):
                etapes[label]="refusee"
                result["echecs"]+=1
                return None
            etapes[label]="acceptee"
            return raw if isinstance(raw,dict) else {}
        except Exception:
            # Never expose SDK exception text, URL, payload or identifiers.
            etapes[label]="erreur"
            result["echecs"]+=1
            return None

    detail=once("fiche_tuya",{"devId":target})
    details=detail if isinstance(detail,dict) else {}
    parsed=parse_device(details if detail is not None else inventory,
                        expected_device_id=target,
                        aosu_sn=aosu_sn, aosu_coop=aosu_coop)
    identity=result["identite"]
    identity["sn"]=parsed.get("etat_sn_b29","inconnu")
    identity["reference"]=parsed.get("etat_reference_b29","inconnu")
    identity["p2p_sdk"]=parsed.get("p2p_sdk_type_b30","inconnu")
    identity["identite_exacte"]=parsed.get("identite_aosu_tuya_etablie") is True
    pid,version,ref=_product_identity(details,inventory)
    result["reference_produit"]=ref
    if pid is not None:
        product=once("produit",{"productId":pid})
        if product is not None:
            result["produit"]=_product_report(product)
            newpid,newver,ref=_product_identity(details,inventory,product)
            # A product-information response must not silently substitute
            # a different identifier from the selected device.
            if newpid is None and ref["product_id_ambigu"]:
                etapes["modele_produit"]="non_tentee_produit_ambigu"
                version=None
            else:
                version=newver
            result["reference_produit"]["version_produit_presente"]=version is not None
            result["reference_produit"]["version_produit_ambigue"]=ref["version_produit_ambigue"]
        if version is not None:
            model=once("modele_produit",{"productId":pid,"productVersion":version})
            if model is not None:
                model_flags=_product_report(model)
                # The product model's explicit category/model are useful,
                # but presence alone cannot establish device identity.
                if (result["produit"]["categorie"]=="absente"
                        and model_flags["categorie"]!="absente"):
                    result["produit"]["categorie"]=model_flags["categorie"]
                if result["produit"]["modele"]=="absent":
                    result["produit"]["modele"]=model_flags["modele"]
                result["produit"]["capacites_bloc_present"] |= model_flags["capacites_bloc_present"]
                result["produit"]["video_indice_present"] |= model_flags["video_indice_present"]
                result["produit"]["p2p_bloc_present"] |= model_flags["p2p_bloc_present"]
                result["produit"]["webrtc_bloc_present"] |= model_flags["webrtc_bloc_present"]
        elif etapes["modele_produit"]=="non_tentee":
            etapes["modele_produit"]="non_tentee_version_absente"
    else:
        why=("non_tentee_produit_ambigu" if ref["product_id_ambigu"]
             else "non_tentee_product_id_absent")
        etapes["produit"]=why
        etapes["modele_produit"]=why

    for key in ("ipc_v2","rtc_v4","rtc_classique"):
        raw=once(key,{"devId":target})
        if raw is not None:
            try:
                result["rtc"][key]=_rtc_report(raw,parse_hints,parse_rtc)
            except Exception:
                # This is a local parser problem, not a network API refusal.
                etapes[key]="analyse_indisponible"
                result["echecs"]+=1
    required=("fiche_tuya","produit","ipc_v2","rtc_v4","rtc_classique")
    result["etat"]=("termine" if all(etapes[k]=="acceptee" for k in required)
                   else "partiel")
    return result
