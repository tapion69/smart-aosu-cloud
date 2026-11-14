"""One explicitly authorized, bounded native-style Thing-4 HTTP offer probe.

This is NOT the camera stream and does not publish MQTT, send PTZ, wake the
camera or establish proof of C9C identity. The operation MAY create remote
Tuya RTC session state, so it must be manually requested once, never on a
normal Home Assistant refresh. Request values exist only in RAM.
"""
from __future__ import annotations

import json
from typing import Any

_HTTP_ACTION = "thing.m.rtc.session.offer"
_HTTP_VERSION = "1.0"
_NON_VIDEO = frozenset(("gw","gateway","hub","switch","socket","sensor",
                         "light","zigbee","plug","cz","kg","dj","cl","pir","wsdcg"))


def _id(value: Any) -> bool:
    return (isinstance(value,str) and 5 <= len(value) <= 128
            and value == value.strip() and value.isprintable()
            and not any(ch.isspace() or ch in "#+\0" for ch in value))


def manual_target_gate(devices: object, *, aosu_sn: object,
                       typed_target: object, typed_selection: str,
                       allow_one_unproven: bool) -> tuple[str | None,str]:
    """Never infer an exact AOSU-Tuya link from one device alone.

    Weak selection is permitted *only* for one manual HTTP negotiation probe,
    with its own unambiguous owner confirmation, never for video, PTZ or wake.
    """
    if not _id(aosu_sn):
        return None,"aosu_sn_non_confirme"
    if not isinstance(devices,dict) or not devices:
        return None,"inventaire_tuya_absent"
    if typed_selection.startswith("identite_exacte_") and isinstance(typed_target,str):
        if typed_target in devices and _id(typed_target):
            return typed_target,"identite_typée"
        return None,"cible_typée_invalide"
    if not allow_one_unproven or len(devices) != 1:
        return None,"liaison_aosu_tuya_non_prouvee"
    target, row = next(iter(devices.items()))
    if not _id(target) or not isinstance(row,dict):
        return None,"appareil_unique_invalide"
    if row.get("devId") not in (None,target) or row.get("deviceId") not in (None,target):
        return None,"identifiant_tuya_contradictoire"
    categories=set()
    for obj in (row, row.get("deviceInfo"), row.get("productBean")):
        if isinstance(obj,dict) and isinstance(obj.get("category"),str):
            categories.add(obj["category"].strip().lower())
    if categories & _NON_VIDEO:
        return None,"appareil_unique_non_camera"
    return target,"candidat_unique_autorise_manuellement"


def validate_type4_rtc(rtc: object, target: str) -> bool:
    """Require the RTC response itself to bind a Thing-4 CameraInfoBean.id."""
    if not _id(target) or not isinstance(rtc,dict):
        return False
    nodes=[(rtc,0)]
    seen=set()
    found=False
    while nodes and len(seen)<80:
        node,depth=nodes.pop(0)
        if isinstance(node,list):
            if depth<5:
                nodes.extend((v,depth+1) for v in node[:20] if isinstance(v,(dict,list)))
            continue
        if not isinstance(node,dict) or id(node) in seen:
            continue
        seen.add(id(node))
        ty=node.get("p2pSpecifiedType")
        if str(ty)=="4" and type(ty) in (str,int):
            ids={node.get(key) for key in ("id","devId","deviceId")
                 if isinstance(node.get(key),str)}
            if ids != {target}:
                return False
            found=True
        if depth<5:
            for key in ("data","result","cameraInfo","cameraInfoBean","device",
                        "info","ipc","camera","p2pConfig"):
                child=node.get(key)
                if isinstance(child,(dict,list)):
                    nodes.append((child,depth+1))
    return found


def native_http_form(offer: object, *, target: str) -> dict[str,object]:
    """Convert the existing validated MQTT offer to the native HTTP envelope.

    Native cJSON creates header+msg, stringifies that object and sends a
    separate Tuya api/devId/msg request. Java parses the inner JSON string
    into the POST data. The API name is split from suffix '_1.0'.\n    No invented UDP relay fields.
    """
    if not _id(target) or not isinstance(offer,dict):
        raise ValueError("c9c_http_offer_invalid")
    h=offer.get("header")
    body=offer.get("msg")
    if not isinstance(h,dict) or not isinstance(body,dict):
        raise ValueError("c9c_http_offer_invalid")
    if (h.get("type")!="offer" or h.get("to")!=target or
        not _id(h.get("from")) or
        not isinstance(h.get("sessionid"),str) or
        not 1 <= len(h["sessionid"]) <= 256 or
        h.get("p2p_skill") != 1635 or h.get("security_level") != 3 or
        not isinstance(h.get("trace_id"),str) or
        not 1 <= len(h["trace_id"]) <= 512):
        raise ValueError("c9c_http_offer_invalid")
    if not isinstance(body.get("sdp"),str) or "AES/KCP" not in body["sdp"] or len(body["sdp"])>10000:
        raise ValueError("c9c_http_sdp_invalid")
    for key in ("token","tcp_token","log"):
        if key not in body:
            raise ValueError("c9c_http_transport_missing")
    # Explicit construction: do not forward arbitrary metadata from MQTT.
    native_header={k:h[k] for k in ("type","from","to","sessionid",
                                     "moto_id","trace_id","is_pre",
                                     "p2p_skill","security_level") if k in h}
    native_msg={k:body[k] for k in ("sdp","token","udp_token","tcp_token","log")
                if k in body}
    serialized=json.dumps({"header":native_header,"msg":native_msg},
                          ensure_ascii=False,separators=(",",":"))
    if len(serialized.encode("utf-8"))>32_768:
        raise ValueError("c9c_http_offer_oversized")
    return {"header":native_header,"msg":native_msg}


def safe_http_result(safe: object) -> dict[str,object]:
    """Never return inner HTTP content, SDP, device identity or token."""
    state=safe if isinstance(safe,dict) else {}
    rejected=state.get("rejet_explicite") is True
    accepted=state.get("serveur_accepte") is True and not rejected
    return {
        "diagnostic":"c9c_thing4_http_offer_one_shot",
        "etat":("offre_http_acceptee" if accepted else
                "offre_http_refusee" if rejected else
                "offre_http_sans_acceptation_explicite"),
        "requete_http_effectuee":True,
        "serveur_accepte":accepted,
        "rejet_explicite":rejected,
        "reponse_sdp_recue":False,
        "video_lancee":False,
        "offres_mqtt_envoyees":0,
        "commandes_ptz":0,
        "identifiants_retournes":False,
        "secrets_retournes":False,
    }
