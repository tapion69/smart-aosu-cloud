"""Classify encrypted C9C MQTT signals in volatile memory, not logs.

All output fields are booleans or fixed enums. No payload, key, serial,
identity, SDP or unknown protocol strings are ever returned.
"""
from __future__ import annotations
from typing import Any, Callable


def classify_observed_signal(raw: bytes, *, key: bytes | None,
                             device_id: str, uid: str,
                             decoder: Callable[[bytes, bytes], tuple[Any, Any]]) -> dict:
    result = {
        "pv22": False, "decoded": False,
        "protocol": "other", "type": "other",
        "from_device": False, "to_device": False,
        "from_user": False, "to_user": False,
        "path_mqtt": False, "path_other": False,
        "sessionid_present": False, "moto_id_present": False,
        "answer_sdp_present": False, "answer_aes_kcp": False,
        "candidate_ice_present": False, "answer_to_user": False,
        "offer_sdp_present": False, "offer_aes_kcp": False,
        "offer_trace_present": False, "offer_is_pre_zero": False,
        "offer_p2p_skill_1635": False, "offer_security_level_3": False,
        "offer_preconnect_true": False, "offer_token_present": False,
        "offer_tcp_token_present": False, "offer_log_present": False,
    }
    if not isinstance(raw, bytes) or len(raw) < 3 or len(raw) > 32768:
        return result
    if not raw.startswith(b"2.2"):
        return result
    result["pv22"] = True
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        return result
    try:
        protocol, payload = decoder(key, raw)
    except Exception:
        # Errors may include private vendor data: never forward or log them.
        return result
    if not isinstance(payload, dict):
        return result
    result["decoded"] = True
    if type(protocol) is int and protocol in (22, 302):
        result["protocol"] = str(protocol)
    header = payload.get("header")
    if isinstance(header, dict):
        kind = header.get("type")
        if kind in ("offer", "answer", "candidate", "disconnect"):
            result["type"] = kind
        sender, recipient = header.get("from"), header.get("to")
        result["from_device"] = (
            isinstance(sender, str) and bool(device_id) and sender == device_id)
        result["to_device"] = (
            isinstance(recipient, str) and bool(device_id) and recipient == device_id)
        result["from_user"] = (
            isinstance(sender, str) and bool(uid) and sender == uid)
        result["to_user"] = (
            isinstance(recipient, str) and bool(uid) and recipient == uid)
        path = header.get("path")
        result["path_mqtt"] = path == "mqtt"
        result["path_other"] = isinstance(path,str) and bool(path) and path != "mqtt"
        sessionid = header.get("sessionid")
        moto = header.get("moto_id")
        result["sessionid_present"] = isinstance(sessionid,str) and bool(sessionid)
        result["moto_id_present"] = isinstance(moto,str) and bool(moto)
        if result["protocol"]=="302" and result["type"]=="offer":
            result["offer_trace_present"] = (
                isinstance(header.get("trace_id"),str) and bool(header["trace_id"]))
            result["offer_is_pre_zero"] = type(header.get("is_pre")) is int and header["is_pre"]==0
            result["offer_p2p_skill_1635"] = (
                type(header.get("p2p_skill")) is int and header["p2p_skill"]==1635)
            result["offer_security_level_3"] = (
                type(header.get("security_level")) is int and header["security_level"]==3)
    msg = payload.get("msg")
    if isinstance(msg,dict) and result["protocol"]=="302":
        if result["type"]=="offer":
            sdp=msg.get("sdp")
            result["offer_sdp_present"]=isinstance(sdp,str) and bool(sdp)
            result["offer_aes_kcp"]=isinstance(sdp,str) and "AES/KCP" in sdp
            result["offer_preconnect_true"]=msg.get("preconnect") is True
            result["offer_token_present"]=isinstance(msg.get("token"),(list,dict)) and bool(msg["token"])
            result["offer_tcp_token_present"]=isinstance(msg.get("tcp_token"),dict) and bool(msg["tcp_token"])
            result["offer_log_present"]=isinstance(msg.get("log"),dict)
        elif result["type"]=="answer":
            sdp = msg.get("sdp")
            result["answer_sdp_present"] = isinstance(sdp,str) and bool(sdp)
            result["answer_aes_kcp"] = (
                isinstance(sdp,str) and "AES/KCP" in sdp)
            result["answer_to_user"] = result["to_user"] is True
        elif result["type"]=="candidate":
            candidate = msg.get("candidate")
            result["candidate_ice_present"] = (
                isinstance(candidate,str) and bool(candidate))
    return result
