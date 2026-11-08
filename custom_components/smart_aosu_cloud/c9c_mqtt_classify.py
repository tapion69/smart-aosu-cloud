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
    return result
