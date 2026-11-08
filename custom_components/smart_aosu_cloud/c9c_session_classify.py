"""Privacy-preserving classification of decoded MQTT traffic during C9C live.

All identifiers and SDP remain in RAM. Only fixed labels and booleans escape.
"""
from __future__ import annotations
from typing import Any

_KINDS = frozenset(("offer", "answer", "candidate", "disconnect"))


def classify_unmatched_c9c_message(protocol: object, data: Any, *,
                                   expected_session: str,
                                   expected_device: str,
                                   expected_uid: str) -> dict:
    """Categorize out-of-session and non-video MQTT messages, no raw values."""
    result = {
        "protocol_bucket": "autre",
        "kind": "autre",
        "session_state": "absente",
        "from_device": False,
        "to_user": False,
        "answer_sdp_present": False,
    }
    if type(protocol) is int:
        if 0 <= protocol < 100:
            result["protocol_bucket"] = "0_99"
        elif 100 <= protocol < 300:
            result["protocol_bucket"] = "100_299"
        elif 300 <= protocol < 400:
            result["protocol_bucket"] = "300_399"
    if not isinstance(data, dict) or not isinstance(data.get("header"), dict):
        return result
    header = data["header"]
    kind = header.get("type")
    if isinstance(kind, str) and kind in _KINDS:
        result["kind"] = kind
    sess = header.get("sessionid")
    if isinstance(sess, str) and sess:
        result["session_state"] = (
            "identique" if sess == expected_session and bool(expected_session)
            else "differente")
    result["from_device"] = bool(expected_device) and header.get("from") == expected_device
    result["to_user"] = bool(expected_uid) and header.get("to") == expected_uid
    msg = data.get("msg")
    if kind == "answer" and isinstance(msg, dict):
        sdp = msg.get("sdp")
        result["answer_sdp_present"] = isinstance(sdp, str) and bool(sdp)
    return result
