"""Anonymous RTC structure report for the standalone C9C pilot.

Never return vendor endpoints, device IDs, keys, candidate addresses or SDP.
The RTC response is already fetched by the caller. Zero additional requests.
"""
from __future__ import annotations
from typing import Any


def _walk(node: Any, depth: int = 0):
    if depth > 6:
        return
    if isinstance(node, dict):
        yield node
        for value in list(node.values())[:50]:
            if isinstance(value, (dict, list)):
                yield from _walk(value, depth + 1)
    elif isinstance(node, list):
        for value in node[:30]:
            if isinstance(value, (dict, list)):
                yield from _walk(value, depth + 1)


def _known_pv(device: Any) -> str:
    """Values are whitelisted literals only; no raw device metadata escapes."""
    for obj in _walk(device):
        for key in ("pv", "protocolVersion", "protocol_version"):
            value = obj.get(key)
            if value in ("2.2", "2.3"):
                return value
    return "non_identifiee"


def _turn_in_ices(node: Any) -> bool:
    # Inspect strings only from documented ICE URL fields. Never report URLs.
    if not isinstance(node, (dict, list)):
        return False
    def urls(container):
        if isinstance(container, dict):
            for key in ("urls", "urlsEx", "url"):
                v = container.get(key)
                if isinstance(v, str):
                    yield v
                elif isinstance(v, list):
                    for item in v[:20]:
                        if isinstance(item, str):
                            yield item
            for child in list(container.values())[:30]:
                if isinstance(child, (dict, list)):
                    yield from urls(child)
        elif isinstance(container, list):
            for item in container[:30]:
                if isinstance(item, (dict, list)):
                    yield from urls(item)
    return any(s.lower().startswith(("turn:", "turns:")) for s in urls(node))


def summarize_c9c_rtc_schema(rtc: Any, device: Any) -> dict:
    """Flags only: RTC fields cannot prove camera identity or working video."""
    root = rtc if isinstance(rtc, dict) else {}
    nodes = list(_walk(root))[:120]
    p2p = next((obj["p2pConfig"] for obj in nodes
                if isinstance(obj.get("p2pConfig"), dict)), {})
    session = p2p.get("session")
    session = session if isinstance(session, dict) else {}
    ices = p2p.get("ices", [])
    known_moto = any(
        isinstance(obj.get(key), str) and bool(obj[key].strip())
        for obj in nodes for key in ("motoId", "moto_id", "motoID"))
    return {
        "diagnostic": "aosu_c9c_rtc_schema_b8",
        "lecture_seule": True,
        "appels_reseau_supplementaires": 0,
        "commandes_camera": 0,
        "video_lancee": False,
        "identifiants_retournes": False,
        "secrets_retournes": False,
        "p2p_config_presente": bool(p2p),
        "session_presente": bool(session),
        "moto_id_present": known_moto,
        "version_mqtt_pv_connue": _known_pv(device),
        "serveurs_ice_presents": isinstance(ices, list) and bool(ices),
        "serveur_turn_dans_ices": _turn_in_ices(ices),
        "relais_tcp_declare": isinstance(p2p.get("tcpRelay"), dict),
        "relais_udp_declare": isinstance(p2p.get("udpRelay"), dict),
        "cle_locale_presente": isinstance(device, dict)
            and isinstance(device.get("localKey"), str)
            and bool(device["localKey"]),
        "session_id_present": isinstance(session.get("sessionId"), str)
            and bool(session["sessionId"]),
        "video_compatible_confirmee": False,
    }
