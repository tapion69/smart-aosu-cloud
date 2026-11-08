"""Carefully extract an optional moto_id from the *same* RTC response.

Never export its value, and never use one found at an unknown nested path.
An observation of moto_id somewhere in the response is not identity proof.
"""
from __future__ import annotations
from typing import Any

_FIELDS = ("moto_id", "motoId", "motoID")
_ALLOWED_PATHS = ("rtc_root", "rtc_data", "p2p_config", "p2p_session")


def _candidate_nodes(raw: Any) -> list[tuple[str, dict]]:
    """A few recognized envelopes only; deliberately no generic deep walk."""
    if not isinstance(raw, dict):
        return []
    roots = [raw]
    for key in ("data", "result"):
        val = raw.get(key)
        if isinstance(val, dict):
            roots.append(val)
            for inner in ("data", "result"):
                nested = val.get(inner)
                if isinstance(nested, dict):
                    roots.append(nested)
    nodes: list[tuple[str, dict]] = []
    for node in roots[:8]:
        label = "rtc_root" if node is raw else "rtc_data"
        nodes.append((label, node))
        p2p = node.get("p2pConfig")
        if isinstance(p2p, dict):
            nodes.append(("p2p_config", p2p))
            session = p2p.get("session")
            if isinstance(session, dict):
                nodes.append(("p2p_session", session))
    return nodes[:32]


def _valid_moto(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and all(
        32 < ord(char) < 127 for char in value)


def resolve_rtc_moto_id(raw: Any) -> tuple[str, str]:
    """Return (private value, safe source enum); fail closed if ambiguous."""
    found: dict[str, set[str]] = {}
    for source, node in _candidate_nodes(raw):
        if source not in _ALLOWED_PATHS:
            continue
        for field in _FIELDS:
            value = node.get(field)
            if _valid_moto(value):
                found.setdefault(value, set()).add(source)
    if not found:
        return "", "champ_non_resolu"
    if len(found) != 1:
        return "", "valeurs_ambigues"
    value, sources = next(iter(found.items()))
    for source in ("p2p_session", "p2p_config", "rtc_data", "rtc_root"):
        if source in sources:
            return value, source
    return "", "champ_non_resolu"
