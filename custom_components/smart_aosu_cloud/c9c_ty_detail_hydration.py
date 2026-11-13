"""Safe, on-demand, AOSU SN-bound Ty cpUuid from the existing detail API.

The Android app enriches GzDeviceInfo from a Tuya platform cache; getList
alone need not contain cpDeviceInfo. We may consume cpDeviceInfo.cpUuid if
and ONLY if the separately authenticated getInfoBySn response actually
contains it in an exact SN-matched GzDeviceInfo-like record.

This module performs zero network requests and never serializes identifiers.
"""
from __future__ import annotations
import time
from typing import Any

from .c9c_cp_reference_b32 import extract_c9c_ty_cp_uuid


def _valid_sn(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and value == value.strip() and value.isprintable())


def extract_ty_cp_uuid_from_aosu_detail(payload: Any, expected_sn: str
                                        ) -> tuple[str | None, str]:
    """Exact SN + nested cpDeviceInfo.cpUuid, no inferred/cross-namespace IDs."""
    if not _valid_sn(expected_sn) or not isinstance(payload, dict):
        return None, 'detail_non_conforme'
    if type(payload.get('errno')) is not int or payload['errno'] != 0:
        return None, 'detail_refuse'
    data = payload.get('data')
    if not isinstance(data, (dict, list)):
        return None, 'structure_non_reconnue'
    pending = [(data, 0)]
    seen = set()
    observed_serials = set()
    matches = []
    visited = 0
    while pending and visited < 60:
        node, depth = pending.pop(0)
        if isinstance(node, list):
            if depth < 4:
                pending.extend((part, depth + 1) for part in node[:30]
                               if isinstance(part, (dict, list)))
            continue
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        visited += 1
        sn = node.get('sn')
        if _valid_sn(sn):
            observed_serials.add(sn)
            if sn == expected_sn:
                value, _kind = extract_c9c_ty_cp_uuid(node)
                if value:
                    matches.append(value)
        if depth < 4:
            for key in ('data', 'list', 'device', 'deviceInfo', 'info'):
                child = node.get(key)
                if isinstance(child, (dict, list)):
                    pending.append((child, depth + 1))
    if not observed_serials:
        return None, 'numero_serie_absent'
    if observed_serials != {expected_sn}:
        return None, 'numero_serie_contradictoire'
    values = set(matches)
    if len(values) > 1:
        return None, 'cp_uuid_contradictoire'
    if not values:
        return None, 'cp_uuid_absent_du_detail'
    return next(iter(values)), 'cp_uuid_detail_sn_verifie'


def remember_ty_cp_uuid_from_aosu_detail(client: Any, payload: Any,
                                         expected_sn: str) -> str:
    """Transient memory only. Bound to the existing AOSU authentication."""
    value, source = extract_ty_cp_uuid_from_aosu_detail(payload, expected_sn)
    client._standalone_c9c_ty_uuid_detail = None
    if value is not None and getattr(client, '_sid', None) and getattr(client, '_uid', None):
        client._standalone_c9c_ty_uuid_detail = {
            'uuid': value, 'sn': expected_sn,
            'sid': client._sid, 'uid': client._uid,
            'created': time.monotonic(),
        }
    return source


def resolve_aosu_ty_cp_uuid(client: Any) -> tuple[str | None, str]:
    """Read getList first; then only an unexpired same-SN/session detail."""
    # Neither a former AOSU account nor a failed session may authorize
    # active camera traffic, even if an earlier getList was successful.
    if (not getattr(client, '_sid', None) or
        not getattr(client, '_uid', None) or
        not _valid_sn(getattr(client, '_standalone_c9c_sn', None))):
        return None, 'aucune'
    getlist = getattr(client, '_standalone_c9c_ty_cp_uuid', None)
    if isinstance(getlist, str) and getlist:
        return getlist, 'getlist_sn'
    slot = getattr(client, '_standalone_c9c_ty_uuid_detail', None)
    sn = getattr(client, '_standalone_c9c_sn', None)
    if not isinstance(slot, dict) or not _valid_sn(sn):
        return None, 'aucune'
    at = slot.get('created')
    if (slot.get('sn') != sn or
        slot.get('sid') != getattr(client, '_sid', None) or
        slot.get('uid') != getattr(client, '_uid', None) or
        type(at) not in (float, int) or
        not 0 <= time.monotonic() - at <= 3600):
        return None, 'aucune'
    value = slot.get('uuid')
    if isinstance(value, str) and value:
        return value, 'detail_sn_session'
    return None, 'aucune'
