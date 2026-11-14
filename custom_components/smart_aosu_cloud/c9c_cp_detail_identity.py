"""Extract an AOSU CP device ID from its ALREADY authorised C9C detail.

The beta43 getInfoBySn reader retained Ty cpUuid but ignored the distinct
AOSU cpDeviceId/coopUUID namespace, although the same authenticated response
is already in memory. This module makes no HTTP call, no camera command
and never serializes the identifier. A valid CP value is ALWAYS paired with
the exact SN and current AOSU session and may not contradict getList.
"""
from __future__ import annotations

import time
from typing import Any

from .c9c_cp_reference_b32 import extract_c9c_cp_reference, _valid_reference


def extract_cp_id_from_aosu_detail(payload: Any, expected_sn: str
                                   ) -> tuple[str | None, str]:
    """Require confirmed SN; inspect only its own record, never nested peers."""
    if not _valid_reference(expected_sn) or not isinstance(payload, dict):
        return None, "detail_non_conforme"
    if type(payload.get("errno")) is not int or payload["errno"] != 0:
        return None, "detail_refuse"
    data = payload.get("data")
    if not isinstance(data, (dict, list)):
        return None, "structure_non_reconnue"
    queue = [(data, 0)]
    seen = set()
    serials = set()
    references = set()
    invalid = False
    checked = 0
    while queue and checked < 60:
        node, depth = queue.pop(0)
        if isinstance(node, list):
            if depth < 4:
                queue.extend((item, depth+1) for item in node[:30]
                             if isinstance(item, (dict, list)))
            continue
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        checked += 1
        sn = node.get("sn")
        if _valid_reference(sn):
            serials.add(sn)
            if sn == expected_sn:
                cp, source = extract_c9c_cp_reference(node)
                if cp is not None:
                    references.add(cp)
                elif source in ("format_invalide", "references_contradictoires"):
                    invalid = True
        if depth < 4:
            for key in ("data", "list", "device", "deviceInfo", "info"):
                child = node.get(key)
                if isinstance(child, (dict, list)):
                    queue.append((child, depth+1))
    if not serials:
        return None, "numero_serie_absent"
    if serials != {expected_sn}:
        return None, "numero_serie_contradictoire"
    if invalid or len(references) > 1:
        return None, "cp_device_id_contradictoire"
    if not references:
        return None, "cp_device_id_absent_du_detail"
    return next(iter(references)), "cp_device_id_detail_sn_verifie"


def remember_cp_id_from_aosu_detail(client: Any, payload: Any,
                                    expected_sn: str) -> str:
    """Store the exact CP reference only in RAM under this same AOSU login."""
    value, source = extract_cp_id_from_aosu_detail(payload, expected_sn)
    client._standalone_c9c_cp_detail = None
    if (value is not None
            and getattr(client, "_standalone_c9c_sn", None) == expected_sn
            and getattr(client, "_sid", None)
            and getattr(client, "_uid", None)):
        client._standalone_c9c_cp_detail = {
            "cp": value, "sn": expected_sn,
            "sid": client._sid, "uid": client._uid,
            "created": time.monotonic()}
    return source


def resolve_aosu_cp_device_id(client: Any) -> tuple[str | None, str]:
    """Fail closed on contradictory getList/detail refs; no persistence."""
    sn = getattr(client, "_standalone_c9c_sn", None)
    sid = getattr(client, "_sid", None)
    uid = getattr(client, "_uid", None)
    if not _valid_reference(sn) or not sid or not uid:
        return None, "aucune"
    list_cp = getattr(client, "_standalone_c9c_coop_id", None)
    if not _valid_reference(list_cp):
        list_cp = None
    entry = getattr(client, "_standalone_c9c_cp_detail", None)
    detail_cp = None
    if isinstance(entry, dict):
        created = entry.get("created")
        if (entry.get("sn") == sn
                and entry.get("sid") == sid and entry.get("uid") == uid
                and type(created) in (float, int)
                and 0 <= time.monotonic() - created <= 3600
                and _valid_reference(entry.get("cp"))):
            detail_cp = entry["cp"]
    if list_cp is not None and detail_cp is not None and list_cp != detail_cp:
        return None, "sources_aosu_contradictoires"
    if list_cp is not None:
        return list_cp, "getlist_sn"
    if detail_cp is not None:
        return detail_cp, "detail_sn_session"
    return None, "aucune"
