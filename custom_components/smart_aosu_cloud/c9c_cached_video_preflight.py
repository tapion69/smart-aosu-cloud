"""C9C standalone: avoid futile active Play on a proven-weak fresh cache.

Pure local preflight, no credentials copied and no network. This is NOT
a replacement for the server-side identity gate in tuya_rtc_inventory.
Missing/expired caches return UNKNOWN, never a fabricated exact identity.
"""
from __future__ import annotations

import time
from typing import Any, Callable

_EXACT = frozenset({
    "identite_exacte_serie",
    "identite_exacte_cp_device_id",
    "identite_exacte_cp_device_id_dev_id",
    "identite_exacte_ty_cp_uuid",
})


def cached_c9c_video_preflight(client: Any, *,
                              select_tuya_typed: Callable,
                              resolve_ty_uuid: Callable,
                              resolve_cp_id: Callable | None = None,
                              now: float | None = None) -> dict[str, object]:
    """Safe constant-token report; only fresh same-session data can block."""
    base = {
        "diagnostic": "aosu_c9c_preflight_cache_v1",
        "appels_reseau": 0,
        "commandes_camera": 0,
        "offres_mqtt_envoyees": 0,
        "identifiants_retournes": False,
        "secrets_retournes": False,
        "etat": "cache_non_conclusif",
    }
    at = time.monotonic() if now is None else now
    if (not isinstance(at,(float,int)) or isinstance(at,bool)
            or not isinstance(getattr(client,"_standalone_c9c_sn",None),str)
            or not getattr(client,"_standalone_c9c_sn")
            or not getattr(client,"_sid",None)
            or not getattr(client,"_uid",None)):
        return base
    session = getattr(client,"_tuya_oem_session",None)
    cache = getattr(client,"_tuya_oem_inventory_cache",None)
    if not isinstance(cache,dict):
        return base
    created = cache.get("created")
    acquired = getattr(session,"acquired_at",None)
    uid = getattr(session,"uid",None)
    devices = cache.get("devices")
    if (type(created) not in (float,int)
            or type(acquired) not in (float,int)
            or not 0 <= at-created < 600
            or not 0 <= at-acquired < 1200
            or not isinstance(uid,str) or not uid
            or cache.get("session_uid") != uid
            or not isinstance(devices,dict)
            or not 1 <= len(devices) <= 100):
        return base
    ty_uuid, _source = resolve_ty_uuid(client)
    cp_id = (
        resolve_cp_id(client)[0] if callable(resolve_cp_id)
        else getattr(client, "_standalone_c9c_coop_id", None))
    target, classification = select_tuya_typed(
        devices,
        camera_sn=client._standalone_c9c_sn,
        camera_cp_device_id=cp_id,
        camera_ty_cp_uuid=ty_uuid)
    if target is not None and classification in _EXACT:
        return {**base,"etat":"identite_exacte_cachee"}
    # A current, same-account, same-session inventory only shows weak,
    # ambiguous or absent matches. Repeating active offers cannot fix this.
    return {**base,"etat":"identite_non_prouvee_cache_reutilise"}


__all__ = ["cached_c9c_video_preflight"]
