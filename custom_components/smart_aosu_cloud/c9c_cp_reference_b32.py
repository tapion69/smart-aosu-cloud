"""Private AOSU CP identity selection for exactly one standalone C9C.

The AOSU SDK maps UUIDInfoWebDataItem.coopUUID -> GzDeviceInfo.cpDeviceId.
The authenticated /v1/dev/getList may contain equivalent references in
known locations. Use only the camera's own SN-matched record, never arbitrary
JSON traversal, names, guessed IDs, or identifiers from other cameras.

Do not serialize, log, hash or return CP IDs in Home Assistant responses.
"""
from __future__ import annotations
from typing import Any


def _valid_reference(value: Any) -> bool:
    # Strict, exact-byte matching is vital: never trim, casefold, coerce or
    # normalize an ID and accidentally bind a different device.
    return (
        isinstance(value, str) and not isinstance(value, bool)
        and 1 <= len(value) <= 256 and value == value.strip()
        and value.isprintable() and not any(c.isspace() for c in value)
        and not any(c in value for c in "#+\r\n\0")
    )


def extract_c9c_cp_reference(record: Any) -> tuple[str | None, str]:
    """AOSU-owned record -> (private ID or None, safe source classification).

    A root coopUUID, root cpDeviceId or nested cpDeviceInfo.cpDeviceId may
    represent the Android SDK's CP mapping. Contradictory values (even if a
    candidate can be selected uniquely) MUST NOT establish an exact identity.
    """
    if not isinstance(record, dict):
        return None, "fiche_absente"
    meta = record.get("cpDeviceInfo")
    sources = {
        "coop_uuid_racine": record.get("coopUUID"),
        "cp_device_id_racine": record.get("cpDeviceId"),
        "cp_device_info": meta.get("cpDeviceId") if isinstance(meta,dict) else None,
    }
    provided = {key: value for key, value in sources.items() if value is not None}
    if not provided:
        return None, "absente"
    if any(not _valid_reference(value) for value in provided.values()):
        return None, "format_invalide"
    unique = set(provided.values())
    if len(unique) != 1:
        return None, "references_contradictoires"
    if len(provided) > 1:
        return next(iter(unique)), "champs_concordants"
    key = next(iter(provided))
    return next(iter(unique)), key


def extract_c9c_ty_cp_uuid(record: Any) -> tuple[str | None, str]:
    """Private authoritative Tuya-platform UUID from an AOSU SN-matched row.

    AOSU Android 5.10.12 DeviceInfoExtKt.OooO0O0 reads
    GzDeviceInfo.cpDeviceInfo.cpUuid when its Iot platform is Ty.
    This is a distinct namespace from the coopUUID -> cpDeviceId mapping.
    Do not guess cpUuid from coopUUID, deviceId, SN or a product UUID.
    """
    if not isinstance(record, dict):
        return None, "fiche_absente"
    nested = record.get("cpDeviceInfo")
    if not isinstance(nested, dict):
        return None, "champ_cp_device_info_absent"
    value = nested.get("cpUuid")
    if value is None:
        return None, "cp_uuid_absent"
    if not _valid_reference(value):
        return None, "cp_uuid_invalide"
    # If root cpUuid is explicitly present, reject contradictory values.
    root = record.get("cpUuid")
    if root is not None and (not _valid_reference(root) or root != value):
        return None, "cp_uuid_contradictoire"
    return value, "cp_uuid_ty_explicite"
