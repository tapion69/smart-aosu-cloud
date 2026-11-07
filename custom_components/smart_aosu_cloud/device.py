"""Shared HA device descriptor; keep original v0.7.0 device identifiers.

Newer HA versions recommend via_device_id over via_device.  Resolve the
parent in the current config entry to avoid ambiguous cross-account IDs.
"""
from __future__ import annotations
from homeassistant.helpers import device_registry as dr
from .const import DOMAIN

def info_for_device(coordinator, config_entry_id: str, key: str) -> dict:
    record = (coordinator.data or {}).get(key, {})
    info = {
        "identifiers": {(DOMAIN, key)},
        "manufacturer": "AOSU",
        "model": record.get("model") or "AOSU",
        "name": record.get("name") or "AOSU",
    }
    parent = record.get("via_device")
    if parent and parent != key:
        # Hub may not yet be registered during the first round of entity adds.
        # Keep the old linkage as a fallback for existing installations.
        try:
            parent_id = dr.async_get_device_id_by_identifier(
                coordinator.hass, (DOMAIN, parent), config_entry_id=config_entry_id
            )
        except (AttributeError, ValueError):
            parent_id = None
        if parent_id:
            info["via_device_id"] = parent_id
        else:
            info["via_device"] = (DOMAIN, parent)
    return info
