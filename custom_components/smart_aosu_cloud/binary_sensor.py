"""Read-only cloud connectivity from AOSU's documented getList payload.

online=1 was observed on every connected device; 0 is treated as offline.
Any unexpected numeric code is unknown (None), not interpreted as online.
"""
from __future__ import annotations
from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .device import info_for_device
from .semantics import cloud_online

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    registered = set()

    def add_new():
        new = []
        for key, info in sorted(
            (coordinator.data or {}).items(),
            key=lambda kv: bool(kv[1].get("via_device")),
        ):
            if key in registered or info.get("online") is None:
                continue
            registered.add(key)
            new.append(SmartAosuCloudConnectivity(coordinator, entry.entry_id, key))
        if new:
            async_add_entities(new)

    add_new()
    entry.async_on_unload(coordinator.async_add_listener(add_new))

class SmartAosuCloudConnectivity(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True
    _attr_name = "Connexion cloud"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator, config_entry_id, key):
        super().__init__(coordinator)
        self.key = key
        self.config_entry_id = config_entry_id
        self._attr_unique_id = f"aosu_{key}_connected"

    @property
    def available(self):
        return super().available and self.key in (self.coordinator.data or {})

    @property
    def is_on(self):
        raw = (self.coordinator.data or {}).get(self.key, {}).get("online")
        return cloud_online(raw)

    @property
    def device_info(self):
        return info_for_device(self.coordinator, self.config_entry_id, self.key)
