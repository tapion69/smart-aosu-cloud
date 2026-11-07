"""Existing raw sensors, with Wi-Fi and energy exposed as normal sensors.

Preserves EVERY v0.7.0 unique_id so existing entity registry entries and
user automations are not replaced.  Units remain deliberately unspecified.
"""
from __future__ import annotations
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .device import info_for_device

DESCRIPTORS = {
    # kind: (name, icon, is_diagnostic)
    "online": ("Connexion cloud (code brut)", "mdi:cloud-outline", True),
    "device_type": ("Type d'appareil (code brut)", "mdi:identifier", True),
    "electricity": ("Énergie AOSU (valeur brute)", "mdi:battery-unknown", False),
    "wifi_signal": ("Signal Wi-Fi (valeur brute)", "mdi:wifi", False),
    "power_mode": ("Mode d'alimentation (code brut)", "mdi:power", True),
}

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    registered = set()
    registered_event_time = set()
    registered_event_feed = set()

    def add_new():
        new = []
        # Register hub first: HA can then link child devices correctly.
        for key, info in sorted(
            (coordinator.data or {}).items(),
            key=lambda kv: bool(kv[1].get("via_device")),
        ):
            for kind in DESCRIPTORS:
                if info.get(kind) is None or (key, kind) in registered:
                    continue
                registered.add((key, kind))
                new.append(SmartAosuCloudRawSensor(coordinator, entry.entry_id, key, kind))
            # Only cameras that expose a valid timestamp get this sensor.
            # The H1L base does not expose coverInfo.eventTime in the real inventory.
            if info.get("cover_event_time") is not None and key not in registered_event_time:
                registered_event_time.add(key)
                new.append(SmartAosuCloudCoverTime(coordinator, entry.entry_id, key))
            if info.get("is_camera") and key not in registered_event_feed:
                registered_event_feed.add(key)
                new.append(SmartAosuCloudLastEventType(coordinator, entry.entry_id, key))
                new.append(SmartAosuCloudLastEventTime(coordinator, entry.entry_id, key))
        if new:
            async_add_entities(new)

    add_new()
    entry.async_on_unload(coordinator.async_add_listener(add_new))

class SmartAosuCloudRawSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, config_entry_id, key, kind):
        super().__init__(coordinator)
        self.key = key
        self.kind = kind
        self.config_entry_id = config_entry_id
        name, icon, diagnostic = DESCRIPTORS[kind]
        self._attr_name = name
        self._attr_icon = icon
        self._attr_unique_id = f"aosu_{key}_{kind}"
        if diagnostic:
            self._attr_entity_category = EntityCategory.DIAGNOSTIC
        # No unit / state_class / device_class until verified against AOSU.

    @property
    def available(self):
        return super().available and self.key in (self.coordinator.data or {})

    @property
    def native_value(self):
        return (self.coordinator.data or {}).get(self.key, {}).get(self.kind)

    @property
    def device_info(self):
        return info_for_device(self.coordinator, self.config_entry_id, self.key)


class SmartAosuCloudCoverTime(CoordinatorEntity, SensorEntity):
    """Timestamp supplied by coverInfo.eventTime, with no event-type claim."""
    _attr_has_entity_name = True
    _attr_name = "Horodatage de couverture AOSU"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:clock-outline"

    def __init__(self, coordinator, config_entry_id, key):
        super().__init__(coordinator)
        self.key = key
        self.config_entry_id = config_entry_id
        self._attr_unique_id = f"aosu_{key}_cover_event_time"

    @property
    def available(self):
        return super().available and self.key in (self.coordinator.data or {})

    @property
    def native_value(self):
        # Parsed as aware UTC in normalize_devices(). No image, URLs or tokens.
        return (self.coordinator.data or {}).get(self.key, {}).get("cover_event_time")

    @property
    def device_info(self):
        return info_for_device(self.coordinator, self.config_entry_id, self.key)


class SmartAosuCloudLastEventType(CoordinatorEntity, SensorEntity):
    """Most recent *recorded* event from getImageList, NOT active detection."""
    _attr_has_entity_name = True
    _attr_name = "Dernier type de détection AOSU"
    _attr_icon = "mdi:motion-sensor"

    def __init__(self, coordinator, config_entry_id, key):
        super().__init__(coordinator)
        self.key = key
        self.config_entry_id = config_entry_id
        self._attr_unique_id = f"aosu_{key}_recent_event_type"

    @property
    def available(self):
        return super().available and self.key in (self.coordinator.data or {})

    @property
    def native_value(self):
        return (self.coordinator.data or {}).get(self.key, {}).get("recent_event_type")

    @property
    def device_info(self):
        return info_for_device(self.coordinator, self.config_entry_id, self.key)


class SmartAosuCloudLastEventTime(CoordinatorEntity, SensorEntity):
    """Time of latest event in bounded cloud list, not live movement."""
    _attr_has_entity_name = True
    _attr_name = "Dernière détection AOSU (liste d'images)"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_icon = "mdi:clock-check-outline"

    def __init__(self, coordinator, config_entry_id, key):
        super().__init__(coordinator)
        self.key = key
        self.config_entry_id = config_entry_id
        self._attr_unique_id = f"aosu_{key}_recent_event_time"

    @property
    def available(self):
        return super().available and self.key in (self.coordinator.data or {})

    @property
    def native_value(self):
        return (self.coordinator.data or {}).get(self.key, {}).get("recent_event_time")

    @property
    def device_info(self):
        return info_for_device(self.coordinator, self.config_entry_id, self.key)
