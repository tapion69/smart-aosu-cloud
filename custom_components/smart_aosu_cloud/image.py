"""AOSU last detection thumbnail image entities; no stream or raw URLs exposed."""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

from homeassistant.components.image import ImageEntity
from homeassistant.core import callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .device import info_for_device
from .image_fetch import fetch_thumbnail


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    registered = set()

    @callback
    def add_new():
        entities = []
        for key, data in (coordinator.data or {}).items():
            if (key in registered or not data.get("is_camera") or
                    not data.get("has_image_ref")):
                continue
            registered.add(key)
            entities.append(SmartAosuCloudImage(hass, coordinator, entry.entry_id, key))
        if entities:
            async_add_entities(entities)

    add_new()
    entry.async_on_unload(coordinator.async_add_listener(add_new))


class SmartAosuCloudImage(CoordinatorEntity, ImageEntity):
    _attr_has_entity_name = True
    _attr_name = "Dernière miniature"
    _attr_icon = "mdi:image-outline"
    _attr_should_poll = False

    def __init__(self, hass, coordinator, config_entry_id, key):
        CoordinatorEntity.__init__(self, coordinator)
        ImageEntity.__init__(self, hass)
        self.key = key
        self.config_entry_id = config_entry_id
        self._attr_unique_id = f"aosu_{key}_last_thumbnail"
        self._updated: datetime | None = None
        self._fingerprint = None
        self._cached_bytes: bytes | None = None
        self._cached_type = "image/jpeg"
        self._next_retry = 0.0
        self._reconcile_state()

    @property
    def available(self):
        data = (self.coordinator.data or {}).get(self.key)
        return bool(super().available and data and data.get("has_image_ref"))

    @property
    def device_info(self):
        return info_for_device(self.coordinator, self.config_entry_id, self.key)

    @property
    def content_type(self):
        return self._cached_type

    @property
    def image_last_updated(self):
        return self._updated

    def _reconcile_state(self):
        data = (self.coordinator.data or {}).get(self.key, {})
        url = self.coordinator.client.get_image_url(self.key)
        if not url or not data.get("is_camera"):
            self._fingerprint = None
            self._cached_bytes = None
            self._updated = None
            return
        event_at = data.get("cover_event_time")
        revision = (hashlib.sha256(url.encode()).digest(), event_at)
        if revision == self._fingerprint:
            return
        self._fingerprint = revision
        self._cached_bytes = None
        self._next_retry = 0.0
        # Image state indicates when HA noticed a new revision, not the
        # detection time (already available as a separate timestamp sensor).
        self._updated = datetime.now(timezone.utc)

    @callback
    def _handle_coordinator_update(self):
        self._reconcile_state()
        super()._handle_coordinator_update()

    async def async_image(self):
        """Only fetch on first view/change, rate-limit failed requests."""
        if self._cached_bytes is not None:
            return self._cached_bytes
        if time.monotonic() < self._next_retry:
            return None
        url = self.coordinator.client.get_image_url(self.key)
        if not url:
            return None
        # Do not keep the URL in HA state, image properties or returned output.
        revision = self._fingerprint
        image, mime, status = await self.hass.async_add_executor_job(fetch_thumbnail, url)
        if revision != self._fingerprint:
            return None  # Ignore bytes belonging to a superseded URL/event.
        if image is None:
            self._next_retry = time.monotonic() + 60.0
            return None
        self._cached_bytes = image
        self._cached_type = mime
        return image
