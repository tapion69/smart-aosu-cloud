"""User-activated Play and Stop controls for the selected camera. Never auto-start."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.exceptions import HomeAssistantError
from homeassistant.core import callback
from .device import info_for_device
from .live_device import select_live_camera_key


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    registered = False

    @callback
    def add_when_available():
        nonlocal registered
        target_key = select_live_camera_key(coordinator)
        if registered or target_key is None:
            return
        registered = True
        async_add_entities([
            SmartAosuLiveButton(coordinator, entry.entry_id, target_key, action='play'),
            SmartAosuLiveButton(coordinator, entry.entry_id, target_key, action='stop'),
        ])

    # Remove the old Pause button from the entity registry too, not just from
    # setup. Otherwise an orphaned 'Unavailable' entity survives upgrades.
    if hass is not None:
        from homeassistant.helpers import entity_registry as er
        registry = er.async_get(hass)
        old_uid = f'smart_aosu_{entry.entry_id}_c5l_direct_pause'
        old_id = registry.async_get_entity_id('button', 'smart_aosu_cloud', old_uid)
        if old_id:
            registry.async_remove(old_id)
    add_when_available()
    entry.async_on_unload(coordinator.async_add_listener(add_when_available))


class SmartAosuLiveButton(ButtonEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator, entry_id, device_key, *, play: bool | None = None, action: str | None = None):
        self._controller = coordinator.live_controller
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_key = device_key
        action = action or ('play' if play else 'stop')
        if action not in ('play', 'stop'):
            raise ValueError('invalid preview action')
        self._action = action
        self._attr_unique_id = f"smart_aosu_{entry_id}_c5l_direct_{action}"
        names = {'play': 'C5L Direct - Lecture', 'stop': 'C5L Direct - Arrêt'}
        icons = {'play': 'mdi:play-circle', 'stop': 'mdi:stop-circle'}
        self._attr_name = names[action]
        self._attr_icon = icons[action]

    @property
    def device_info(self):
        return info_for_device(self._coordinator, self._entry_id, self._device_key)

    async def async_press(self) -> None:
        if self._action == 'stop':
            self._controller.stop()
            return
        # Pressing Play is the explicit user decision to start Tuya RTC/MQTT
        # and the camera-name-selected C5L. No background / setup start.
        result = self._controller.start(password_confirmed=True, candidate_confirmed=True)
        if result.get("etat") in ("demarrage_demande", "direct_deja_en_cours", "reprise_direct_existant"):
            return
        if result.get('etat') == 'demarrage_non_lance_reessai':
            seconds = int(result.get('secondes_restantes') or 0)
            raise HomeAssistantError(
                f'Direct C5L indisponible apres un echec reel : nouvel essai dans {seconds} s. ' +
                'Aucune nouvelle demande automatique.')
        if result.get("etat") == "demarrage_non_lance_limitation":
            delay = int(result.get("delai_maximum_secondes") or 0)
            raise HomeAssistantError(f"Direct C5L non lance : autre operation en cours ({delay} secondes restantes au maximum).")
        raise HomeAssistantError("Direct C5L non lance : " + str(result.get("etat", "erreur")))
