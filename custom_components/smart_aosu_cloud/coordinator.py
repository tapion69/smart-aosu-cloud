"""Read-only polling coordinator for AOSU cloud."""
from __future__ import annotations
from datetime import timedelta
import logging
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from .const import DOMAIN, UPDATE_SECONDS
from .api import AosuCloudError
_LOGGER=logging.getLogger(__name__)

class SmartAosuCloudCoordinator(DataUpdateCoordinator[dict]):
    def __init__(self,hass,client, update_seconds=UPDATE_SECONDS):
        super().__init__(hass,_LOGGER,name=DOMAIN,
                         update_interval=timedelta(seconds=update_seconds),
                         always_update=False)
        self.client=client

    async def _async_update_data(self):
        try:
            return await self.hass.async_add_executor_job(self.client.refresh)
        except AosuCloudError as exc:
            # Do not include URLs, cookies, sessions or server payloads in logs.
            raise UpdateFailed(str(exc)) from exc
