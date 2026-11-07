"""Account setup. Credentials are stored in HA config entries, not encrypted."""
from __future__ import annotations
import hashlib
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector, TextSelectorConfig, TextSelectorType,
    FileSelector, FileSelectorConfig,
)
from .network_config import optional_station_ip
from .local_resources import resources_ready, import_ha_uploads, ResourceImportError
from .const import (
    DOMAIN, CONF_EMAIL, CONF_PASSWORD,
    CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, ALLOWED_SCAN_INTERVALS, CONF_STATION_IP,
)

class SmartAosuCloudConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_resources(self, user_input=None):
        """Upload APK Lite and OEM resources from the user browser."""
        errors = {}
        if user_input is not None:
            apk_id = user_input.get("apk_lite")
            oem_id = user_input.get("oem_resources")
            if not apk_id or not oem_id:
                errors["base"] = "missing_files"
            else:
                try:
                    await self.hass.async_add_executor_job(
                        import_ha_uploads, self.hass, apk_id, oem_id
                    )
                except ResourceImportError as exc:
                    errors["base"] = str(exc)
                else:
                    return await self.async_step_user()
        return self.async_show_form(step_id="resources", data_schema=vol.Schema({
            vol.Required("apk_lite"): FileSelector(FileSelectorConfig(accept=".apk")),
            vol.Required("oem_resources"): FileSelector(FileSelectorConfig(accept=".zip")),
        }), errors=errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return SmartAosuCloudOptionsFlow()

    async def async_step_user(self, user_input=None):
        # Existing installations retain their resources; fresh installs import
        # both files before collecting AOSU account credentials.
        if not await self.hass.async_add_executor_job(resources_ready):
            return await self.async_step_resources()
        errors = {}
        if user_input is not None:
            email = str(user_input[CONF_EMAIL]).strip().lower()
            password = user_input[CONF_PASSWORD]
            if not email or "@" not in email or len(email) > 254 or not password:
                errors["base"] = "invalid_input"
            else:
                try:
                    station_ip = optional_station_ip(user_input.get(CONF_STATION_IP))
                except ValueError:
                    errors[CONF_STATION_IP] = "invalid_station_ip"
                if not errors:
                    # Store a hash, not the email, in the config-entry unique ID.
                    fingerprint = hashlib.sha256(email.encode("utf-8")).hexdigest()[:20]
                    await self.async_set_unique_id(f"aosu_{fingerprint}")
                    self._abort_if_unique_id_configured()
                    return self.async_create_entry(title="Smart AOSU Cloud", data={
                        CONF_EMAIL: email, CONF_PASSWORD: password,
                        CONF_STATION_IP: station_ip,
                    })
        return self.async_show_form(step_id="user", data_schema=vol.Schema({
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
            vol.Optional(CONF_STATION_IP): str,
        }), errors=errors)


class SmartAosuCloudOptionsFlow(config_entries.OptionsFlow):
    """Let the user adjust polling without restarting or reconnecting."""

    async def async_step_init(self, user_input=None):
        if user_input is not None:
            try:
                seconds = int(user_input[CONF_SCAN_INTERVAL])
            except (KeyError, ValueError, TypeError):
                seconds = None
            if seconds not in ALLOWED_SCAN_INTERVALS:
                return self.async_show_form(
                    step_id="init", data_schema=self._options_schema(),
                    errors={"base": "invalid_interval"},
                )
            try:
                station_ip = optional_station_ip(user_input.get(CONF_STATION_IP))
            except ValueError:
                return self.async_show_form(step_id="init", data_schema=self._options_schema(),
                                            errors={CONF_STATION_IP: "invalid_station_ip"})
            return self.async_create_entry(title="", data={
                CONF_SCAN_INTERVAL: seconds, CONF_STATION_IP: station_ip,
            })

        return self.async_show_form(step_id="init", data_schema=self._options_schema())

    def _options_schema(self):
        current = self.config_entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
        if current not in ALLOWED_SCAN_INTERVALS:
            current = DEFAULT_SCAN_INTERVAL
        options = [SelectOptionDict(value=str(seconds), label=label) for seconds, label in (
            (60, "1 minute (experimental)"),
            (120, "2 minutes (recommande)"),
            (300, "5 minutes"),
            (600, "10 minutes"),
            (900, "15 minutes"),
        )]
        station_ip = self.config_entry.options.get(
            CONF_STATION_IP, self.config_entry.data.get(CONF_STATION_IP, ""))
        return vol.Schema({
            vol.Required(CONF_SCAN_INTERVAL, default=str(current)): SelectSelector(
                SelectSelectorConfig(options=options, mode=SelectSelectorMode.DROPDOWN)
            ),
            vol.Optional(CONF_STATION_IP, default=station_ip or ""): str,
        })
