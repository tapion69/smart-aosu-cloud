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
)
from .const import (
    DOMAIN, CONF_EMAIL, CONF_PASSWORD,
    CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, ALLOWED_SCAN_INTERVALS,
)

class SmartAosuCloudConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return SmartAosuCloudOptionsFlow()

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            email = str(user_input[CONF_EMAIL]).strip().lower()
            password = user_input[CONF_PASSWORD]
            if not email or "@" not in email or len(email) > 254 or not password:
                errors["base"] = "invalid_input"
            else:
                # Store a hash, not the email, in the config-entry unique ID.
                fingerprint = hashlib.sha256(email.encode("utf-8")).hexdigest()[:20]
                await self.async_set_unique_id(f"aosu_{fingerprint}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title="Smart AOSU Cloud", data={
                    CONF_EMAIL: email, CONF_PASSWORD: password,
                })
        return self.async_show_form(step_id="user", data_schema=vol.Schema({
            vol.Required(CONF_EMAIL): str,
            vol.Required(CONF_PASSWORD): str,
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
            return self.async_create_entry(title="", data={CONF_SCAN_INTERVAL: seconds})

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
        return vol.Schema({
            vol.Required(CONF_SCAN_INTERVAL, default=str(current)): SelectSelector(
                SelectSelectorConfig(options=options, mode=SelectSelectorMode.DROPDOWN)
            )
        })
