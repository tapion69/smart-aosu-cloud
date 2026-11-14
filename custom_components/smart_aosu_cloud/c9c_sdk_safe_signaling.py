"""AOSU-specific safety overrides for optional Tuya IPC P2P SDK 0.1.3.

Upstream MotoClient intentionally disables certificate verification on
its regional broker, and checks only sessionid on incoming answers. Our
AOSU bridge must not silently downgrade our already-verified TLS or accept
packets from the wrong camera or user.

MIT original: https://github.com/roquerodrigo/tuya-ipc-p2p-sdk/
The SDK itself is not modified or vendored here. Not wired into HA Play.
"""
from __future__ import annotations

import asyncio
import ssl
from typing import Any

import aiomqtt

from tuya_ipc_p2p_sdk.exceptions import TuyaIpcP2pError
from tuya_ipc_p2p_sdk.signaling.envelope import decode_payload
from tuya_ipc_p2p_sdk.signaling.moto_client import MotoClient
from tuya_ipc_p2p_sdk.stream_session import StreamSession


class SafeAosuMotoClient(MotoClient):
    """Maintain certificate verification and bind inbound signal to our C9C."""

    def __init__(self, *args: Any, moto_id: str = "", **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._aosu_moto_id = (
            moto_id if isinstance(moto_id, str)
            and len(moto_id) <= 128 and moto_id == moto_id.strip()
            and moto_id.isprintable() and not any(ch.isspace() for ch in moto_id)
            else "")

    def _header(self, message_type: str, trace_id: str = "") -> dict:
        header = super()._header(message_type, trace_id)
        # Native AOSU may supply an actual moto_id; do not overwrite it
        # with the upstream library's hardcoded empty identifier.
        header["moto_id"] = self._aosu_moto_id
        return header

    def _consume(self, payload: bytes) -> None:
        """Discard other-account, other-device or stale-session SDP/candidates."""
        try:
            signal = decode_payload(self._key, payload)
        except (TuyaIpcP2pError, ValueError, TypeError, KeyError, UnicodeError):
            return
        if not isinstance(signal, dict):
            return
        header, message = signal.get("header"), signal.get("msg")
        if not isinstance(header, dict) or not isinstance(message, dict):
            return
        # Upstream alone permits missing sessionid and does not check from/to.
        # C9C must require all three independently, before callback delivery.
        if (header.get("sessionid") != self._session_id
                or header.get("from") != self._device_id
                or header.get("to") != self._uid):
            return
        kind = header.get("type")
        if kind in ("answer", "candidate", "disconnect"):
            self._dispatch(kind, message)

    async def async_connect(self) -> None:
        """Use verified TLS or fail; never fall back to the upstream insecure context."""
        tls = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tls.check_hostname = True
        tls.verify_mode = ssl.CERT_REQUIRED
        client = aiomqtt.Client(
            hostname=self._identity.host, port=self._identity.port,
            username=self._identity.username,
            password=self._identity.password,
            identifier=self._identity.client_id, keepalive=60,
            tls_context=tls, clean_session=True)
        opened = False
        try:
            async with asyncio.timeout(15):
                await client.__aenter__()
            opened = True
            await client.subscribe(self._subscribe_topic, qos=1)
            self._client = client
            self._reader = asyncio.create_task(self._async_read())
        except asyncio.CancelledError:
            if opened:
                try:
                    await client.__aexit__(None, None, None)
                except Exception:
                    pass
            raise
        except Exception:
            if opened:
                try:
                    await client.__aexit__(None, None, None)
                except Exception:
                    pass
            # Never return broker URLs, account IDs or vendor exception strings.
            raise ValueError("c9c_signalisation_tls_ou_mqtt_refusee") from None


class SafeAosuStreamSession(StreamSession):
    """The real upstream relay/ICE/KCP/media engine, with safe OEM MQTT."""

    async def _async_connect_signaling(self, session_id: str) -> None:
        config = self._config
        self._moto = SafeAosuMotoClient(
            identity=self._identity, uid=self._uid,
            device_id=config.device_id, session_id=session_id,
            local_key=config.local_key,
            on_answer=self._on_answer,
            on_candidate=self._on_remote_candidate,
            on_disconnect=self._on_device_disconnect,
            moto_id=config.moto_id)
        await self._moto.async_connect()
