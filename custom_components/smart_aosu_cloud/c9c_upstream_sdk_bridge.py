"""Optional *real* Linux P2P SDK backend for AOSU standalone C9C.

The upstream MIT-licensed tuya-ipc-p2p-sdk (tested contract: v0.1.3)
implements signaling, ICE, relay, KCP and MJPEG; this bridge adapts the
existing AOSU-authenticated Tuya session to it. It never performs a second
Smart Life login and does not duplicate the authenticated RTC request.

NOT wired into LiveController. Callers must supply a freshly authenticated,
uniquely SN-bound AOSU camera->Tuya device proof. No weak unique candidate
can use this bridge. Package is deliberately NOT added to HA manifest.
One-shot active transport remains disabled until hardware validation.

No raw identifier, key, token, SDP, vendor exception or image enters an
output report or log here. The upstream package may log private session and
candidate values at DEBUG; an eventual integration MUST keep its logger
at WARNING or higher before enabling this backend.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable

from .camera_topology import select_tuya_standalone_target_typed

_ALLOWED_SELECTIONS = frozenset({
    "identite_exacte_serie",
    "identite_exacte_cp_device_id",
    "identite_exacte_cp_device_id_dev_id",
    "identite_exacte_ty_cp_uuid",
})


class C9CBackendError(ValueError):
    """Only fixed tokens; never embed a vendor exception or private value."""


def _private_string(value: object, maximum: int = 8192) -> bool:
    return (isinstance(value, str) and
            1 <= len(value) <= maximum and
            value == value.strip() and value.isprintable())


@dataclass(repr=False)
class PreparedThing4Backend:
    """Ephemeral SDK objects. Must never be exposed in HA service output."""

    _config: Any = field(repr=False)
    _mqtt: Any = field(repr=False)
    _uid: str = field(repr=False)
    _media: Any = field(repr=False)
    _selection: str = field(repr=False)

    def __repr__(self) -> str:
        return "<PreparedThing4Backend redacted>"

    def safe_status(self) -> dict[str, object]:
        return {
            "diagnostic": "aosu_c9c_backend_python_p2p_v1",
            "etat": "session_sdk_preparee_non_connectee",
            "identite_exacte": self._selection in _ALLOWED_SELECTIONS,
            "sdk_python_transport_disponible": True,
            "connexion_effectuee": False,
            "video_confirmee": False,
            "appels_reseau": 0,
            "commandes_camera": 0,
            "identifiants_retournes": False,
            "secrets_retournes": False,
        }


def build_verified_sdk_backend(
    *, media: Any, tuya_session: Any, install_id: str,
    apk_identity: Any, signer: Any,
    aosu_sn: str, aosu_cp_device_id: str | None,
    aosu_ty_cp_uuid: str | None,
    inventory: dict[str, dict],
    standalone_c9c: bool,
    sdk_types: tuple[type, type] | None = None,
    identity_factory: Callable[..., Any] | None = None,
) -> PreparedThing4Backend:
    """Adapt existing signed Tuya login and RTC to an *actual* SDK StreamConfig.

    Fail closed BEFORE constructing any MQTT or RTC session when AOSU<->Tuya
    identity is ambiguous. Nothing in this function contacts a server.
    """
    if standalone_c9c is not True or not _private_string(aosu_sn, 256):
        raise C9CBackendError("c9c_cible_non_autorisee")
    if not isinstance(inventory, dict) or not 1 <= len(inventory) <= 100:
        raise C9CBackendError("c9c_inventaire_absent")
    target, classification = select_tuya_standalone_target_typed(
        inventory,
        camera_sn=aosu_sn,
        camera_cp_device_id=aosu_cp_device_id,
        camera_ty_cp_uuid=aosu_ty_cp_uuid)
    if target is None or classification not in _ALLOWED_SELECTIONS:
        raise C9CBackendError("c9c_identite_tuya_non_prouvee")
    if not (_private_string(getattr(media, "device_id", None), 128)
            and target == media.device_id
            and _private_string(getattr(media, "owner_uid", None), 256)
            and media.owner_uid == getattr(tuya_session, "uid", None)
            and getattr(media, "is_fresh", lambda: False)() is True):
        raise C9CBackendError("c9c_session_ou_cible_incoherente")
    key = getattr(media, "local_key", None)
    media_key = getattr(media, "aes_key", None)
    relay = getattr(media, "relay", None)
    if (not isinstance(key, str) or len(key.encode("utf-8")) not in (16, 24, 32)
            or not isinstance(media_key, bytes) or len(media_key) != 16
            or not isinstance(relay, dict)
            or not _private_string(relay.get("username"), 512)
            or not _private_string(relay.get("credential"), 8192)
            or not _private_string(relay.get("sessionId"), 512)
            or not any(isinstance(relay.get(k), list) and relay[k] for k in ("urls", "urlsEx"))
            or not _private_string(getattr(media, "session_id", None), 512)
            or not _private_string(getattr(media, "ice_ufrag", None), 512)
            or not _private_string(getattr(media, "ice_password", None), 512)
            or not _private_string(getattr(media, "device_password", None), 2048)):
        raise C9CBackendError("c9c_rtc_sdk_incomplet")
    if not isinstance(getattr(media, "ice_servers", None), list) or len(media.ice_servers) > 30:
        raise C9CBackendError("c9c_rtc_sdk_incomplet")
    if not _private_string(install_id, 256):
        raise C9CBackendError("c9c_installation_absente")

    if sdk_types is None:
        try:
            from tuya_ipc_p2p_sdk.models import MqttIdentity, StreamConfig
        except ImportError as exc:
            raise C9CBackendError("c9c_sdk_python_non_installe") from None
    else:
        MqttIdentity, StreamConfig = sdk_types

    if identity_factory is None:
        from .tuya_mqtt_signaling import _BROKER, _PORT, _identity
        identity_factory = _identity
    else:
        # Test doubles must still use the known EU broker, never an arbitrary
        # endpoint supplied by inventory metadata.
        from .tuya_mqtt_signaling import _BROKER, _PORT

    auth = identity_factory(
        apk_identity, signer, tuya_session, install_id, media.device_id)
    if not all(_private_string(getattr(auth, k, None), 2048)
               for k in ("client_id", "username", "password")):
        raise C9CBackendError("c9c_identite_mqtt_incomplete")

    # StreamConfig.from_json parses an IPC RTC config. We supply the same
    # values held in volatile PrivateMediaBootstrap, not guessed defaults.
    source = {
        "password": media.device_password,
        "motoId": media.moto_id if isinstance(media.moto_id, str) else "",
        "p2pConfig": {
            "session": {
                "sessionId": media.session_id,
                "aesKey": media_key.hex(),
                "iceUfrag": media.ice_ufrag,
                "icePassword": media.ice_password,
                "traceId": media.trace_id if isinstance(media.trace_id, str) else "",
            },
            "tcpRelay": dict(relay),
            "ices": list(media.ice_servers),
            "log": dict(media.log_config) if isinstance(media.log_config, dict) else {},
        },
    }
    try:
        config = StreamConfig.from_json(source, media.device_id, key)
        mqtt = MqttIdentity(
            host=_BROKER, port=_PORT,
            client_id=auth.client_id, username=auth.username,
            password=auth.password)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise C9CBackendError("c9c_rtc_sdk_incomplet") from None
    return PreparedThing4Backend(config, mqtt, media.owner_uid, media, classification)


async def run_one_explicit_sdk_session(
    prepared: PreparedThing4Backend,
    *, stop_event: asyncio.Event,
    on_frame: Callable[[bytes], None],
    explicit_owner_play: bool,
    sdk_session_factory: Callable[..., Any] | None = None,
) -> dict[str, object]:
    """Real StreamSession transport, intentionally NOT wired into UI/HA yet.

    Only a later reviewed Play integration may call this. No auto retries.
    Always call async_close() to issue SDK disconnect, even on an error.
    Vendor exception bodies are NEVER returned to HA.
    """
    if (not isinstance(prepared, PreparedThing4Backend)
            or explicit_owner_play is not True
            or not isinstance(stop_event, asyncio.Event)
            or not callable(on_frame)):
        raise C9CBackendError("c9c_action_active_non_autorisee")
    if stop_event.is_set():
        return _result("arret_demande_avant_connexion", False, 0, 0)
    if getattr(prepared._media, "is_fresh", lambda: False)() is not True:
        return _result("rtc_expire_avant_connexion", False, 0, 0)
    if sdk_session_factory is None:
        try:
            from tuya_ipc_p2p_sdk.stream_session import StreamSession
        except ImportError:
            raise C9CBackendError("c9c_sdk_python_non_installe") from None
        sdk_session_factory = StreamSession

    frames = 0

    def deliver_jpeg(jpeg: bytes) -> None:
        nonlocal frames
        if (not stop_event.is_set() and isinstance(jpeg, bytes)
                and 1024 <= len(jpeg) <= 3 * 1024 * 1024
                and jpeg.startswith(b"\xff\xd8") and jpeg.endswith(b"\xff\xd9")):
            frames = min(frames + 1, 1_000_000)
            on_frame(jpeg)

    # The SDK owns actual ICE, MQTT, relay, channel 0 and disconnect.
    # This bridge never claims that MQTT CONNACK alone proves video.
    session = sdk_session_factory(
        prepared._config, prepared._mqtt, prepared._uid, deliver_jpeg)
    established = False
    try:
        await session.async_start()
        established = True
        # Stop when user asks, transport ends, or the task is cancelled.
        # Avoid background reconnect or a second concurrent offer.
        stop_task = asyncio.create_task(stop_event.wait())
        ended_task = asyncio.create_task(session.async_wait_closed())
        try:
            done, _pending = await asyncio.wait(
                (stop_task, ended_task), return_when=asyncio.FIRST_COMPLETED)
            reason = "arret_utilisateur" if stop_task in done else "transport_termine"
        finally:
            for task in (stop_task, ended_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stop_task, ended_task, return_exceptions=True)
        return _result(reason, established, frames, 1)
    except asyncio.CancelledError:
        raise
    except Exception:
        # Upstream may embed hosts, user IDs or session IDs in exceptions.
        return _result("connexion_ou_transport_echoue", established, frames, 1)
    finally:
        try:
            await session.async_close()
        except Exception:
            # No exception body, raw media or identifiers are logged.
            pass


def _result(state: str, connected: bool, frames: int,
            attempts: int) -> dict[str, object]:
    return {
        "diagnostic": "aosu_c9c_python_sdk_transport_v1",
        "etat": state,
        # The SDK start finishes when a VIDEO KCP conversation is up;
        # native AOSU Thing-4 parity is still not independently proved.
        "session_sdk_video_ouverte": connected,
        "jpeg_recues": min(frames, 1_000_000),
        "video_visible_confirmee": frames > 0,
        "parite_sdk_aosu_native_prouvee": False,
        "tentatives_p2p": attempts,
        "tentatives_automatiques": 0,
        "identifiants_retournes": False,
        "secrets_retournes": False,
    }
