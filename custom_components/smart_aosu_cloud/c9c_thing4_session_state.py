"""Pure, non-network C9C Thing-4 session lifecycle.

A C9C session is NOT connected because a MQTT PUBACK or HTTP success exists.
This state machine does not implement the proprietary Android SDK, construct
offers, authenticate, transmit, launch video, store files, or infer identity.
It is an adapter boundary for a future verified, portable P2P transport.

The session and device identifiers remain ephemeral and hidden from repr,
snapshots, exceptions and logs. Legacy C5L and H1L paths do not use it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import time


_EXACT_SELECTION = frozenset({
    "identite_exacte_serie",
    "identite_exacte_cp_device_id",
    "identite_exacte_cp_device_id_dev_id",
    "identite_exacte_ty_cp_uuid",
})
_SESSION_TTL_SECONDS = 90.0


class Phase(str, Enum):
    NEW = "nouvelle"
    IDENTIFIED = "identite_verifiee"
    CONFIGURED = "configuration_verifiee"
    DEVICE_CREATED = "peripherique_p2p_cree"
    CONNECTING = "connexion_en_cours"
    OFFER_SENT = "offre_emise"
    ANSWER_RECEIVED = "reponse_sdp_recue"
    CONNECTED = "connexion_p2p_confirmee"
    STREAMING = "premiere_image_recue"
    STOPPED = "arretee"
    FAILED = "echec"


class SessionStateError(ValueError):
    """Fixed error tokens only. Never attach vendor data or identifiers."""


def _private_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 5 <= len(value) <= 128
        and value == value.strip()
        and value.isascii()
        and value.isprintable()
        and not any(ch.isspace() for ch in value)
    )


@dataclass(repr=False)
class Thing4C9CSession:
    """Sequence monitor only. Callers must provide REAL transport callbacks.

    No class method opens a network connection or sends an offer. A real,
    independent P2P adapter is required before this object can progress
    past DEVICE_CREATED; do not synthesize success callbacks from HTTP
    acceptance, MQTT PUBACK or mere CameraInfoBean field presence.
    """

    phase: Phase = Phase.NEW
    _device_id: str | None = field(default=None, repr=False)
    _session_id: str | None = field(default=None, repr=False)
    _deadline: float | None = field(default=None, repr=False)
    _answer_seen: bool = field(default=False, repr=False)
    _connected_seen: bool = field(default=False, repr=False)
    _frames_seen: int = field(default=0, repr=False)
    _ack_seen: bool = field(default=False, repr=False)

    def _require(self, *phases: Phase) -> None:
        if self.phase not in phases:
            raise SessionStateError("transition_interdite")

    def _require_fresh(self, now: float | None = None) -> None:
        at = time.monotonic() if now is None else now
        if self._deadline is None or at >= self._deadline:
            self.fail("configuration_expiree")
            raise SessionStateError("configuration_expiree")

    def bind(self, *, tuya_device_id: str, selection: str, aosu_c9c_unique: bool) -> None:
        """Accept only an explicitly *typed* AOSU→Tuya exact match."""
        self._require(Phase.NEW)
        if (aosu_c9c_unique is not True or
                selection not in _EXACT_SELECTION or
                not _private_id(tuya_device_id)):
            raise SessionStateError("identite_c9c_non_prouvee")
        self._device_id = tuya_device_id
        self.phase = Phase.IDENTIFIED

    def configure(self, *, rtc_device_id: str, session_id: str,
                  p2p_specified_type: int, local_key_present: bool,
                  config_present: bool, now: float | None = None) -> None:
        """Validate RTC ownership and lifetime; no network or SDP generated."""
        self._require(Phase.IDENTIFIED)
        if (rtc_device_id != self._device_id or
                type(p2p_specified_type) is not int or p2p_specified_type != 4 or
                local_key_present is not True or config_present is not True or
                not _private_id(session_id)):
            raise SessionStateError("configuration_c9c_non_conforme")
        self._session_id = session_id
        self._deadline = (time.monotonic() if now is None else now) + _SESSION_TTL_SECONDS
        self.phase = Phase.CONFIGURED

    def on_device_created(self, *, success: bool, now: float | None = None) -> None:
        """Invoke solely after a REAL SDK-compatible create-device callback."""
        self._require(Phase.CONFIGURED)
        self._require_fresh(now)
        if success is not True:
            self.fail("creation_peripherique_echouee")
            return
        self.phase = Phase.DEVICE_CREATED

    def on_connect_started(self, *, now: float | None = None) -> None:
        self._require(Phase.DEVICE_CREATED)
        self._require_fresh(now)
        self.phase = Phase.CONNECTING

    def on_offer_sent(self, *, now: float | None = None) -> None:
        self._require(Phase.CONNECTING)
        self._require_fresh(now)
        self.phase = Phase.OFFER_SENT

    def on_mqtt_puback(self) -> None:
        """PUBACK is broker delivery, never proof of camera or SDP answer."""
        self._require(Phase.OFFER_SENT, Phase.ANSWER_RECEIVED, Phase.CONNECTED)
        self._ack_seen = True

    def on_sdp_answer(self, *, from_device_id: str, session_id: str,
                      validated: bool, now: float | None = None) -> None:
        """Accept a *validated* answer for exactly our own fresh session."""
        self._require(Phase.OFFER_SENT, Phase.CONNECTING)
        self._require_fresh(now)
        if (validated is not True or from_device_id != self._device_id
                or session_id != self._session_id):
            raise SessionStateError("reponse_sdp_non_associee")
        self._answer_seen = True
        self.phase = Phase.CONNECTED if self._connected_seen else Phase.ANSWER_RECEIVED

    def on_connect_confirmed(self, *, authenticated: bool,
                             now: float | None = None) -> None:
        """Only real P2P connector callback after channel authorization."""
        self._require(Phase.CONNECTING, Phase.OFFER_SENT, Phase.ANSWER_RECEIVED)
        self._require_fresh(now)
        if authenticated is not True:
            self.fail("connexion_non_authentifiee")
            return
        self._connected_seen = True
        if self._answer_seen:
            self.phase = Phase.CONNECTED

    def on_media_frame(self, *, decoded: bool, now: float | None = None) -> None:
        """Video is proved only after an actual decoded frame, not stream start."""
        self._require(Phase.CONNECTED, Phase.STREAMING)
        self._require_fresh(now)
        if decoded is not True:
            raise SessionStateError("image_non_decodee")
        self._frames_seen += 1
        self.phase = Phase.STREAMING

    def fail(self, reason: str = "echec") -> None:
        # The reason is deliberately not persisted or exposed.
        self._clear()
        self.phase = Phase.FAILED

    def stop(self) -> None:
        self._clear()
        self.phase = Phase.STOPPED

    def _clear(self) -> None:
        self._device_id = None
        self._session_id = None
        self._deadline = None
        self._answer_seen = False
        self._connected_seen = False

    def safe_status(self) -> dict[str, object]:
        """Stable whitelisted status fields: no SN, UID, devId, tokens or SDP."""
        return {
            "diagnostic": "aosu_c9c_thing4_session_lifecycle_v1",
            "phase": self.phase.value,
            "cible_exacte_verifiee": self._device_id is not None,
            "reponse_sdp_validee": self._answer_seen,
            "connexion_authentifiee": self._connected_seen,
            "broker_puback_observe": self._ack_seen,
            "au_moins_une_image_decodee": self._frames_seen > 0,
            "video_confirmee": self.phase is Phase.STREAMING,
            "transport_reel_implemente": False,
            "appels_reseau": 0,
            "commandes_camera": 0,
            "identifiants_retournes": False,
            "secrets_retournes": False,
        }
