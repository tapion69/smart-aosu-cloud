"""Read-only evidence from an EXISTING, explicitly started C9C MQTT connection.

No network access. This module is a protocol-verification boundary between
incoming untrusted MQTT packets and the future Thing-4 session lifecycle.

The transport is not SDK-native. A validated SDP answer is not proof of P2P
authentication, media decoding, or video. No identifiers or SDP leave this
module's fixed-status output.
"""
from __future__ import annotations
from dataclasses import dataclass, field


def _bounded_id(value: object) -> bool:
    return (isinstance(value, str) and
            1 <= len(value) <= 256 and
            value == value.strip() and value.isprintable()
            and not any(ch.isspace() for ch in value))


def _compatible_sdp(value: object) -> bool:
    """Only coarse AES/KCP/ICE structure; NOT native or cryptographic parity."""
    return (isinstance(value, str) and
            32 <= len(value) <= 16384 and
            value.startswith("v=0") and
            "AES/KCP" in value and
            "a=ice-ufrag:" in value and
            "a=ice-pwd:" in value)


@dataclass(repr=False)
class C9CMqttSessionEvidence:
    """C9C-only: accept signals for our EXACT camera, user and offer session."""

    _device: str = field(repr=False)
    _user: str = field(repr=False)
    _session: str = field(repr=False)
    _offer_sent: bool = False
    _puback: bool = False
    _answer_validated: bool = False
    _candidate_count: int = 0
    _other_session_count: int = 0
    _untrusted_sender_count: int = 0
    _malformed_answer_count: int = 0
    _disconnect_seen: bool = False

    def __post_init__(self) -> None:
        if not all(_bounded_id(v) for v in
                   (self._device, self._user, self._session)):
            raise ValueError("c9c_mqtt_contexte_invalide")

    def mark_offer_sent(self) -> None:
        self._offer_sent = True

    def mark_puback(self, packet_id: object) -> None:
        # Only QoS1 PUBACK for the PUBLISH that contained our SDP offer.
        if self._offer_sent and type(packet_id) is int and packet_id == 11:
            self._puback = True

    def classify(self, protocol: object, header: object, msg: object) -> str:
        """Fixed enum; never returns nor serializes arbitrary incoming fields."""
        if not self._offer_sent:
            return "offre_non_envoyee"
        if type(protocol) is not int or protocol != 302:
            return "protocole_non_302"
        if not isinstance(header, dict) or not isinstance(msg, dict):
            return "format_invalide"
        if header.get("sessionid") != self._session:
            self._other_session_count = min(100, self._other_session_count + 1)
            return "autre_session"
        kind = header.get("type")
        if kind not in ("answer", "candidate", "disconnect"):
            return "type_non_pertinent"
        # Strong provenance rule: correct session alone is NOT enough.
        if (header.get("from") != self._device or
                header.get("to") != self._user):
            self._untrusted_sender_count = min(
                100, self._untrusted_sender_count + 1)
            return "origine_ou_destination_incorrecte"
        if kind == "disconnect":
            self._disconnect_seen = True
            return "deconnexion_confirmee"
        if kind == "candidate":
            candidate = msg.get("candidate")
            if not isinstance(candidate, str) or not 1 <= len(candidate) <= 4096:
                return "candidat_invalide"
            self._candidate_count = min(100, self._candidate_count + 1)
            return "candidat_confirme"
        if not _compatible_sdp(msg.get("sdp")):
            self._malformed_answer_count = min(
                100, self._malformed_answer_count + 1)
            return "reponse_sdp_incompatible"
        self._answer_validated = True
        return "reponse_sdp_liee_a_notre_session"

    def safe_status(self) -> dict[str, object]:
        """Strictly fixed labels/booleans/bounded counts; no device IDs."""
        return {
            "diagnostic": "aosu_c9c_mqtt_observateur_session_v1",
            "offre_emise": self._offer_sent,
            "puback_broker": self._puback,
            "reponse_sdp_origine_verifiee": self._answer_validated,
            "candidats_origine_verifiee": self._candidate_count,
            "reponses_autre_session": self._other_session_count,
            "reponses_origine_invalide": self._untrusted_sender_count,
            "reponses_sdp_incompatibles": self._malformed_answer_count,
            "deconnexion_distante_confirmee": self._disconnect_seen,
            "connexion_p2p_authentifiee": False,
            "image_decodee": False,
            "video_confirmee": False,
            "SDK_Thing4_initialise": False,
            "requete_reseau_supplementaire": 0,
            "commandes_camera_supplementaires": 0,
            "identifiants_retournes": False,
            "secrets_retournes": False,
        }
