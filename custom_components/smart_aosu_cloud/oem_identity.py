"""AOSU -> Tuya OEM UID identity hand-off; NO network, no signing.

The AOSU Android 5.10.12 app uses LoginWebData.tuyaUserName,
LoginWebData.countryCode and the AOSU login password for Tuya's SDK UID login.
DEX class LoginWebData field tuyaUserName has Gson @SerializedName("tuyaUsername").
The AOSU JSON WIRE NAME is tuyaUsername, NOT tuyaUserName.
This file extracts only the account hints already present in a successful AOSU
login response. It must never expose them in HA diagnostics or logging.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, repr=False)
class OemIdentityHints:
    country_code: str = field(repr=False)
    tuya_username: str = field(repr=False)
    tuya_uid: str | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "OemIdentityHints(<redacted>)"

    def __str__(self) -> str:
        return repr(self)


# Exact JSON serialized names verified from APK classes12.dex field annotation.
_JSON_TUYA_USERNAME = "tuyaUsername"


def _code(raw: Any) -> str | None:
    if type(raw) is int:
        raw = str(raw)
    if not isinstance(raw, str) or not raw.isascii() or not raw.isdigit():
        return None
    return raw if 1 <= len(raw) <= 4 else None


def _uid_str(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw) > 256:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        return None
    return raw


def extract_login_hints(login_data: object) -> OemIdentityHints | None:
    """Extract if *both* login UID fields are available, else return None.

    Caller passes the `data` object of an already validated AOSU login, never
    the whole response, and never a remote-supplied field of a different name.
    """
    if not isinstance(login_data, dict):
        return None
    cc = _code(login_data.get('countryCode'))
    username = _uid_str(login_data.get(_JSON_TUYA_USERNAME))
    tuya_uid = _uid_str(login_data.get('tuyaUid'))
    return OemIdentityHints(cc, username, tuya_uid) if cc and username else None


def inspect_login_hints(login_data: object) -> dict[str, object]:
    """Display-only flags: no values, lengths, hashes, dynamic server keys.

    This is intentionally not equivalent to an authenticated Tuya session.
    """
    if not isinstance(login_data, dict):
        return {"etat": "donnees_indisponibles", "country_code_present": False,
                "tuya_username_present": False, "tuya_uid_present": False,
                "uid_fields_ready": False,
                "oem_login_possible": False, "session_tuya_authentifiee": False}
    cc = _code(login_data.get('countryCode')) is not None
    un = _uid_str(login_data.get(_JSON_TUYA_USERNAME)) is not None
    uid = _uid_str(login_data.get('tuyaUid')) is not None
    return {"etat": "champs_verifies", "country_code_present": cc,
            "tuya_username_present": un, "tuya_uid_present": uid,
            "uid_fields_ready": bool(cc and un),
            "oem_login_possible": False, "session_tuya_authentifiee": False}


def not_logged_in_report() -> dict[str, object]:
    return {"etat": "login_aosu_non_observe_depuis_demarrage",
            "country_code_present": False, "tuya_username_present": False,
            "tuya_uid_present": False, "uid_fields_ready": False, "oem_login_possible": False,
            "session_tuya_authentifiee": False, "requete_reseau": 0,
            "reconnexion_forcee": False, "commande_camera": 0}


def public_report(status: dict[str, object] | None) -> dict[str, object]:
    if status is None:
        return not_logged_in_report()
    # Reconstruct fixed output rather than returning a potentially mutable raw
    # dictionary that a future caller may have extended with private metadata.
    return {"etat": status.get("etat") if status.get("etat") in {
                "champs_verifies", "donnees_indisponibles"} else "donnees_indisponibles",
            "country_code_present": status.get("country_code_present") is True,
            "tuya_username_present": status.get("tuya_username_present") is True,
            "tuya_uid_present": status.get("tuya_uid_present") is True,
            "uid_fields_ready": bool(status.get("country_code_present") is True
                                     and status.get("tuya_username_present") is True),
            "oem_login_possible": False, "session_tuya_authentifiee": False,
            "requete_reseau": 0, "reconnexion_forcee": False,
            "commande_camera": 0}
