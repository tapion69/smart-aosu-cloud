"""Pure RAM-only comparison of an official-app C9C serial with the AOSU cache.

Never persist, print, log, hash, expose, or send either serial over the network.
An app/AOSU-cache match does NOT establish the separate AOSU↔Tuya device link.
"""
from __future__ import annotations


def _valid_sn(sn: object) -> bool:
    return (isinstance(sn, str) and 5 <= len(sn) <= 128
            and sn == sn.strip() and sn.isascii() and sn.isprintable())


def compare_app_sn_locally(app_sn: object, cloud_sn: object) -> dict[str, object]:
    """Return only fixed status labels / booleans, never the supplied serial."""
    result: dict[str, object] = {
        "diagnostic": "c9c_sn_application_comparaison_locale_b44rc2",
        "etat": "sn_non_verifie",
        "sn_aosu_cache_present": _valid_sn(cloud_sn),
        "sn_application_correspond": False,
        "identite_aosu_tuya_etablie_par_ce_test": False,
        "appels_reseau": 0,
        "offres_http_envoyees": 0,
        "offres_mqtt_envoyees": 0,
        "video_lancee": False,
        "commandes_ptz": 0,
        "commandes_camera": 0,
        "identifiants_retournes": False,
        "secrets_retournes": False,
    }
    if not _valid_sn(app_sn):
        result["etat"] = "sn_application_invalide"
    elif not _valid_sn(cloud_sn):
        result["etat"] = "sn_aosu_cache_indisponible"
    elif app_sn == cloud_sn:
        result["etat"] = "sn_application_egal_aosu"
        result["sn_application_correspond"] = True
    else:
        result["etat"] = "sn_application_different_aosu"
    return result
