"""Global privacy-limited Smart AOSU read-only diagnostic.

Works from the existing normalized getList cache and whitelisted metadata.
Never returns serials, device keys, custom names, account details, image URLs,
notification payloads or raw cloud JSON. No network calls are made here.
"""
from __future__ import annotations

from datetime import datetime, timezone
import math

KNOWN_MODELS = frozenset({"H1L", "C5L", "C9C3CA11"})


def _numeric(value):
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    if abs(value) > 1_000_000:
        return None
    return value


def _cloud_status(value):
    if type(value) not in (int, float):
        return "inconnu"
    return {1: "connecte", 0: "deconnecte"}.get(value, "code_non_interprete")


def _whitelisted_model(value):
    return value if isinstance(value, str) and value in KNOWN_MODELS else "autre_ou_inconnu"


def _whitelisted_power_mode(value):
    # Do not echo strings copied from an untrusted cloud response.
    return value if isinstance(value, str) and value in ("0", "1") else "non_interprete"


def _event_summary(value, now):
    if not isinstance(value, datetime) or value.tzinfo is None:
        return {"horodatage_valide": False, "age_minutes": None}
    delta = (now - value).total_seconds()
    if delta < -600 or delta > 12 * 365 * 24 * 3600:
        return {"horodatage_valide": False, "age_minutes": None}
    return {"horodatage_valide": True, "age_minutes": max(0, int(delta // 60))}


def summarize_global_inventory(devices, safe_metadata, *, now=None):
    """Return a shareable full inventory without identifiers or arbitrary values."""
    if not isinstance(devices, dict) or not isinstance(safe_metadata, dict):
        raise ValueError("Inventaire normalise ou metadonnees indisponibles")
    if len(devices) > 25:
        raise ValueError("Trop d'appareils pour le diagnostic")
    if now is None:
        now = datetime.now(tz=timezone.utc)

    keys = list(devices)
    index = {key: i for i, key in enumerate(keys, 1)}
    reports = []
    for i, key in enumerate(keys, 1):
        d = devices[key]
        if not isinstance(d, dict):
            continue
        # The list order is temporary, never used as entity ID.
        parent = d.get("via_device")
        item = {
            "numero_temporaire": i,
            "modele": _whitelisted_model(d.get("model")),
            "role": "base" if _whitelisted_model(d.get("model")) == "H1L" else "camera_ou_appareil",
            "connexion": _cloud_status(d.get("online")),
            "online_code_brut": _numeric(d.get("online")),
            "type_code_brut": _numeric(d.get("device_type")),
            "base_numero_temporaire": index.get(parent) if parent else None,
            "energie_brute": _numeric(d.get("electricity")),
            "wifi_brut": _numeric(d.get("wifi_signal")),
            "mode_alimentation_code": _whitelisted_power_mode(d.get("power_mode")),
            "couverture_evenement": _event_summary(d.get("cover_event_time"), now),
        }
        reports.append(item)

    # The metadata summary was already sanitized against a *fixed* whitelist
    # during inventory polling. We allow only narrowly selected boolean/count
    # facts from it, never arbitrary field names or values.
    meta_devices = safe_metadata.get("appareils", [])
    structures = []
    if isinstance(meta_devices, list):
        for record in meta_devices[:25]:
            if not isinstance(record, dict):
                continue
            ix = record.get("numero_temporaire")
            if type(ix) is not int or not 1 <= ix <= len(devices):
                continue
            groups = record.get("groupes", {})
            if not isinstance(groups, dict):
                groups = {}
            app = groups.get("appSetting", {})
            cover = groups.get("coverInfo", {})
            support = groups.get("support", {})
            snooze = app.get("snooze", {}) if isinstance(app, dict) else {}
            contract = support.get("contractInfo", {}) if isinstance(support, dict) else {}
            def count_of(node):
                n = node.get("nombre") if isinstance(node, dict) else None
                return n if type(n) is int and 0 <= n <= 10000 else None
            structures.append({
                "numero_temporaire": ix,
                "miniature_reference_presente": record.get("miniature_reference_presente") is True,
                "ai_vision_renseigne": count_of(cover.get("aiVision")) not in (None, 0) if isinstance(cover, dict) else False,
                "video_info_renseigne": count_of(cover.get("videoInfo")) not in (None, 0) if isinstance(cover, dict) else False,
                "level_info_renseigne": count_of(cover.get("levelInfo")) not in (None, 0) if isinstance(cover, dict) else False,
                "snooze_liste_taille": count_of(snooze),
                "contrat_champs_nombre": count_of(contract),
            })

    connected = sum(x["connexion"] == "connecte" for x in reports)
    cameras = sum(x["modele"] in ("C5L", "C9C3CA11") for x in reports)
    parent_links = sum(x["base_numero_temporaire"] is not None for x in reports)
    return {
        "resultat": "audit_global_aosu",
        "mode": "lecture_seule",
        "confidentialite": "Aucun numero de serie, nom prive, URL image, SID, UID, mot de passe ni jeton",
        "inventaire": {
            "endpoint": "/v1/dev/getList",
            "nombre_appareils": len(reports),
            "modeles_reconnus_cameras": cameras,
            "connectes": connected,
            "liens_vers_base": parent_links,
            "appareils": reports,
        },
        "metadonnees": structures,
        "fonctions_non_validees": [
            "unites_et_signification_exactes_energie_wifi_alimentation",
            "classement_personne_mouvement_sonnette",
            "reglages_detection_eclairage_alarme",
            "miniatures_accessibles_sans_exposer_url",
            "video_direct_p2p",
        ],
    }


def safe_dp_summary(result):
    """Condense the existing DP diagnostic to fixed, privacy-safe fields."""
    if not isinstance(result, dict):
        return {"etat": "reponse_non_reconnue"}
    if result.get("type_data") == "object" and result.get("resultat") == "structure_a_etudier":
        structure = result.get("structure")
        if isinstance(structure, list) and structure:
            first = structure[0]
            if isinstance(first, dict) and first.get("nombre_elements") == 0:
                return {"etat": "reponse_valide_mais_vide", "type_data": "objet", "nombre_dp": 0}
    if result.get("resultat") == "lecture_reussie":
        values = result.get("noms_dp", [])
        safe_codes = []
        if isinstance(values, list):
            for item in values[:80]:
                if isinstance(item, dict):
                    code = item.get("dp")
                    kind = item.get("type")
                    # Only numeric codes, no free text, even if upstream changes.
                    if isinstance(code, str) and code.isascii() and code.isdecimal() and len(code) <= 4 and kind in ("number","string","object","array","bool","null"):
                        safe_codes.append({"code": code, "type": kind})
        return {"etat": "parametres_recus", "nombre_dp": len(values) if isinstance(values,list) else 0,
                "codes_numeriques": safe_codes}
    return {"etat": "reponse_non_interpretee"}
