"""Read-only C9C AOSU/Tuya identity evidence from in-memory caches.

Only fixed booleans, counters and local status tokens are returned. Never
expose device IDs, serial numbers, names, local keys, SDP, sessions or tokens.
This module performs no network calls, camera commands or filesystem writes.
"""
from __future__ import annotations

import time
from typing import Any

_VIDEO = frozenset(("sp", "ipc", "camera", "smart_camera"))
_NON_VIDEO = frozenset(("gw", "gateway", "hub", "switch", "socket",
                        "sensor", "light", "zigbee", "plug", "cz",
                        "kg", "dj", "cl", "pir", "wsdcg"))
_SN_FIELDS = ("sn", "deviceSn", "serialNumber", "serialNo")
_COOP_FIELDS = ("devId", "deviceId", "uuid", "devUuid",
                "deviceUuid", "cpDeviceId")
_MODEL_FIELDS = ("model", "productModel", "modelName", "productType",
                 "deviceModel", "productName")
_CONTAINERS = ("productBean", "product", "productInfo",
               "deviceBean", "deviceInfo")


def _objects(item: Any) -> list[dict]:
    if not isinstance(item, dict):
        return []
    return [item] + [item[k] for k in _CONTAINERS
                     if isinstance(item.get(k), dict)]


def _categories(item: Any) -> set[str]:
    return {obj["category"].strip().lower()
            for obj in _objects(item)
            if isinstance(obj.get("category"), str)
            and obj["category"].strip()}


def _exact(objects: list[dict], fields: tuple[str, ...],
           expected: str | None) -> bool:
    return bool(expected) and any(
        obj.get(key) == expected for obj in objects for key in fields)


def inspect_c9c_identity_cache(*, data: Any, client: Any, cache: Any,
                               select_standalone, select_tuya) -> dict:
    """Classify matching evidence; uniqueness does not prove device identity."""
    result = {
        "diagnostic": "aosu_c9c_identite_cache_b5",
        "lecture_seule": True,
        "appels_reseau": 0,
        "commandes_camera": 0,
        "commandes_ptz": 0,
        "identifiants_retournes": False,
        "secrets_retournes": False,
        "video_lancee": False,
        "comparaison_protocole": {
            "video_c5l": "mqtt_offre_302",
            "video_c9c_essai": "mqtt_offre_302",
            "voie_h1l": False,
            "compatibilite_video_prouvee": False,
        },
    }
    if select_standalone(data) is None:
        return {**result, "etat": "topologie_c9c_non_unique"}
    sn = getattr(client, "_standalone_c9c_sn", None)
    coop = getattr(client, "_standalone_c9c_coop_id", None)
    sn = sn if isinstance(sn, str) and sn else None
    coop = coop if isinstance(coop, str) and coop else None
    result["identite_aosu"] = {
        "numero_serie_present": sn is not None,
        "coop_uuid_present": coop is not None,
    }
    if not isinstance(cache, dict) or not isinstance(cache.get("devices"), dict):
        return {**result, "etat": "inventaire_tuya_non_charge"}
    devices = cache["devices"]
    created = cache.get("created")
    try:
        age = max(0, min(86400, int(time.monotonic() - float(created))))
    except (ValueError, TypeError, OverflowError):
        age = None
    result["cache_tuya"] = {
        "present": True,
        "age_secondes": age,
        "recent": age is not None and age <= 600,
        "appareils": min(len(devices), 100),
    }
    if not devices or len(devices) > 100:
        return {**result, "etat": "inventaire_tuya_vide_ou_trop_large"}
    strong_sn = 0
    strong_coop = 0
    all_video = 0
    details = []
    for item in devices.values():
        objs = _objects(item)
        cats = _categories(item)
        strong_sn += int(_exact(objs, _SN_FIELDS, sn))
        strong_coop += int(_exact(objs, _COOP_FIELDS, coop))
        all_video += int(bool(cats & _VIDEO))
        if len(devices) == 1:
            details = [{
                "categorie_video_reconnue": bool(cats & _VIDEO),
                "categorie_explicitement_non_video": bool(cats & _NON_VIDEO),
                "categorie_absente": not bool(cats),
                "categorie_autre": bool(cats) and not bool(cats & (_VIDEO | _NON_VIDEO)),
                "product_bean_present": isinstance(item.get("productBean"), dict)
                    if isinstance(item, dict) else False,
                "modele_c9c_annonce": any(
                    str(obj.get(field) or "").strip().upper() == "C9C"
                    for obj in objs for field in _MODEL_FIELDS),
                "modele_present": any(
                    isinstance(obj.get(field), str) and bool(obj[field])
                    for obj in objs for field in _MODEL_FIELDS),
                "nom_present": any(
                    isinstance(obj.get("name"), str) and bool(obj["name"])
                    for obj in objs),
                "cle_locale_presente": any(
                    isinstance(obj.get("localKey"), str) and bool(obj["localKey"])
                    for obj in objs),
            }]
    target, method = select_tuya(devices, camera_sn=sn, camera_coop=coop)
    allowed_methods = (
        "identite_exacte", "correspondance_ambigue",
        "camera_tuya_unique_non_confirmee",
        "cameras_tuya_multiples_ambigues",
        "appareil_tuya_unique_sans_categorie_video",
        "appareil_tuya_unique_categorie_non_video",
        "appareil_tuya_unique_invalide",
        "aucune_camera_tuya_identifiable", "inventaire_tuya_absent",
    )
    method = method if method in allowed_methods else "autre_methode"
    exact = target is not None and method == "identite_exacte"
    result["correspondance"] = {
        "serie_exacte_nombre": strong_sn,
        "coop_exact_nombre": strong_coop,
        "cameras_tuya_reconnues": all_video,
        "selection_rtc": method,
        "selection_possible": target is not None,
        "identite_exacte_confirmee": exact,
        "uniquement_hypothese": target is not None and not exact,
    }
    if details:
        result["unique_appareil_tuya"] = details[0]
    result["etat"] = ("identite_exacte_confirmee" if exact else
                      "identite_non_prouvee" if target is not None else
                      "selection_impossible")
    return result
