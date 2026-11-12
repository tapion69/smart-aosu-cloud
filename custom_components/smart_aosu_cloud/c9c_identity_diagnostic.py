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
                               select_standalone, select_tuya,
                               select_tuya_typed=None) -> dict:
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
    selected = select_standalone(data)
    if selected is None:
        return {**result, "etat": "topologie_c9c_non_unique"}
    # These fields come from the AOSU inventory already sanitized in memory.
    # svcType is a PTZ routing hint, *not* proof of the live-video backend.
    row = data.get(selected) if isinstance(data, dict) else None
    row = row if isinstance(row, dict) else {}
    platform = row.get("ptz_iot_platform")
    platform = platform if platform in ("Gz", "Ty") else "indeterminee"
    ref = row.get("ptz_tuya_reference_status")
    allowed_ref = ("racine_et_infos_concordantes", "racine_et_infos_differentes",
                   "racine_presente", "infos_seulement", "format_non_reconnu",
                   "absent", "indisponible")
    ref = ref if ref in allowed_ref else "indisponible"
    # Separate provider hints (sdkProvider/p2pType) are also cached at getList.
    # Never infer a provider from a product's name or the user device name.
    snapshot = getattr(client, "_provider_snapshot", None)
    provider_rows = snapshot.get("appareils") if isinstance(snapshot, dict) else None
    provider_row = (provider_rows[0] if isinstance(provider_rows, list)
                    and len(provider_rows) == 1 and isinstance(provider_rows[0], dict)
                    else {})
    provider = provider_row.get("sdk_provider_declare_nom")
    allowed_provider = ("TUTK", "THING", "THING_STATION", "FISHEYE",
                        "VIRTUAL", "INDETERMINE")
    provider = provider if provider in allowed_provider else "INDETERMINE"
    p2p_type = provider_row.get("p2p_type_declare")
    p2p_type = p2p_type if type(p2p_type) is int and 0 <= p2p_type <= 9 else "absent"
    result["aosu_routage_declare"] = {
        "branche_ptz": platform,
        "reference_tuya": ref,
        "fournisseur_p2p": provider,
        "p2p_type": p2p_type,
        "fournisseur_runtime_confirme": False,
        "video_c5l_compatible_confirmee": False,
    }
    sn = getattr(client, "_standalone_c9c_sn", None)
    coop = getattr(client, "_standalone_c9c_coop_id", None)
    sn = sn if isinstance(sn, str) and sn else None
    coop = coop if isinstance(coop, str) and coop else None
    ty_uuid = getattr(client, "_standalone_c9c_ty_cp_uuid", None)
    ty_uuid = ty_uuid if isinstance(ty_uuid, str) and ty_uuid else None
    result["identite_aosu"] = {
        "numero_serie_present": sn is not None,
        "coop_uuid_present": coop is not None,
        "ty_cp_uuid_present": ty_uuid is not None,
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
    sn_matches_tuya_id = 0
    details = []
    for dev_id, item in devices.items():
        objs = _objects(item)
        cats = _categories(item)
        # Some bridges use the AOSU SN as Tuya devId instead of a SN field.
        # This is *additional evidence only*, never a routing override.
        tuya_ids = [dev_id] + [obj.get(k) for obj in objs for k in _COOP_FIELDS]
        sn_matches_tuya_id += int(bool(sn) and any(
            isinstance(v, str) and v == sn for v in tuya_ids))
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
    # Read-only view may inspect a previously authenticated Tuya detail
    # entry. This is the ONLY comparison between AOSU's Ty cpUuid and Tuya's
    # own uuid, and it is never persisted or used to send a camera command.
    detail = getattr(client, "_c9c_reverse_uuid_cache", None)
    provenance = {
        "fiche_tuya_uuid_recente": False,
        "ty_cp_uuid_aosu_present": ty_uuid is not None,
        "uuid_tuya_present": False,
        "concordance_directe": False,
        "liaison_video_confirmee": False,
        "identifiants_retournes": False,
    }
    if (isinstance(detail, dict)
        and isinstance(cache.get("session_uid"), str)
        and detail.get("session_uid") == cache.get("session_uid")
        and isinstance(detail.get("created"), (int, float))
        and 0 <= time.monotonic() - detail["created"] <= 600
        and isinstance(detail.get("target"), str)
        and detail.get("target") in devices
        and isinstance(detail.get("candidates"), tuple)):
        provenance["fiche_tuya_uuid_recente"] = True
        uuid_refs = [row[1] for row in detail["candidates"][:5]
                     if isinstance(row, tuple) and len(row) == 2
                     and row[0] == "uuid_tuya" and isinstance(row[1], str)
                     and 1 <= len(row[1]) <= 256
                     and row[1] == row[1].strip()
                     and row[1].isprintable()]
        if len(uuid_refs) == 1:
            # Tuya UUID availability is independent of whether AOSU provided
            # its own cpUuid; never report a missing Tuya UUID by inference.
            provenance["uuid_tuya_present"] = True
            provenance["concordance_directe"] = (
                ty_uuid is not None and uuid_refs[0] == ty_uuid)
    result["comparaison_ty_cp_uuid"] = provenance
    if select_tuya_typed is not None:
        target, method = select_tuya_typed(
            devices, camera_sn=sn,
            camera_cp_device_id=coop,
            camera_ty_cp_uuid=ty_uuid)
    else:
        target, method = select_tuya(devices, camera_sn=sn, camera_coop=coop)
    allowed_methods = (
        "identite_exacte", "identite_exacte_serie",
        "identite_exacte_cp_device_id", "identite_exacte_ty_cp_uuid",
        "correspondance_ambigue",
        "camera_tuya_unique_non_confirmee",
        "cameras_tuya_multiples_ambigues",
        "appareil_tuya_unique_sans_categorie_video",
        "appareil_tuya_unique_categorie_non_video",
        "appareil_tuya_unique_invalide",
        "aucune_camera_tuya_identifiable", "inventaire_tuya_absent",
    )
    method = method if method in allowed_methods else "autre_methode"
    exact = target is not None and method in (
        "identite_exacte", "identite_exacte_serie",
        "identite_exacte_cp_device_id", "identite_exacte_ty_cp_uuid")
    result["correspondance"] = {
        "serie_exacte_nombre": strong_sn,
        "serie_egale_id_tuya_nombre": sn_matches_tuya_id,
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
