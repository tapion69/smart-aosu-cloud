"""B98: cache-only bridge audit for child C9 cameras and an H1L station.

Never initiates Tuya login, RTC configuration, MQTT, video or PTZ. The only
private inputs (AOSU serials and OEM Tuya DeviceBeans) stay in volatile memory.
The result contains *only* whitelisted model names, booleans and counts.
Model agreement by itself is not an identity match: two C9 units may share one
model and a station may use a different SDK entity from the AOSU base.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

_MODELS = frozenset({"C9C3CA11", "H1L", "C5L"})
_SERIAL_FIELDS = ("sn", "deviceSn", "serialNumber", "serialNo", "devSn")
_NESTED_FIELDS = ("productBean", "product", "productInfo", "deviceBean", "deviceInfo")
_PARENT_FIELDS = ("communicationId", "gatewayId", "parentId", "baseDevId")
_FRESH_SECONDS = 600


def _parts(item: Any) -> list[dict]:
    if not isinstance(item, dict):
        return []
    return [item] + [item[k] for k in _NESTED_FIELDS if isinstance(item.get(k), dict)]


def _serial_match(item: Any, serial: str | None) -> bool:
    if not isinstance(serial, str) or not serial or len(serial) > 256:
        return False
    return any(obj.get(field) == serial for obj in _parts(item) for field in _SERIAL_FIELDS)


def _model_match(item: Any, model: str) -> bool:
    return any(obj.get(field) == model for obj in _parts(item)
               for field in ("model", "productModel", "modelName", "deviceModel", "productName"))


def _safe_index(data: dict, serials: Any) -> dict:
    """Map normalized opaque hashes to RAM-only serials without exporting either."""
    out: dict[str, tuple[int, str]] = {}
    if not isinstance(serials, (tuple, list)):
        return out
    for ix, sn in enumerate(serials[:30], 1):
        if isinstance(sn, str) and 0 < len(sn) <= 256:
            key = hashlib.sha256(("aosu-device:" + sn).encode()).hexdigest()[:32]
            if key in data and key not in out:
                out[key] = (ix, sn)
    return out


def audit_c9_h1l_bridge(coordinator_data: Any, client: Any, *, now: float | None = None) -> dict:
    """Classify each C9/H1L identity using existing AOSU and OEM Tuya caches."""
    report = {
        "diagnostic": "aosu_c9_h1l_correspondance_b98",
        "lecture_seule": True,
        "appels_http": 0,
        "login_tuya_effectue": False,
        "configuration_rtc_demandee": False,
        "connexions_p2p_demarre": 0,
        "commandes_video_envoyees": 0,
        "commandes_ptz_envoyees": 0,
        "numeros_serie_retournes": False,
        "identifiants_tuya_retournes": False,
        "cles_locales_retournees": False,
        "moteur_video_h1l_valide": False,
    }
    data = coordinator_data if isinstance(coordinator_data, dict) else {}
    indexed = _safe_index(data, getattr(client, "_device_sn_index", None))
    # Only the normalized HA inventory is used for the station relationship.
    bases = [(k, v) for k, v in data.items()
             if isinstance(v, dict) and v.get("model") == "H1L" and v.get("is_camera") is False]
    cameras = [(k, v) for k, v in data.items()
               if isinstance(v, dict) and v.get("model") == "C9C3CA11" and v.get("is_camera") is True]
    cameras.sort(key=lambda pair: indexed.get(pair[0], (9999, ""))[0])
    report["inventaire_aosu"] = {
        "nombre_c9": len(cameras),
        "nombre_stations_h1l": len(bases),
        "c9_avec_parent_h1l": sum(any(v.get("via_device") == k for k, _ in bases) for _, v in cameras),
        "correspondance_serial_aosu_en_ram": len(indexed) == len(data) and bool(data),
    }
    timestamp = time.monotonic() if now is None else now
    cache = getattr(client, "_tuya_oem_inventory_cache", None)
    valid_cache = isinstance(cache, dict) and isinstance(cache.get("devices"), dict)
    created = cache.get("created") if valid_cache else None
    age = timestamp - created if type(created) in (int, float) else None
    fresh = bool(valid_cache and age is not None and 0 <= age < _FRESH_SECONDS)
    # Cache belongs to the current OEM session, not a previous account login.
    current = getattr(client, "_tuya_oem_session", None)
    session_ok = bool(fresh and current is not None and
                      getattr(current, "uid", None) is not None and
                      cache.get("session_uid") == current.uid)
    tuya_devices = cache["devices"] if session_ok else {}
    # The index never leaks device IDs or local keys into report fields.
    report["inventaire_tuya"] = {
        "cache_present": valid_cache,
        "cache_frais": fresh,
        "meme_session_oem": session_ok,
        "nombre_appareils": min(len(tuya_devices), 100),
        "nouvelle_requete_effectuee": False,
    }
    station_matches: dict[str, list[str]] = {}
    for key, base in bases:
        sn = indexed.get(key, (None, None))[1]
        station_matches[key] = [did for did, item in tuya_devices.items() if _serial_match(item, sn)]
    report["stations_h1l"] = {
        "identification_tuya_serie_exacte": sum(len(matches) == 1 for matches in station_matches.values()),
        "correspondances_station_ambigues": sum(len(matches) > 1 for matches in station_matches.values()),
        "correspondance_tuya_sur_modele_seul_interdite": True,
    }
    rows = []
    for rank, (key, row) in enumerate(cameras[:20], 1):
        serial = indexed.get(key, (None, None))[1]
        exact = [did for did, item in tuya_devices.items() if _serial_match(item, serial)]
        only_model = sum(_model_match(item, "C9C3CA11") for item in tuya_devices.values())
        parent_key = row.get("via_device")
        parent_verified_aosu = any(parent_key == bk for bk, _ in bases)
        station_ids = station_matches.get(parent_key, [])
        linked_tuya = False
        if len(exact) == 1 and len(station_ids) == 1:
            obj = tuya_devices[exact[0]]
            linked_tuya = any(part.get(field) == station_ids[0]
                              for part in _parts(obj) for field in _PARENT_FIELDS)
        rows.append({
            "numero": rank,
            "modele": "C9C3CA11",
            "en_ligne_aosu": row.get("online") == 1,
            "station_h1l_associee_dans_aosu": parent_verified_aosu,
            "serie_privee_disponible_en_ram": serial is not None,
            "correspondance_tuya_exacte_unique": len(exact) == 1,
            "correspondances_exactes_ambigues": len(exact) > 1,
            "candidats_tuya_par_modele_sans_preuve": min(only_model, 100),
            "communication_id_vers_station_confirmee": linked_tuya,
            "identification_suffisante_pour_lecture_rtc_ciblee": len(exact) == 1,
            "lecture_rtc_effectuee": False,
            "video_disponible": False,
        })
    report["cameras_c9"] = rows
    if not cameras or not bases:
        state = "inventaire_c9_ou_h1l_incomplet"
    elif not all(r["station_h1l_associee_dans_aosu"] for r in rows):
        state = "liaison_h1l_incomplete"
    elif not session_ok:
        state = "liaison_aosu_confirmee_inventaire_tuya_non_disponible"
    elif any(r["correspondance_tuya_exacte_unique"] for r in rows):
        state = "c9_tuya_identifiee_preparation_rtc_possible"
    else:
        state = "liaison_aosu_confirmee_identite_tuya_non_prouvee"
    report["etat"] = state
    report["prochaine_etape"] = (
        "audit_rtc_c9_cible_sans_video_apres_validation_identite"
        if state == "c9_tuya_identifiee_preparation_rtc_possible" else
        "identifier_c9_dans_inventaire_oem_sans_selection_par_nom_ou_modele"
        if session_ok else
        "utiliser_inventaire_oem_existant_ou_diagnostic_explicitement_autorise"
    )
    report["remarque"] = (
        "La relation baseSn est confirmee dans AOSU, mais ne garantit pas le "
        "moteur video Tuya; une concordance de modele seule ne permet pas de choisir une C9."
    )
    return report
