"""B99 C9/H1L identity structure diagnostic; RAM-only and zero-network.

Untrusted OEM device values are used only for exact comparisons in RAM. Return
only hardcoded labels, safe booleans and bounded counts. Names, IDs, raw values,
reversible digests and server-provided field names never leave this function.

A name match is *only* a clue and must never authorize camera selection.
"""
from __future__ import annotations

import time
from typing import Any

from .c9_h1l_preflight_b98 import _safe_index, _FRESH_SECONDS

# Allowlisted schema only. Unknown fields never become result keys or values.
_IDENTITY_FIELDS = (
    "sn", "deviceSn", "devSn", "serialNumber", "serialNo", "devId",
    "deviceId", "uuid", "devUuid", "deviceUuid", "cpDeviceId",
    "thirdId", "communicationId", "gatewayId", "parentId", "baseDevId",
    "gwId", "hubId", "nodeId", "subDevId", "productId",
)
_LINK_FIELDS = (
    "communicationId", "gatewayId", "parentId", "baseDevId", "gwId",
    "hubId", "subDevId",
)
_CONTAINERS = (
    "productBean", "product", "productInfo", "deviceBean", "deviceInfo",
    "data", "ext", "extra", "skills", "config", "deviceAttribute",
)
_PUBLIC_PROPERTIES = (
    "devId", "deviceId", "uuid", "devUuid", "deviceUuid", "sn", "deviceSn",
    "serialNumber", "serialNo", "communicationId", "gatewayId", "parentId",
    "baseDevId", "gwId", "hubId", "subDevId", "nodeId", "category",
    "productBean", "productId", "skills", "p2pType", "localKey", "name",
    "isOnline", "deviceType", "model", "productModel", "modelName",
)


def _nodes(item: Any) -> list[dict]:
    """Visit only documented-like containers, never lists/arbitrary server keys."""
    if not isinstance(item, dict):
        return []
    result = [item]
    for name in _CONTAINERS:
        nested = item.get(name)
        if isinstance(nested, dict):
            result.append(nested)
            # One additional named nesting level for wrapped DeviceBeans.
            for child in _CONTAINERS:
                grandchild = nested.get(child)
                if isinstance(grandchild, dict):
                    result.append(grandchild)
    return result[:80]


def _values(item: dict, field: str) -> list[str]:
    return [node[field] for node in _nodes(item)
            if isinstance(node.get(field), str) and 0 < len(node[field]) <= 256]


def _presence(item: dict, field: str) -> bool:
    return any(field in node for node in _nodes(item))


def _match_name(item: dict, name: Any) -> bool:
    """RAM-only hint, never a verified device identity."""
    if not isinstance(name, str) or not (1 <= len(name.strip()) <= 100):
        return False
    needle = name.strip().casefold()
    return any(n.strip().casefold() == needle
               for n in _values(item, "name") if n.strip())


def audit_c9_oem_structure(data: Any, client: Any, *, now: float | None = None) -> dict:
    """Inspect already-cached OEM identity fields without returning their values."""
    report = {
        "diagnostic": "aosu_c9_h1l_structure_b99",
        "lecture_seule": True,
        "requete_reseau_effectuee": False,
        "login_effectue": False,
        "rtc_demande": False,
        "video_demarre": False,
        "commande_camera_envoyee": False,
        "commande_ptz_envoyee": False,
        "identifiants_prives_retournes": False,
        "noms_prives_retournes": False,
        "valeurs_oem_retournees": False,
        "correspondance_par_nom_suffisante_pour_video": False,
    }
    aosu = data if isinstance(data, dict) else {}
    indexed = _safe_index(aosu, getattr(client, "_device_sn_index", None))
    cache = getattr(client, "_tuya_oem_inventory_cache", None)
    valid = isinstance(cache, dict) and isinstance(cache.get("devices"), dict)
    t = time.monotonic() if now is None else now
    created = cache.get("created") if valid else None
    fresh = type(created) in (int, float) and 0 <= t - created < _FRESH_SECONDS
    session = getattr(client, "_tuya_oem_session", None)
    same_session = bool(fresh and session is not None and
                        getattr(session, "uid", None) is not None and
                        cache.get("session_uid") == session.uid)
    all_devices = cache["devices"] if same_session else {}
    # Sort by OEM ID like the B27 inventory so anonymous slot numbers align.
    ids = sorted((did for did, item in all_devices.items()
                  if isinstance(did, str) and isinstance(item, dict)))[:50]
    devices = {did: all_devices[did] for did in ids}
    positions = {did: ix for ix, did in enumerate(ids, 1)}
    report["inventaire_tuya"] = {
        "cache_present": valid, "cache_frais": bool(fresh),
        "meme_session_oem": same_session,
        "nombre_appareils": min(len(devices), 50),
        "numerotation_identique_a_audit_oem_b27": same_session,
    }
    station_rows = [(k, row) for k, row in aosu.items()
                    if isinstance(row, dict) and row.get("model") == "H1L"]
    camera_rows = [(k, row) for k, row in aosu.items()
                   if isinstance(row, dict) and row.get("model") == "C9C3CA11"
                   and row.get("is_camera") is True]
    camera_rows.sort(key=lambda pair: indexed.get(pair[0], (9999, ""))[0])
    report["inventaire_aosu"] = {
        "nombre_c9": len(camera_rows),
        "nombre_h1l": len(station_rows),
        "c9_liees_a_la_station": sum(any(row.get("via_device") == key
                                      for key, _ in station_rows)
                                      for _, row in camera_rows),
    }
    # Private serials are used only to test exact cross-inventory equality.
    targets = [(key, row) for key, row in camera_rows + station_rows]
    target_serials = {key: indexed[key][1] for key, _ in targets if key in indexed}
    per_target = []
    for key, row in targets[:20]:
        sn = target_serials.get(key)
        if not sn:
            continue
        matches = []
        for did, item in devices.items():
            fields = [field for field in _IDENTITY_FIELDS
                      if sn in _values(item, field)]
            if sn == did and "devId" not in fields:
                fields.append("devId")
            if fields:
                matches.append({"numero_tuya": positions[did],
                                "champs_identite": sorted(set(fields))})
        per_target.append({
            "categorie": "station_h1l" if row.get("model") == "H1L" else "camera_c9",
            "numero_aosu": (indexed[key][0] if key in indexed else None),
            "nombre_correspondances_serie_exactes": len(matches),
            "preuves_identite": matches[:8],
            "nom_consideré_uniquement_comme_indice": True,
            "candidats_par_nom": [positions[did] for did, item in devices.items()
                                   if _match_name(item, row.get("name"))][:10],
        })
    report["comparaison_identites"] = per_target
    nodes_summary = []
    for did in ids:
        item = devices[did]
        relations = []
        for field in _LINK_FIELDS:
            for ref in _values(item, field):
                if ref in positions and ref != did:
                    marker = {"champ": field, "vers_numero_tuya": positions[ref]}
                    if marker not in relations:
                        relations.append(marker)
        row = {
            "numero_tuya": positions[did],
            "champs_identification_presents": [field for field in _IDENTITY_FIELDS
                                               if _presence(item, field)],
            "autres_champs_presents": [field for field in _PUBLIC_PROPERTIES
                                      if field not in _IDENTITY_FIELDS and _presence(item, field)],
            "liens_internes_tuya": relations[:12],
            "objet_productBean_present": isinstance(item.get("productBean"), dict),
            "objet_skills_present": isinstance(item.get("skills"), dict),
        }
        nodes_summary.append(row)
    report["appareils_tuya_anonymes"] = nodes_summary
    total_verified = sum(entry["nombre_correspondances_serie_exactes"] == 1
                         for entry in per_target)
    links = sum(len(entry["liens_internes_tuya"]) for entry in nodes_summary)
    report["conclusion"] = (
        "inventaire_oem_absent_ou_expire" if not same_session else
        "identifiants_exacts_present_dans_champs_alternatifs" if total_verified else
        "relations_internes_oem_a_etudier" if links else
        "aucune_identite_serie_ni_relation_interne_etablie"
    )
    report["identification_exacte_unique_nombre"] = total_verified
    report["relations_oem_nombre"] = links
    report["video_c9_disponible"] = False
    report["note"] = (
        "Les indices par nom ne sont pas des preuves d'identite. Les numeros Tuya "
        "ne sont que des emplacements anonymes dans ce cache. Aucune session video C9." 
    )
    return report
