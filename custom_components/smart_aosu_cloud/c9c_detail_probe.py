"""One-shot read-only AOSU C9C detail comparison, never expose identifiers.

Uses the same /v1/dev/getInfoBySn read already used by the C5L audit.
Requires user consent at the service layer. No video, MQTT or PTZ calls.
"""
from __future__ import annotations
import time
import requests
from .identity_audit import TARGET_INFO, summarize_info


def _valid(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 256


def _detail_references(payload):
    """Only known ID fields, at bounded depth. Values stay in memory."""
    keys = ("cpDeviceId", "coopUUID", "cpUuid", "deviceUuid",
            "devId", "deviceId", "communicationId")
    found = set()
    sn_values = set()
    todo = [(payload.get("data"), 0)]
    inspected = 0
    while todo and inspected < 80:
        node, depth = todo.pop()
        if isinstance(node, dict):
            inspected += 1
            for k in keys:
                v = node.get(k)
                if _valid(v):
                    found.add(v)
            v = node.get("sn")
            if _valid(v):
                sn_values.add(v)
            if depth < 5:
                todo.extend((v, depth + 1) for v in list(node.values())[:40]
                            if isinstance(v, (dict, list)))
        elif isinstance(node, list) and depth < 5:
            todo.extend((v, depth + 1) for v in node[:20]
                        if isinstance(v, (dict, list)))
    return found, sn_values


def summarize_c9c_detail(payload, sn, tuya_cache):
    """Return only fixed enums, counts, booleans and sanitized provider hints."""
    out = {"etat": "reponse_invalide", "commandes_camera": 0,
           "commandes_ptz": 0, "video_lancee": False,
           "secrets_retournes": False, "identifiants_retournes": False}
    if not isinstance(payload, dict) or payload.get("errno") != 0:
        return out
    info = summarize_info(payload)
    refs, sn_values = _detail_references(payload)
    devices = (tuya_cache.get("devices") if isinstance(tuya_cache, dict) else None)
    target_ids = set()
    if isinstance(devices, dict) and len(devices) <= 100:
        for did, obj in devices.items():
            if _valid(did):
                target_ids.add(did)
            if isinstance(obj, dict):
                for k in ("devId", "deviceId", "uuid", "cpDeviceId", "deviceUuid"):
                    v = obj.get(k)
                    if _valid(v):
                        target_ids.add(v)
    matches = refs & target_ids
    provider = info.get("audit_provider_p2p", {})
    candidate = provider.get("candidat") if isinstance(provider, dict) else None
    candidate = candidate if isinstance(candidate, dict) else {}
    label = candidate.get("sdk_provider_declare_nom")
    label = label if label in ("THING", "TUTK", "THING_STATION",
                             "FISHEYE", "VIRTUAL") else "INDETERMINE"
    kind = candidate.get("p2p_type_declare")
    kind = kind if type(kind) is int and 0 <= kind <= 9 else "absent"
    out.update({
        "etat": "fiche_obtenue",
        "references_connues_presentes": bool(refs),
        "references_tuya_potentielles": info.get("references", {}),
        "numero_serie_present_dans_fiche": bool(sn_values),
        "numero_serie_concordant": _valid(sn) and sn in sn_values,
        "numero_serie_contradictoire": bool(sn_values) and sn not in sn_values,
        "inventaire_tuya_present": isinstance(devices, dict),
        "correspondance_reference_tuya": bool(matches),
        "nombre_correspondances_references": min(len(matches), 20),
        "fournisseur_p2p_fiche": label,
        "type_p2p_fiche": kind,
        "fournisseur_confirme_par_video": False,
        "conclusion": ("reference_correspondante_a_verifier" if matches
                      else "aucune_reference_correspondante"),
    })
    return out


def probe_c9c_detail(client):
    """One fixed HTTPS read per hour per live client, no retries or raw output."""
    base = {"diagnostic": "aosu_c9c_fiche_detaillee_b7",
            "appels_http": 0, "commandes_camera": 0, "commandes_ptz": 0,
            "video_lancee": False, "identifiants_retournes": False,
            "secrets_retournes": False}
    with client._dp_lock:
        sn = getattr(client, "_standalone_c9c_sn", None)
        if not _valid(sn):
            return {**base, "etat": "c9c_autonome_non_identifiee"}
        if not all((getattr(client, "_sid", None),
                    getattr(client, "_uid", None),
                    getattr(client, "_login_headers", None),
                    getattr(client, "_suffix", None))):
            return {**base, "etat": "session_aosu_indisponible"}
        now = time.monotonic()
        last = getattr(client, "_last_c9c_detail_probe", 0)
        if last and now - last < 3600:
            return {**base, "etat": "limite_une_fois_par_heure"}
        client._last_c9c_detail_probe = now
        from . import protocol_060 as proto
        try:
            params, headers = proto.build_device_list_request(
                client._suffix, client._login_headers, client._sid, client._uid)
            headers = dict(headers)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            response = client.session.post(
                TARGET_INFO, params=params, data={"sn": sn}, headers=headers,
                timeout=(8, 20), verify=True, allow_redirects=False)
            if response.status_code != 200:
                return {**base, "etat": "http_non_200", "appels_http": 1}
            if len(response.content) > 262144:
                return {**base, "etat": "reponse_trop_grande", "appels_http": 1}
            parsed = response.json()
            report = summarize_c9c_detail(
                parsed, sn, getattr(client, "_tuya_oem_inventory_cache", None))
            return {**base, **report, "appels_http": 1}
        except (requests.RequestException, ValueError, TypeError, KeyError):
            return {**base, "etat": "erreur_lecture", "appels_http": 1}
