"""B100: explicitly authorized read-only OEM detailed DeviceBeans for C9/H1L.

Never authenticate, open RTC/P2P/MQTT, publish DPs, or return raw OEM data.
Never choose a target for video from matching names. Uses existing session and
inventory cache only; at most 8 detail GETs, with per-process rate limiting.
"""
from __future__ import annotations

import re
import threading
import time
from typing import Any

from .c9_h1l_identity_structure_b99 import _LINK_FIELDS
from .c9_h1l_preflight_b98 import _safe_index, _FRESH_SECONDS

_LOCK = threading.Lock()
_LAST_RUN: dict[int, float] = {}
_COOLDOWN = 300
_SERIAL_PROOF_FIELDS = ("sn", "deviceSn", "devSn", "serialNumber", "serialNo",
                        "devId", "deviceId", "uuid", "devUuid", "deviceUuid", "cpDeviceId")
_ALLOWED_FIELDS = _SERIAL_PROOF_FIELDS + ("productId", "communicationId", "gatewayId",
                    "parentId", "baseDevId", "gwId", "hubId", "subDevId",
                    "p2pType", "skills", "productBean", "deviceInfo")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{5,128}\Z")
_DETAIL_WRAPPERS = ("result", "data", "device", "deviceBean", "deviceInfo",
                    "productBean", "product", "productInfo", "skills", "ext",
                    "extra", "config", "deviceAttribute")


def _detail_nodes(value: Any) -> list[dict]:
    """Traverse only named SDK wrappers, bounded; never arbitrary user keys."""
    result: list[dict] = []
    frontier = [value]
    for _ in range(4):
        next_frontier = []
        for node in frontier:
            if not isinstance(node, dict) or len(result) >= 64:
                continue
            result.append(node)
            for field in _DETAIL_WRAPPERS:
                nested = node.get(field)
                if isinstance(nested, dict):
                    next_frontier.append(nested)
        frontier = next_frontier[:64]
        if not frontier:
            break
    return result


def _field_values(nodes: list[dict], field: str) -> list[str]:
    return [v for n in nodes if isinstance((v := n.get(field)), str)
            and 0 < len(v) <= 256]



def _detail_summary(raw: Any, ids: dict[str, int], targets: list[tuple[int, str, str, str]]) -> dict:
    """Analyze private SDK details in memory, returning only allowlisted labels and counts."""
    if not isinstance(raw, dict):
        return {"etat": "structure_inattendue", "champs_presents": [],
                "liens_vers_autres_numeros_tuya": [], "correspondances_serie": []}
    nodes = _detail_nodes(raw)
    present = [field for field in _ALLOWED_FIELDS if any(field in n for n in nodes)]
    links = []
    for field in _LINK_FIELDS:
        for candidate in _field_values(nodes, field):
            if candidate in ids:
                item = {"champ": field, "numero_tuya": ids[candidate]}
                if item not in links:
                    links.append(item)
    matches = []
    for number, kind, serial, _name in targets:
        proof = [field for field in _SERIAL_PROOF_FIELDS if serial in _field_values(nodes, field)]
        if proof:
            matches.append({"numero_aosu": number, "categorie": kind,
                            "champs_identite": proof[:11]})
    return {"etat": "fiche_lue", "champs_presents": present,
            "liens_vers_autres_numeros_tuya": links[:16],
            "correspondances_serie": matches[:12],
            "capacite_p2p_indiquee": any("p2pType" in n for n in nodes)}


def audit_oem_details_c9_h1l_b100(coordinator: Any, *, consent: bool = False,
                                   now: float | None = None) -> dict:
    """Make a single, bounded burst of detail GETs on an already-authenticated cache."""
    report = {"diagnostic": "aosu_c9_h1l_fiches_detaillees_b100",
              "lecture_seule": True, "autorisation_lecture_explicite": consent is True,
              "appels_http": 0, "authentification_effectuee": False,
              "nouveau_mot_de_passe_envoye": False, "rtc_demande": False,
              "p2p_demarre": False, "video_demarre": False,
              "commandes_camera_envoyees": 0, "commandes_ptz_envoyees": 0,
              "identifiants_retournes": False, "noms_retournes": False,
              "valeurs_oem_retournees": False, "association_par_nom_autorisee": False,
              "moteur_video_h1l_valide": False,
              "appareils_oem": [], "correspondances_exactes": []}
    if consent is not True:
        return {**report, "etat": "confirmation_lecture_requise"}
    if getattr(getattr(coordinator, "live_controller", None), "running", False):
        return {**report, "etat": "direct_c5l_en_cours"}
    client = getattr(coordinator, "client", None)
    cache = getattr(client, "_tuya_oem_inventory_cache", None)
    session = getattr(client, "_tuya_oem_session", None)
    tick = time.monotonic() if now is None else now
    if (not isinstance(cache, dict) or not isinstance(cache.get("devices"), dict)
            or session is None or not isinstance(getattr(session, "uid", None), str)
            or cache.get("session_uid") != session.uid
            or type(cache.get("created")) not in (int, float)
            or not 0 <= tick - cache["created"] < _FRESH_SECONDS
            or type(getattr(session, "acquired_at", None)) not in (int, float)
            or not 0 <= tick - session.acquired_at < 1200):
        return {**report, "etat": "cache_oem_ou_session_absente_expiree"}
    raw_devices = cache["devices"]
    if not 1 <= len(raw_devices) <= 8:
        return {**report, "etat": "nombre_appareils_hors_limite"}
    if any(not isinstance(k, str) or not _TOKEN.fullmatch(k) or not isinstance(v, dict)
           for k, v in raw_devices.items()):
        return {**report, "etat": "identifiants_oem_invalides"}
    aosu = getattr(coordinator, "data", None)
    if not isinstance(aosu, dict):
        return {**report, "etat": "inventaire_aosu_absent"}
    idx = _safe_index(aosu, getattr(client, "_device_sn_index", None))
    targets = []
    for key, row in aosu.items():
        if not isinstance(row, dict):
            continue
        kind = ("station_h1l" if row.get("model") == "H1L" else
                "camera_c9" if row.get("model") == "C9C3CA11" and row.get("is_camera") is True else None)
        if kind and key in idx and isinstance(idx[key][1], str) and idx[key][1]:
            targets.append((idx[key][0], kind, idx[key][1], row.get("name", "")))
    if sum(t[1] == "camera_c9" for t in targets) < 1 or not any(t[1] == "station_h1l" for t in targets):
        return {**report, "etat": "c9_ou_h1l_non_identifiee"}
    targets.sort(key=lambda t: (t[0] if isinstance(t[0], int) else 9999))
    remaining = _LAST_RUN.get(id(client), 0) - tick
    if remaining > 0:
        return {**report, "etat": "temporisation_diagnostic",
                "secondes_restantes": int(remaining + .999)}
    if not _LOCK.acquire(blocking=False):
        return {**report, "etat": "audit_deja_en_cours"}
    try:
        remaining = _LAST_RUN.get(id(client), 0) - tick
        if remaining > 0:
            return {**report, "etat": "temporisation_diagnostic",
                    "secondes_restantes": int(remaining + .999)}
        from .uid_token_probe import _ready_identity, _apk_preflight
        from .tuya_uid_gateway import TuyaAuthSession, OEMGatewayError, do_oem_read
        if not isinstance(session, TuyaAuthSession):
            return {**report, "etat": "session_oem_non_validee"}
        ready = _ready_identity(client)
        if ready is None:
            return {**report, "etat": "profil_oem_absent"}
        _, install_id = ready
        _, parsed = _apk_preflight(client.apk_path)
        if parsed is None:
            return {**report, "etat": "ressources_oem_invalides"}
        identity, signer = parsed
        ttid = f"sdk_international@{identity.app_id}"
        _LAST_RUN[id(client)] = tick + _COOLDOWN
        ids = sorted(raw_devices)
        numbers = {device_id: i for i, device_id in enumerate(ids, 1)}
        results = []
        for device_id in ids:
            # Never trust an OEM payload to select the API destination; only the
            # validated IDs from the already cached inventory are accepted.
            record = {"numero_tuya": numbers[device_id], "etat": "non_lu"}
            try:
                report["appels_http"] += 1
                response, status = do_oem_read(
                    identity, signer, "sha256_material", session,
                    action="thing.m.device.get", form_data={"devId": device_id},
                    ttid=ttid, device_id=install_id,
                    endpoint="https://a1.tuyaeu.com/api.json")
                if status.get("serveur_accepte") and not status.get("rejet_explicite"):
                    record.update(_detail_summary(response, numbers, targets))
                else:
                    record["etat"] = "fiche_refusee_ou_non_confirmee"
            except OEMGatewayError:
                record["etat"] = "erreur_api_oem"
            except Exception:
                record["etat"] = "erreur_lecture_non_detaillee"
            results.append(record)
        report["appareils_oem"] = results
        cross = []
        for number, kind, _serial, _name in targets:
            found = []
            for result in results:
                for match in result.get("correspondances_serie", []):
                    if match["numero_aosu"] == number and match["categorie"] == kind:
                        found.append({"numero_tuya": result["numero_tuya"],
                                      "champs_identite": match["champs_identite"]})
            cross.append({"numero_aosu": number, "categorie": kind,
                          "nombre_preuves_exactes": len(found),
                          "correspondances": found[:8],
                          "identite_unique_prouvee": len(found) == 1})
        report["correspondances_exactes"] = cross
        successes = sum(r["etat"] == "fiche_lue" for r in results)
        report["etat"] = ("aucune_fiche_lue" if successes == 0 else
                          "fiches_partiellement_lues" if successes < len(ids) else
                          "preuves_identite_exacte_detectees" if any(r["identite_unique_prouvee"] for r in cross) else
                          "fiches_lues_identite_non_prouvee")
        report["note"] = ("Seule une correspondance serie/ID exacte et unique pourrait "
                          "preparer un test RTC cible. Aucun direct n'a ete lance.")
        return report
    finally:
        _LOCK.release()
