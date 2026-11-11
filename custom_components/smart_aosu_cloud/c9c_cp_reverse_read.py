"""One consented, read-only reverse AOSU/Tuya CP identity check for a C9C.

AOSU Android 5.10.12 declares POST /v1/dev/getListByCoopUUIDList with the
form field coopUUID[]. Its UUIDInfoWebDataItem exposes coopUUID + deviceId.
Only an actual ID returned by the authenticated Tuya inventory may be queried.
A reverse result can establish a proven link only when it matches a\nSN-verified AOSU deviceId, otherwise it is diagnostic evidence alone.

No camera, MQTT, PTZ, wake, media, secret logging, persistent identity or
automatic authorization for video. The caller enforces a 1-hour cooldown.
"""
from __future__ import annotations

import time
from typing import Any

_ENDPOINT = 'https://api-eu.aosulife.com/v1/dev/getListByCoopUUIDList'
_NON_VIDEO = frozenset(('gw', 'gateway', 'hub', 'switch', 'socket', 'sensor',
                         'light', 'zigbee', 'plug', 'cz', 'kg', 'dj', 'cl',
                         'pir', 'wsdcg'))


def _id(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 256
            and value == value.strip() and value.isprintable()
            and not any(c.isspace() or c in '#+\r\n\0' for c in value))


def _aosu_detail_identity(detail: Any, serial: str) -> tuple[bool, str | None]:
    """Require one verified SN in getInfoBySn, even when deviceId is absent.

    Walk only known nested device containers at a bounded depth. A deviceId
    from a different serial can never be promoted to the expected camera.
    """
    if (not isinstance(detail, dict) or type(detail.get('errno')) is not int
            or detail['errno'] != 0 or not _id(serial)):
        return False, None
    data = detail.get('data')
    todo = [(data, 0)]
    visited = 0
    serials = []
    matches = []
    while todo and visited < 80:
        node, depth = todo.pop()
        if isinstance(node, list):
            if depth < 5:
                todo.extend((row, depth + 1) for row in node[:30])
            continue
        if not isinstance(node, dict):
            continue
        visited += 1
        if _id(node.get('sn')):
            serials.append(node['sn'])
            if node['sn'] == serial and _id(node.get('deviceId')):
                matches.append(node['deviceId'])
        if depth < 5:
            todo.extend((value, depth + 1) for value in list(node.values())[:40]
                        if isinstance(value, (dict, list)))
    # Duplicate representations of exactly one SN are fine; a second
    # different SN is contradictory and must not authorize any lookup.
    if not serials or any(item != serial for item in serials):
        return False, None
    unique = set(matches)
    if len(unique) > 1:
        return False, None
    return True, next(iter(unique)) if unique else None



def extract_tuya_detail_cp_candidates(payload: Any, target: str) -> tuple[tuple[str, str], ...]:
    """Read only actual alternative UUID fields of the same Tuya device.

    This is never an AOSU identity proof. The caller retains only these
    identifiers temporarily in RAM, not the private response or localKey.
    No network access, filesystem writes or output of raw values.
    """
    if not isinstance(payload, dict) or not _id(target):
        return ()
    nodes = [payload]
    visited = set()
    found_ids = set()
    values = []
    fields = (
        ('cpDeviceId', 'cp_device_id_fiche_tuya'),
        ('coopUUID', 'coop_uuid_tuya'),
        ('uuid', 'uuid_tuya'),
        ('devUuid', 'dev_uuid_tuya'),
        ('deviceUuid', 'device_uuid_tuya'),
        ('cpUuid', 'cp_uuid_tuya'),
    )
    while nodes and len(visited) < 50:
        node = nodes.pop(0)
        if not isinstance(node, dict) or id(node) in visited:
            continue
        visited.add(id(node))
        for key in ('devId', 'deviceId'):
            value = node.get(key)
            if _id(value):
                found_ids.add(value)
        for key, kind in fields:
            value = node.get(key)
            if _id(value) and value not in (target,):
                values.append((kind, value))
        for key in ('data', 'result', 'device', 'deviceInfo', 'deviceBean'):
            value = node.get(key)
            if isinstance(value, dict):
                nodes.append(value)
    # A Tuya response must explicitly identify the selected device. Do not
    # reuse UUIDs from anonymous or contradictory responses.
    if found_ids != {target}:
        return ()
    out = []
    seen = {target}
    for kind, value in values:
        if value not in seen:
            seen.add(value)
            out.append((kind, value))
    # Never batch a large or ambiguous collection of distinct UUIDs.
    return tuple(out) if len(out) <= 4 else ()


def _candidate_batch(cache: Any, detail_cache: Any, *, now: float
                     ) -> tuple[list[tuple[str, str]], str]:
    base, source = _tuya_candidate(cache, now=now)
    if base is None:
        return [], source
    candidates = [(source, base)]
    if not isinstance(detail_cache, dict):
        return candidates, 'inventaire_seul'
    created = detail_cache.get('created')
    if (type(created) not in (int, float)
            or not 0 <= now - created <= 600
            or not isinstance(cache, dict)
            or not isinstance(cache.get('devices'), dict)
            or len(cache['devices']) != 1):
        return candidates, 'fiche_expiree_ou_absente'
    target = next(iter(cache['devices']))
    if detail_cache.get('target') != target:
        return candidates, 'fiche_autre_appareil'
    extra = detail_cache.get('candidates')
    if not isinstance(extra, tuple) or len(extra) > 4:
        return candidates, 'fiche_non_exploitable'
    allowed = {
        'cp_device_id_fiche_tuya', 'coop_uuid_tuya', 'uuid_tuya',
        'dev_uuid_tuya', 'device_uuid_tuya', 'cp_uuid_tuya'}
    seen = {base}
    for row in extra:
        if (not isinstance(row, tuple) or len(row) != 2
                or row[0] not in allowed or not _id(row[1])):
            return [(source, base)], 'fiche_non_exploitable'
        if row[1] not in seen:
            candidates.append(row)
            seen.add(row[1])
    return candidates, 'fiche_tuya_et_inventaire'


def _tuya_candidate(cache: Any, *, now: float) -> tuple[str | None, str]:
    """A single actual Tuya device ID, never a guessed/proxied identifier."""
    if not isinstance(cache, dict) or not isinstance(cache.get('devices'), dict):
        return None, 'inventaire_tuya_absent'
    created = cache.get('created')
    if type(created) not in (float, int) or not 0 <= now-created <= 600:
        return None, 'inventaire_tuya_expire'
    devices = cache['devices']
    if len(devices) != 1:
        return None, 'inventaire_tuya_non_unique'
    dev_id, item = next(iter(devices.items()))
    if not isinstance(item, dict) or not _id(dev_id):
        return None, 'appareil_tuya_invalide'
    if item.get('devId') not in (None, dev_id) or item.get('deviceId') not in (None, dev_id):
        return None, 'identifiants_tuya_contradictoires'
    nested = [item]
    for key in ('productBean', 'deviceInfo'):
        if isinstance(item.get(key), dict):
            nested.append(item[key])
    categories = {obj['category'].lower().strip() for obj in nested
                  if isinstance(obj.get('category'), str)}
    if categories & _NON_VIDEO:
        return None, 'categorie_tuya_non_video'
    # A cpDeviceId explicitly returned by Tuya is the most specific legitimate
    # query input. If multiple explicit CP references contradict, do not query.
    cp_ids = {obj['cpDeviceId'] for obj in nested if _id(obj.get('cpDeviceId'))}
    if len(cp_ids) > 1:
        return None, 'references_cp_contradictoires'
    return (next(iter(cp_ids)), 'cp_device_id_tuya') if cp_ids else (dev_id, 'dev_id_tuya')


def _check_batch_reply(raw: Any, candidates: list[tuple[str, str]],
                       expected_device_id: str | None
                       ) -> tuple[str, str, bool]:
    """Resolve at most one exact returned CP candidate, then AOSU device ID.

    Distinguish a returned candidate from an identity proven against the
    SN-verified AOSU device. Neither is permission to send media commands.
    """
    if not isinstance(raw, dict) or type(raw.get('errno')) is not int:
        return 'reponse_non_conforme', 'aucune', False
    if raw['errno'] != 0:
        return 'serveur_refuse', 'aucune', False
    data = raw.get('data')
    rows = data.get('list') if isinstance(data, dict) else None
    if not isinstance(rows, list) or len(rows) > 30:
        return 'schema_non_reconnu', 'aucune', False
    if not rows:
        return 'reference_non_resolue', 'aucune', False
    if any(not isinstance(row, dict) or not _id(row.get('coopUUID'))
           or not _id(row.get('deviceId')) for row in rows):
        return 'champs_identite_manquants', 'aucune', False
    labels = {value: source for source, value in candidates}
    if any(row['coopUUID'] not in labels for row in rows):
        return 'reference_cp_incoherente', 'aucune', False
    if len(rows) != 1:
        return 'references_cp_multiples_ambigues', 'aucune', False
    row = rows[0]
    source = labels[row['coopUUID']]
    if expected_device_id is None:
        return 'reference_cp_resolue_identite_non_confirmee', source, True
    if row['deviceId'] != expected_device_id:
        return 'autre_appareil_aosu', source, True
    return 'liaison_exacte_confirmee', source, True


def _check_reply(raw: Any, candidate: str, expected_device_id: str | None) -> str:
    """No IDs leave this function; distinguish absent, contradictory and exact."""
    if not isinstance(raw, dict) or type(raw.get('errno')) is not int:
        return 'reponse_non_conforme'
    if raw['errno'] != 0:
        return 'serveur_refuse'
    data = raw.get('data')
    rows = data.get('list') if isinstance(data, dict) else None
    if not isinstance(rows, list) or len(rows) > 30:
        return 'schema_non_reconnu'
    if not rows:
        return 'reference_non_resolue'
    if len(rows) != 1 or not isinstance(rows[0], dict):
        return 'reponse_ambigue'
    row = rows[0]
    if not _id(row.get('coopUUID')) or not _id(row.get('deviceId')):
        return 'champs_identite_manquants'
    if row['coopUUID'] != candidate:
        return 'reference_cp_incoherente'
    if expected_device_id is None:
        # A successful CP lookup alone does not tie the Tuya entry to the
        # camera's SN. Never claim an exact AOSU/Tuya identity without that.
        return 'reference_cp_resolue_identite_non_confirmee'
    if row['deviceId'] != expected_device_id:
        return 'autre_appareil_aosu'
    return 'liaison_exacte_confirmee'


def probe_c9c_reverse_cp(client: Any, detail: Any, serial: str,
                         cache: Any, *, params: dict, headers: dict,
                         known_aosu_device_id: str | None = None,
                         tuya_detail_cache: Any = None) -> dict:
    """One opt-in signed HTTPS read. No SDP, MQTT, persistent IDs or retries."""
    out = {'etat': 'non_lance', 'source_identifiant': 'aucune',
           'source_device_id_aosu': 'aucune',
           'id_aosu_fiche_present': False,
           'id_aosu_inventaire_present': False,
           'reference_cp_resolue': False,
           'candidats_cp_essayes': 0,
           'type_reference_resolue': 'aucune',
           'appels_http': 0, 'liaison_exacte_confirmee': False,
           'commandes_camera': 0, 'commandes_ptz': 0, 'video_lancee': False,
           'identifiants_retournes': False, 'secrets_retournes': False}
    serial_confirmed, detail_did = _aosu_detail_identity(detail, serial)
    if not serial_confirmed:
        return {**out, 'etat': 'numero_serie_aosu_non_confirme'}
    cached_did = known_aosu_device_id if _id(known_aosu_device_id) else None
    out['id_aosu_fiche_present'] = detail_did is not None
    out['id_aosu_inventaire_present'] = cached_did is not None
    if detail_did and cached_did and detail_did != cached_did:
        return {**out, 'etat': 'identifiants_aosu_contradictoires'}
    did = detail_did or cached_did
    out['source_device_id_aosu'] = (
        'fiche_SN' if detail_did else 'inventaire_SN' if cached_did else 'aucune')
    candidates, source = _candidate_batch(
        cache, tuya_detail_cache, now=time.monotonic())
    if not candidates:
        return {**out, 'etat': source}
    out['source_identifiant'] = source
    out['candidats_cp_essayes'] = len(candidates)
    # Even with no deviceId in the AOSU detail or getList, we can make
    # ONE read-only reverse query and report presence without proving identity.
    try:
        request_headers = dict(headers)
        request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = client.session.post(
            _ENDPOINT, params=params,
            data=[('coopUUID[]', value) for _source, value in candidates],
            headers=request_headers, timeout=(8, 20), verify=True,
            allow_redirects=False)
        if response.status_code != 200:
            return {**out, 'etat': 'http_non_200', 'appels_http': 1}
        if len(response.content) > 262144:
            return {**out, 'etat': 'reponse_trop_grande', 'appels_http': 1}
        status, matched_source, cp_resolved = _check_batch_reply(
            response.json(), candidates, did)
        out['reference_cp_resolue'] = cp_resolved
        out['type_reference_resolue'] = matched_source
        return {**out, 'etat': status, 'appels_http': 1,
                'liaison_exacte_confirmee': status == 'liaison_exacte_confirmee'}
    except Exception:  # Sanitized HTTP/JSON failure; no IDs or raw exception.
        return {**out, 'etat': 'erreur_reseau_ou_json', 'appels_http': 1}
