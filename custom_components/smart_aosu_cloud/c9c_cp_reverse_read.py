"""One consented, read-only reverse AOSU/Tuya CP identity check for a C9C.

AOSU Android 5.10.12 declares POST /v1/dev/getListByCoopUUIDList with the
form field coopUUID[]. Its UUIDInfoWebDataItem exposes coopUUID + deviceId.
Only an actual ID returned by the authenticated Tuya inventory may be queried.
The result must resolve to the *same* AOSU deviceId as the SN-matched detail.

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


def _aosu_device_id(detail: Any, serial: str) -> str | None:
    """Only the one SN-matched record in getInfoBySn is an AOSU identity."""
    if not isinstance(detail, dict) or type(detail.get('errno')) is not int or detail['errno'] != 0:
        return None
    data = detail.get('data')
    rows = (data.get('list') if isinstance(data, dict) else None)
    if not isinstance(rows, list):
        rows = [data] if isinstance(data, dict) else []
    if len(rows) > 30 or not _id(serial):
        return None
    found = [row['deviceId'] for row in rows if isinstance(row, dict)
             and row.get('sn') == serial and _id(row.get('deviceId'))]
    return found[0] if len(found) == 1 else None


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


def _check_reply(raw: Any, candidate: str, expected_device_id: str) -> str:
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
    if row['deviceId'] != expected_device_id:
        return 'autre_appareil_aosu'
    return 'liaison_exacte_confirmee'


def probe_c9c_reverse_cp(client: Any, detail: Any, serial: str,
                         cache: Any, *, params: dict, headers: dict) -> dict:
    """At most ONE additional signed AOSU HTTPS read, no retry or raw values."""
    out = {'etat': 'non_lance', 'source_identifiant': 'aucune',
           'appels_http': 0, 'liaison_exacte_confirmee': False,
           'commandes_camera': 0, 'commandes_ptz': 0, 'video_lancee': False,
           'identifiants_retournes': False, 'secrets_retournes': False}
    did = _aosu_device_id(detail, serial)
    if did is None:
        return {**out, 'etat': 'device_id_aosu_non_confirme'}
    candidate, source = _tuya_candidate(cache, now=time.monotonic())
    if candidate is None:
        return {**out, 'etat': source}
    out['source_identifiant'] = source
    # Reuse the already authenticated, authenticated-device-list request
    # parameters. POST is strictly restricted to the AOSU Europe host.
    try:
        request_headers = dict(headers)
        request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        response = client.session.post(
            _ENDPOINT, params=params, data=[('coopUUID[]', candidate)],
            headers=request_headers, timeout=(8, 20), verify=True,
            allow_redirects=False)
        if response.status_code != 200:
            return {**out, 'etat': 'http_non_200', 'appels_http': 1}
        if len(response.content) > 262144:
            return {**out, 'etat': 'reponse_trop_grande', 'appels_http': 1}
        status = _check_reply(response.json(), candidate, did)
        return {**out, 'etat': status, 'appels_http': 1,
                'liaison_exacte_confirmee': status == 'liaison_exacte_confirmee'}
    except (OSError, ValueError, TypeError, KeyError):
        return {**out, 'etat': 'erreur_reseau_ou_json', 'appels_http': 1}
