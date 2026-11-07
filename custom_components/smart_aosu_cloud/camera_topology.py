"""Fail-closed video routing using only the already-fetched AOSU inventory.

This module never accesses the network or exposes private camera identifiers.
A C9C on Wi-Fi is *not* an H1L child simply because its model starts with C9.
"""
from __future__ import annotations


def _cameras(data):
    if not isinstance(data, dict):
        return []
    return [(key, row) for key, row in data.items()
            if isinstance(row, dict) and row.get('is_camera') is True]


def has_h1l_video_topology(data):
    """Only create legacy H1L video entities when a H1L and C9C3CA11 exist.

    Keep the legacy H1L slots untouched for the verified two-C9 development
    topology. Never apply these entities to a standalone model C9C.
    """
    if not isinstance(data, dict):
        return False
    has_base = any(isinstance(row, dict) and
                   str(row.get('model') or '').strip().upper() == 'H1L'
                   for row in data.values())
    return has_base and any(
        str(row.get('model') or '').strip().upper() == 'C9C3CA11'
        for _, row in _cameras(data))


def select_standalone_c9c_key(data):
    """Select ONLY one standalone C9C, never by the user's camera name.

    Do not allow a mixed account (or an ambiguous/missing model) to route an
    experimental P2P command to some other camera.
    """
    cameras = _cameras(data)
    if len(cameras) != 1 or has_h1l_video_topology(data):
        return None
    if any(isinstance(row, dict) and
           str(row.get('model') or '').strip().upper() == 'H1L'
           for row in (data or {}).values()):
        return None
    key, row = cameras[0]
    if str(row.get('model') or '').strip().upper() != 'C9C':
        return None
    if row.get('via_device') not in (None, ''):
        return None
    return key


def select_tuya_standalone_target(devices, *, camera_sn, camera_coop):
    """Find the one Tuya target using exact AOSU IDs, or sole IPC fallback.

    Identifier values stay local in memory. Fallback requires EXACTLY one Tuya
    device with an explicit IPC category and is only used after manual consent.
    """
    if not isinstance(devices, dict) or not devices:
        return None, 'inventaire_tuya_absent'
    matches = []
    def objects(item):
        if not isinstance(item, dict):
            return []
        return [item] + [item[k] for k in ('productBean', 'product', 'productInfo',
                'deviceBean', 'deviceInfo') if isinstance(item.get(k), dict)]
    for dev_id, item in devices.items():
        for obj in objects(item):
            if ((camera_sn and any(obj.get(k) == camera_sn for k in
                   ('sn','deviceSn','serialNumber','serialNo'))) or
                (camera_coop and any(obj.get(k) == camera_coop for k in
                   ('devId','deviceId','uuid','devUuid','deviceUuid','cpDeviceId')))):
                matches.append(dev_id)
                break
    if len(matches) == 1:
        return matches[0], 'identite_exacte'
    if matches:
        return None, 'correspondance_ambigue'
    if len(devices) == 1:
        dev_id, item = next(iter(devices.items()))
        if any(str(obj.get('category') or '').strip().lower()
               in ('sp','ipc','camera','smart_camera') for obj in objects(item)):
            return dev_id, 'camera_tuya_unique_non_confirmee'
    return None, 'camera_tuya_non_identifiee'
