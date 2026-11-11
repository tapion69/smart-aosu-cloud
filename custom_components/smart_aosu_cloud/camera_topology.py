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
    """Match exact identifiers or a unique explicitly categorized Tuya camera.

    Fallback is only for one AOSU standalone C9C and a manual video trial,
    as enforced by the caller. Other Tuya device types may coexist, but two
    eligible cameras are always ambiguous. Never use names or device order.
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
    # A Tuya account can contain gateways, switches and sensors in addition
    # to the one standalone C9C. These must not make an otherwise unique IPC
    # ambiguous. Never guess if zero or multiple video candidates remain.
    cameras = [dev_id for dev_id, item in devices.items()
               if any(str(obj.get('category') or '').strip().lower()
                      in ('sp', 'ipc', 'camera', 'smart_camera')
                      for obj in objects(item))]
    if len(cameras) == 1:
        return cameras[0], 'camera_tuya_unique_non_confirmee'
    if len(cameras) > 1:
        return None, 'cameras_tuya_multiples_ambigues'
    # Experimental last resort for an account holding EXACTLY one AOSU C9C
    # and exactly one Tuya device. The caller already checks the AOSU model,
    # absence of H1L and express video-only consent. Never use this fallback
    # with multiple Tuya devices or without the exact AOSU camera SN in RAM.
    # A non-video device may still be the sole Tuya device, so reject explicit
    # non-video categories rather than assuming every unique device is a camera.
    if len(devices) == 1 and isinstance(camera_sn, str) and camera_sn:
        dev_id, item = next(iter(devices.items()))
        if not isinstance(item, dict):
            return None, 'appareil_tuya_unique_invalide'
        categories = {
            str(obj['category']).strip().lower()
            for obj in objects(item)
            if isinstance(obj.get('category'), str) and obj['category'].strip()
        }
        # Common Tuya non-camera categories and hub aliases. This list is
        # deliberately conservative, and only prevents the WEAK fallback;
        # confirmed identity matching above keeps its original behavior.
        non_video = {
            'gw', 'gateway', 'hub', 'switch', 'socket', 'sensor', 'light',
            'zigbee', 'plug', 'cz', 'kg', 'dj', 'cl', 'pir', 'wsdcg',
        }
        if categories & non_video:
            return None, 'appareil_tuya_unique_categorie_non_video'
        return dev_id, 'appareil_tuya_unique_sans_categorie_video'
    return None, 'aucune_camera_tuya_identifiable'


def standalone_c9c_video_identity_verified(selection: object) -> bool:
    """Only an exact AOSU/Tuya link may authorize an experimental video offer.

    Unique device/category fallbacks remain useful for read-only diagnostics,
    but never establish the intended destination for an active MQTT/RTC send.
    No network access, device lookup or private identifier is needed here.
    """
    return selection == 'identite_exacte'
