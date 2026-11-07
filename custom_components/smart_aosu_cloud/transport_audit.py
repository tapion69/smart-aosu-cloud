"""Read-only cached PTZ transport and Tuya-reference preflight.

APK AOSU Android 5.10.12 (DEX):
- DeviceBusinessPlatform selects Gz iff deviceSupport.svcType == 'self'.
- PtzControllerTyImpl.<init> reads GzDeviceInfo.cpDeviceId before calling
  ThingIPCSdk.getPTZInstance(String).

The actual cpDeviceId is NEVER retained in coordinator.data or diagnostics.
This is NOT an IPC feature/support test and does not create a Tuya session.
"""
from __future__ import annotations


def platform_from_support(support: object) -> tuple[str, str]:
    """Return only a safe enum, never the vendor's raw metadata."""
    if not isinstance(support, dict):
        return 'indeterminee', 'champ_absent'
    value = support.get('svcType')
    if not isinstance(value, str) or not value:
        return 'indeterminee', 'champ_absent_ou_vide'
    if value == 'self':
        return 'Gz', 'self'
    return 'Ty', 'autre_que_self'


def _valid_private_id(value: object) -> bool:
    """Only validate structure; caller must not store, hash, or report value."""
    return isinstance(value, str) and 0 < len(value.strip()) <= 256


def tuya_reference_status(device: object) -> str:
    """Observe root cpDeviceId and nested cpDeviceInfo.cpDeviceId *in memory*.

    APK Ty controller reads the root cpDeviceId field. A nested-only reference
    is therefore deliberately NOT reported as ready. No raw identifier escapes.
    """
    if not isinstance(device, dict):
        return 'indisponible'
    root = device.get('cpDeviceId')
    meta = device.get('cpDeviceInfo')
    nested = meta.get('cpDeviceId') if isinstance(meta, dict) else None
    root_ok, nested_ok = _valid_private_id(root), _valid_private_id(nested)
    if root_ok and nested_ok:
        return 'racine_et_infos_concordantes' if root == nested else 'racine_et_infos_differentes'
    if root_ok:
        return 'racine_presente'
    if nested_ok:
        return 'infos_seulement'
    if (root is not None and not root_ok) or (nested is not None and not nested_ok):
        return 'format_non_reconnu'
    return 'absent'


def audit_cached_platforms(devices: object) -> dict:
    """Use only sanitized, normalized cached booleans and enums. Zero requests."""
    if not isinstance(devices, dict):
        return {'resultat': 'inventaire_indisponible', 'appels_http': 0,
                'commandes_ptz': 0}
    cameras=[]
    for device in devices.values():
        if not isinstance(device, dict) or not device.get('is_camera'):
            continue
        model = device.get('model')
        model_safe = model if model in ('C5L','C9C3CA11') else 'autre_modele'
        platform = device.get('ptz_iot_platform','indeterminee')
        platform = platform if platform in ('Gz','Ty') else 'indeterminee'
        source = device.get('ptz_svc_status','champ_absent')
        source = source if source in ('self','autre_que_self','champ_absent','champ_absent_ou_vide') else 'champ_absent'
        id_status = device.get('ptz_tuya_reference_status','indisponible')
        allowed = {'racine_et_infos_concordantes','racine_et_infos_differentes',
                   'racine_presente','infos_seulement','format_non_reconnu','absent'}
        if id_status not in allowed:
            id_status = 'indisponible'
        cameras.append({'camera_index': len(cameras)+1,
                        'modele': model_safe,
                        'plateforme_iot': platform,
                        'svcType_categorie': source,
                        'identifiant_sdk_tuya': id_status,
                        'reference_racine_disponible': id_status in {
                            'racine_et_infos_concordantes','racine_et_infos_differentes','racine_presente'},
                        'capacite_ptz_confirmee': False})
        if len(cameras) >= 10:
            break
    c5l = [c for c in cameras if c['modele']=='C5L']
    only_c5l = c5l[0] if len(c5l) == 1 else None
    return {
        'resultat':'audit_transport_0_8_7',
        'source':'cache_/v1/dev/getList_support.svcType_et_cpDeviceId',
        'reference_apk':'AOSU_Android_5.10.12',
        'cameras':cameras,
        'c5l_plateforme':only_c5l['plateforme_iot'] if only_c5l else 'indeterminee',
        'c5l_identifiant_sdk_tuya':only_c5l['identifiant_sdk_tuya'] if only_c5l else 'indisponible',
        'c5l_reference_racine_disponible':only_c5l['reference_racine_disponible'] if only_c5l else False,
        'appels_http':0, 'commandes_ptz':0, 'session_video_ouverte':False,
        'interpretation':'Presence de cpDeviceId ne prouve ni acces Tuya ni support PTZ. '
                          'Absence dans getList ne prouve pas son absence dans le SDK Android.',
    }
