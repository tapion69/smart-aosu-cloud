"""Manual, read-only Thing SDK P2P prerequisite comparison for one C9C.

The authoritative native Android code consults DeviceBean, skills p2pType,
localKey, CameraInfoBean P2P config, policy and session metadata.
AOSU/Tuya OEM cloud responses may have different schemas: absence of a field
here does NOT prove the native SDK lacks it. No identity or video proof.
Only literal booleans/enums returned. No identifiers, keys, JSON, URIs,
account metadata, camera commands, PTZ, MQTT, SDP or filesystem writes.
"""
from __future__ import annotations
from typing import Any

_ALLOWED_CONTAINERS = (
    'data', 'result', 'device', 'deviceBean', 'deviceInfo',
    'productBean', 'p2pConfig', 'session', 'config', 'rtcConfig',
)


def _objects(raw: Any) -> list[dict]:
    todo = [(raw, 0)]
    seen = set()
    objects: list[dict] = []
    while todo and len(objects) < 65:
        node, depth = todo.pop(0)
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        objects.append(node)
        if depth < 5:
            for key in _ALLOWED_CONTAINERS:
                child = node.get(key)
                if isinstance(child, dict):
                    todo.append((child, depth + 1))
    return objects


def _present(nodes: list[dict], fields: tuple[str, ...]) -> bool:
    return any(isinstance(node.get(name), str)
               and 0 < len(node[name].strip()) <= 8192
               for node in nodes for name in fields)


def _thing4(nodes: list[dict]) -> bool:
    for obj in nodes:
        skills = obj.get('skills')
        if isinstance(skills, dict) and type(skills.get('p2pType')) is int:
            if skills['p2pType'] == 4:
                return True
    return False


def summarize_native_prerequisites_b37(*, tuya_device: Any,
                                       tuya_detail: Any,
                                       rtc_response: Any,
                                       expected_tuya_id: str,
                                       rtc_accepted: bool,
                                       detail_accepted: bool) -> dict:
    """Never infer AOSU ↔ Tuya camera identity or native protocol compatibility."""
    device_nodes = _objects(tuya_device)
    detail_nodes = _objects(tuya_detail) if detail_accepted else []
    rtc_nodes = _objects(rtc_response) if rtc_accepted else []
    # Only the device-identifying keys at the root/device-data levels may
    # support an explicit match, not arbitrary product or nested IDs.
    id_nodes = [
        node for node in detail_nodes if
        isinstance(node.get('devId'), str) or isinstance(node.get('deviceId'), str)
    ]
    seen_ids = {node[key] for node in id_nodes for key in ('devId', 'deviceId')
                if isinstance(node.get(key), str) and node[key]}
    same_device = bool(expected_tuya_id) and seen_ids == {expected_tuya_id}
    all_dev = device_nodes + detail_nodes
    categories = {obj.get('category', '').strip().lower() for obj in all_dev
                  if isinstance(obj.get('category'), str)}
    local_key = _present(all_dev, ('localKey',))
    skills_thing4 = _thing4(all_dev)
    product_bean = any(
        isinstance(obj.get('productBean'), dict) for obj in all_dev)
    return {
        'diagnostic': 'aosu_c9c_thing_sdk_preflight_b37',
        'etat': ('lectures_obtenues' if detail_accepted and rtc_accepted
                 else 'lectures_partielles'),
        'fiche_tuya_acceptee': detail_accepted is True,
        'rtc_ipc_v4_accepte': rtc_accepted is True,
        'fiche_tuya_memes_identifiants': same_device,
        'type_p2p_thing4_present': skills_thing4,
        'cle_locale_presente': local_key,
        'product_bean_present': product_bean,
        'categorie_camera_sp_presente': 'sp' in categories,
        'p2p_config_structure_presente': any(
            isinstance(obj.get('p2pConfig'), dict)
            for obj in rtc_nodes),
        'p2p_policy_champ_present': any(
            obj.get('p2pPolicy') is not None for obj in rtc_nodes),
        'session_tid_champ_present': _present(
            rtc_nodes, ('sessionTid',)),
        'p2p_id_champ_present': _present(
            rtc_nodes, ('p2pId', 'p2pID', 'p2p_id')),
        'ipc_session_id_present': _present(rtc_nodes, ('sessionId',)),
        'client_tid_champ_present': _present(
            rtc_nodes, ('clientTid',)),
        'android_devicebean_reproduit': False,
        'native_sdk_initialized': False,
        'parite_binaire_validee': False,
        'liaison_aosu_tuya_prouvee': False,
        'video_autorisee': False,
        'appels_reseau_supplementaires_hors_fiche_rtc': 0,
        'offres_mqtt_envoyees': 0,
        'commandes_camera': 0,
        'commandes_ptz': 0,
        'identifiants_retournes': False,
        'secrets_retournes': False,
    }


def _camera_info_root_b39(raw: Any, *, accepted: bool) -> dict:
    """Get only the expected RTC CameraInfoBean envelope, not nested ICE IDs."""
    if not accepted or not isinstance(raw, dict):
        return {}
    node = raw
    for _ in range(3):
        if isinstance(node.get('data'), dict):
            node = node['data']
        elif isinstance(node.get('result'), dict):
            node = node['result']
        else:
            break
    return node if isinstance(node, dict) else {}


def _specified_type_b39(value: Any) -> str:
    """Fixed category, never return a server-defined identifier or text."""
    if type(value) is int or (
        isinstance(value, str) and value in ('1', '2', '4')):
        try:
            number = int(value)
        except (ValueError, TypeError):
            return 'autre'
        return ('thing_4' if number == 4 else
                'p2p_2' if number == 2 else
                'tutk_1' if number == 1 else 'autre')
    return 'absent' if value is None else 'autre'


def _rtc_sdk_fields_b38(raw: Any, *, accepted: bool) -> dict:
    """Public field-presence report, without decoding private config strings."""
    nodes = _objects(raw) if accepted else []
    camera_info = _camera_info_root_b39(raw, accepted=accepted)
    # SDK processCameraInfo reads CameraInfoBean.id for specified type 4,
    # NOT CameraInfoBean.p2pId. Never mine nested session or ICE 'id' keys.
    camera_id = camera_info.get('id')
    info_id = (isinstance(camera_id, str) and 0 < len(camera_id.strip()) <= 256
               and camera_id == camera_id.strip())
    specified = _specified_type_b39(camera_info.get('p2pSpecifiedType'))
    p2p_values = [obj.get('p2pConfig') for obj in nodes
                  if 'p2pConfig' in obj]
    has_map = any(isinstance(v, dict) for v in p2p_values)
    has_str = any(isinstance(v, str) and bool(v.strip())
                  for v in p2p_values)
    p2p_shape = ('formes_multiples' if has_map and has_str else
                 'objet' if has_map else 'chaine' if has_str else 'absent')
    return {
        'acceptee': accepted is True,
        'p2p_id': _present(nodes, ('p2pId', 'p2pID', 'p2p_id')),
        'camera_info_id_racine_present': info_id is True,
        'p2p_specified_type_categorie': specified,
        'branche_thing4_compatible_avec_champs':
            specified == 'thing_4' and info_id and p2p_shape != 'absent',
        'session_tid': _present(nodes, ('sessionTid',)),
        'p2p_policy': any(obj.get('p2pPolicy') is not None for obj in nodes),
        'p2p_specified_type': any(
            obj.get('p2pSpecifiedType') is not None for obj in nodes),
        'p2p_config_format': p2p_shape,
        'session_id': _present(nodes, ('sessionId',)),
        'password': _present(nodes, ('password',)),
        'token': _present(nodes, ('token',)),
        'skill': any(isinstance(obj.get('skill'), (dict, str))
                     and bool(obj['skill']) for obj in nodes),
        'p2p_type_thing4': any(
            type(obj.get('p2pType')) is int
            and obj['p2pType'] == 4 for obj in nodes),
    }


def compare_rtc_sdk_b38(ipc_v4: Any, classic: Any, *,
                         ipc_accepted: bool, classic_accepted: bool) -> dict:
    """Two already-authorized read-only RTC responses; zero extra requests.

    This is NOT a camera probe or a native SDK initialization. In particular,
    a missing clientTid in both APIs is expected: it is locally generated by
    ThingSmartCameraP2PSync.getClientTid in the Android implementation.
    """
    ipc = _rtc_sdk_fields_b38(ipc_v4, accepted=ipc_accepted)
    sdk = _rtc_sdk_fields_b38(classic, accepted=classic_accepted)
    return {
        'diagnostic': 'aosu_c9c_sdk_rtc_comparison_b39',
        'ipc_v4': ipc,
        'rtc_sdk_classique': sdk,
        'p2p_id_seulement_classique': sdk['p2p_id'] and not ipc['p2p_id'],
        'p2p_id_absent_des_deux': not sdk['p2p_id'] and not ipc['p2p_id'],
        'client_tid_produit_localement_par_sdk': True,
        'session_init_appelee': False,
        'identite_c9c_etablie': False,
        'creation_p2p_effectuee': False,
        'video_autorisee': False,
        'appels_reseau_supplementaires': 0,
        'commandes_camera': 0, 'commandes_ptz': 0,
        'offres_mqtt': 0,
        'secrets_retournes': False,
        'identifiants_retournes': False,
    }
