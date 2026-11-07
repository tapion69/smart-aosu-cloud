"""Smart AOSU b46: passive, secret-free MQTT PTZ encoder prerequisites.

This is a cached-data-only audit of the actual SDK publishDevice requirements:
DeviceBean.pv, DeviceBean.localKey, topicId, sequence and numeric schema.
It NEVER sends MQTT/HTTP, retries, logs raw bodies or enables motor controls.
"""
from __future__ import annotations

import re
from typing import Any

_SUPPORTED_PV = frozenset(('1.1', '2.1', '2.2', '2.3'))


def _limited_nodes(value: Any, cap: int = 120):
    stack = [value]
    visited = 0
    while stack and visited < cap:
        node = stack.pop()
        visited += 1
        if isinstance(node, dict):
            yield node
            for item in list(node.values())[:30]:
                if isinstance(item, (dict, list)):
                    stack.append(item)
        elif isinstance(node, list):
            for item in node[:30]:
                if isinstance(item, (dict, list)):
                    stack.append(item)


def _version(row: dict) -> tuple[str, str]:
    """Only return a public allowlisted SDK revision; never arbitrary server text."""
    for parent in (row, row.get('productBean'), row.get('communication')):
        if not isinstance(parent, dict):
            continue
        for field in ('pv', 'protocolVersion', 'protocol_version'):
            val = parent.get(field)
            if isinstance(val, (str, int, float)) and not isinstance(val, bool):
                pv = str(val).strip()
                if re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,2}', pv):
                    return (pv, 'reconnue' if pv in _SUPPORTED_PV else 'hors_versions_decrites')
                return ('non_publiee', 'valeur_non_reconnue')
    return ('non_publiee', 'champ_absent')


def _numeric_mapping(row: dict) -> dict[str, bool]:
    found = {'ptz_control_119': False, 'ptz_stop_116': False}
    for node in _limited_nodes(row):
        for code, expected, label in [('ptz_control', 119, 'ptz_control_119'),
                                      ('ptz_stop', 116, 'ptz_stop_116')]:
            # Only count explicit code AND numeric ID inside the same entry.
            if node.get('code', node.get('dpCode')) == code:
                raw = node.get('id', node.get('dpId'))
                if type(raw) is int and raw == expected or (
                    isinstance(raw, str) and raw == str(expected)):
                    found[label] = True
            entry = node.get(code)
            if isinstance(entry, dict):
                raw = entry.get('id', entry.get('dpId'))
                if type(raw) is int and raw == expected or (
                    isinstance(raw, str) and raw == str(expected)):
                    found[label] = True
    return found


def audit_mqtt_encoder_readiness(coordinator: Any) -> dict:
    from .ptz_device_detail_b39 import select_c5l_oem
    result = {
        'diagnostic': 'aosu_ptz_mqtt_preflight_b46',
        'lecture_seule': True,
        'origine': 'inventaire_oem_cache_existant',
        'mode_publication_sdk': 'IMqttServer.publishDevice',
        'encodage_sdk': 'dependant_de_pv_localKey_compteurs',
        'codecs_documentes_dans_apk': ['1.1', '2.1', '2.2', '2.3'],
        'camera_oem_selectionnee': False,
        'preuve_identite_forte': False,
        'pv': 'non_publiee',
        'pv_etat': 'non_determine',
        'cle_locale_presente': False,
        'communication_node_present': False,
        'schema_map_present': False,
        'dp_numeriques_correspondance_confirmee': {
            'ptz_control_119': False, 'ptz_stop_116': False},
        'topic_reel_valide': False,
        'publication_mqtt_ptz_implementee': False,
        'arret_moteur_physiquement_valide': False,
        'commande_ptz_autorisee': False,
        'commandes_arret_envoyees': 0,
        'commandes_directionnelles_envoyees': 0,
        'appels_reseau': 0,
        'connexions_mqtt': 0,
        'video_modifiee': False,
        'secrets_retournes': False,
        'identifiants_retournes': False,
    }
    selected, reason = select_c5l_oem(coordinator)
    if selected is None:
        allowed = {'cache_oem_absent_ou_expire', 'selection_ambigue',
                   'appareil_aosu_non_confirme', 'ptz_absent_fiche_cible',
                   'identifiant_non_compatible', 'cache_oem_non_structure'}
        return {**result, 'etat': reason if reason in allowed else 'selection_non_validee',
                'prochaine_etape': 'actualiser_inventaire_oem_existant'}

    _device_id, row, method = selected  # Never return _device_id or row.
    version, state = _version(row)
    communication = row.get('communication')
    communication = communication if isinstance(communication, dict) else {}
    strong = method == 'identification_exacte'
    mappings = _numeric_mapping(row)
    schema_map = row.get('schemaMap')
    result.update({
        'camera_oem_selectionnee': True,
        'preuve_identite_forte': strong,
        'methode_selection': 'identification_exacte' if strong else 'nom_unique_non_certifie',
        'pv': version,
        'pv_etat': state,
        'cle_locale_presente': isinstance(row.get('localKey'), str) and bool(row['localKey']),
        'communication_node_present': isinstance(communication.get('communicationNode'), str)
                                      and bool(communication['communicationNode']),
        'schema_map_present': isinstance(schema_map, (dict, list)) and bool(schema_map),
        'dp_numeriques_correspondance_confirmee': mappings,
    })
    missing = []
    if not strong: missing.append('identite_camera_a_certifier')
    if version not in _SUPPORTED_PV: missing.append('pv_codec_a_confirmer')
    if not result['cle_locale_presente']: missing.append('cle_locale_absente_dans_cache')
    if not result['communication_node_present']: missing.append('communication_node_absent_du_cache')
    if not all(mappings.values()): missing.append('schema_map_numerique_non_certifie')
    # Even all static fields present is insufficient: no tested codec or motor STOP.
    missing.extend(('encodage_mqtt_python_non_valide', 'commande_stop_non_validee'))
    result['barrieres'] = missing
    result['etat'] = ('preparation_mqtt_partielle' if version in _SUPPORTED_PV
                      else 'pv_reelle_non_identifiee')
    result['prochaine_etape'] = 'identifier_codec_pv_et_preparer_tests_hors_ligne'
    return result
