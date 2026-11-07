"""b70 — Read-only, bounded evidence for Thing-model/DP publication branch.

APK AOSU 5.10.12 classes4.dex method 32865:
    if DeviceRespBean.communication.dataModel == DataModelType.THING_MODEL.getType():
        if DeviceRespBean.thingModel is available:
            publishThingMessageWithType(..., ThingSmartThingMessageType.PROPERTY)
            return
        request the Thing Model by product ID/version, then return
    else:
        publishDpsInPipeline(...)

classes8.dex DataModelType.<clinit> #14053 confirms:
THING_DP.getType() = 1; THING_MODEL.getType() = 2.
No claim that a particular camera uses either branch without live dataModel.
No network, crypto, secrets, IDs, motor or video access. This module receives
in-memory OEM data only and returns whitelisted categories/numbers.
"""
from __future__ import annotations
from typing import Any
import json

MAX_NODES = 800
MAX_DEPTH = 12
SAFE_MODEL_NAMES = {
    'thing_model': 'thing_model',
    'thingmodel': 'thing_model',
    'thing': 'thing_model',
    'dp_model': 'dp_model',
    'dpmodel': 'dp_model',
    'dp': 'dp_model',
    'legacy': 'dp_model',
}


def _model_class(value: Any) -> tuple[str, int | None]:
    """Do not expose arbitrary API strings (could contain credentials/IDs)."""
    if type(value) is int and value == 1:
        return 'thing_dp_sdk_enum', 1
    if type(value) is int and value == 2:
        return 'thing_model_sdk_enum', 2
    if type(value) is int and 0 <= value <= 15:
        return 'entier_non_documente', value
    if isinstance(value, str):
        normalized = value.strip().lower().replace(' ', '_').replace('-', '_')
        if normalized in SAFE_MODEL_NAMES:
            return SAFE_MODEL_NAMES[normalized], None
        if normalized in {'1','2'}:
            return ('thing_dp_sdk_enum' if normalized=='1' else 'thing_model_sdk_enum'),int(normalized)
        if normalized in {str(x) for x in range(16)}:
            return 'entier_texte_non_documente', int(normalized)
        return 'texte_non_interprete', None
    return 'type_non_interprete', None


# AOSU APK 5.10.12, classes7.dex CommunicationEnum.<clinit> #9992.
# IMPORTANT: these are communication type values, NOT DataModelType values.
_COMMUNICATION_TYPES = {
    -1: 'other', 0: 'lan', 1: 'mqtt', 2: 'http', 3: 'ble',
    4: 'sigmesh', 5: 'thing_mesh', 6: 'thing_beacon',
    8: 'thing_matter', 12: 'yu_mqtt', 100: 'cloud_mode',
}
_NAME_TYPES = {
    'lan': 'lan', 'local': 'lan', 'intranet': 'lan',
    'mqtt': 'mqtt', 'mqttclient': 'mqtt', 'mqtt_online': 'mqtt',
    'yu_mqtt': 'yu_mqtt', 'yu-mqtt': 'yu_mqtt',
    'http': 'http', 'ble': 'ble', 'cloud': 'cloud_mode',
    'cloud_mode': 'cloud_mode', 'internet': 'cloud_mode', 'wan': 'cloud_mode',
    'sigmesh': 'sigmesh', 'thing_mesh': 'thing_mesh',
    'thing_beacon': 'thing_beacon', 'thing_matter': 'thing_matter',
}


def _communication_type(item: Any) -> str | None:
    """Only release a known SDK enum name, never unknown values or raw IDs."""
    if type(item) is int:
        return _COMMUNICATION_TYPES.get(item)
    if isinstance(item, str):
        candidate = item.strip().lower()
        if candidate in _NAME_TYPES:
            return _NAME_TYPES[candidate]
        if len(candidate) <= 4 and candidate.lstrip('-').isdigit():
            try:
                return _COMMUNICATION_TYPES.get(int(candidate))
            except ValueError:
                return None
    return None


def _mode_flags(value: Any) -> dict:
    """Read DeviceRespBean.CommunicationModuleT.getType() safely.

    In the SDK, communicationModes is typically a list of {type: integer},
    which was overlooked in b70. Strings and unknown types are not emitted.
    """
    if isinstance(value, str) and len(value) <= 8192 and value.strip().startswith(('[', '{')):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            pass
    shape = ('liste' if isinstance(value, list) else
             'objet' if isinstance(value, dict) else
             'texte' if isinstance(value, str) else 'autre')
    found: set[str] = set()
    ordered: list[str] = []
    unknown = 0
    entries = 0
    # Fixed, bounded walk: objects like {type:12}, lists of those, or tokens.
    stack = [(value, 0)]
    seen: set[int] = set()
    while stack and entries < 80:
        node, depth = stack.pop()
        entries += 1
        if isinstance(node, (list, dict)):
            if id(node) in seen:
                continue
            seen.add(id(node))
        if isinstance(node, list) and depth < 4:
            stack.extend((child, depth + 1) for child in reversed(node[:60]))
        elif isinstance(node, dict) and depth < 4:
            # SDK field is `type`. Do not iterate arbitrary dictionary keys
            # because opaque IDs/user data may coincide with enum names.
            if 'type' in node:
                kind = _communication_type(node['type'])
                if kind is None:
                    unknown += 1
                else:
                    found.add(kind)
                    if len(ordered) < 60: ordered.append(kind)
            else:
                for key in ('modules', 'communicationModes', 'items', 'list'):
                    child = node.get(key)
                    if isinstance(child, (list, dict)):
                        stack.append((child, depth + 1))
        else:
            kind = _communication_type(node)
            if kind is None:
                unknown += 1
            else:
                found.add(kind)
                if len(ordered) < 60: ordered.append(kind)
    return {
        'present': True, 'forme': shape, 'nombre_noeuds': entries,
        'types_sdk_reconnus': sorted(found),
        'ordre_types_sdk_b72': ordered,
        'types_non_interpretes': unknown,
        'analyse_bornee': bool(stack),
        'mqtt': bool({'mqtt','yu_mqtt'} & found),
        'cloud': 'cloud_mode' in found,
        'local': 'lan' in found,
    }


def inspect_publication_route_b70(oem: Any) -> dict:
    """Report structural evidence, never return source values except small ints."""
    models: set[tuple[str, int | None]] = set()
    communications = 0
    thing_present = 0
    product_identification = False
    product_bean_capabilities: set[int] = set()
    product_bean_present = False
    product_bean_capability_invalide = False
    modes: list[dict] = []
    seen: set[int] = set()
    stack = [(oem, 0, False)]
    scanned = 0
    while stack and scanned < MAX_NODES:
        node, depth, in_communication = stack.pop()
        if depth > MAX_DEPTH or not isinstance(node, (dict, list)):
            continue
        if id(node) in seen:
            continue
        seen.add(id(node))
        scanned += 1
        if isinstance(node, list):
            for child in node[:100]:
                if isinstance(child, (dict,list)):
                    stack.append((child, depth+1, in_communication))
            continue
        if in_communication and 'dataModel' in node:
            models.add(_model_class(node['dataModel']))
        if in_communication and 'communicationModes' in node:
            modes.append(_mode_flags(node['communicationModes']))
        if 'thingModel' in node and node['thingModel'] not in (None, '', [], {}):
            thing_present += 1
        if 'productId' in node and 'productVer' in node:
            product_identification = True
        # The SDK uses DeviceBean.getProductBean().getCapability() == 8
        # in qpbpqpq.bdpdqbp, classes4.dex method 33576. Inspect *only*
        # productBean.capability, never a similarly named field elsewhere.
        pb = node.get('productBean')
        if isinstance(pb, dict):
            product_bean_present = True
            if 'capability' in pb:
                raw = pb['capability']
                val = None
                if type(raw) is int and 0 <= raw <= 255:
                    val = raw
                elif isinstance(raw, str) and raw.isascii() and raw.isdecimal() and len(raw) <= 3:
                    val = int(raw)
                if val is None:
                    product_bean_capability_invalide = True
                else:
                    product_bean_capabilities.add(val)
        for key,child in list(node.items())[:150]:
            if key in ('password','localKey','token','accessToken','refreshToken',
                       'privateKey','sessionKey','secret','credentials','credential'):
                continue
            if key == 'communication' and isinstance(child,dict):
                communications += 1
            if isinstance(child,(dict,list)):
                stack.append((child,depth+1,key == 'communication' or in_communication))
    # Avoid an arbitrary raw text/ID escaping through model enum output.
    values = [{'classe': cl, **({'valeur_numerique': n} if n is not None else {})}
              for cl,n in sorted(models, key=lambda x:(x[0],-1 if x[1] is None else x[1]))]
    if len(values)>1:
        verdict='plusieurs_modeles_ou_occurrences_a_verifier'
    elif not values:
        verdict='data_model_non_fourni_par_api_oem'
    elif values[0]['classe']=='thing_model_sdk_enum':
        verdict='data_model_2_branche_thing_model_sdk'
    elif values[0]['classe']=='thing_dp_sdk_enum':
        verdict='data_model_1_branche_thing_dp_sdk'
    elif values[0]['classe']=='thing_model':
        verdict='nom_de_modele_thing_reconnu_non_confirme_par_runtime'
    elif values[0]['classe']=='dp_model':
        verdict='nom_de_modele_dp_reconnu_non_confirme_par_runtime'
    else:
        verdict='data_model_present_enum_sdk_a_interpreter'
    return {
        'diagnostic': 'aosu_publication_sdk_b72',
        'lecture_seule': True,
        'noeuds_examines': scanned,
        'limite_noeuds_atteinte': scanned >= MAX_NODES,
        'blocs_communication': communications,
        'champ_data_model_trouve': bool(values),
        'valeurs_data_model': values,
        'thing_model_present_dans_reponse': thing_present > 0,
        'product_id_et_version_presents': product_identification,
        'champ_communication_modes_trouve': bool(modes),
        'modes_observes': len(modes),
        'modes_sdk_b71': [
            {'forme':m['forme'], 'nombre_noeuds':m['nombre_noeuds'], 'types_sdk_reconnus':m['types_sdk_reconnus'],
             'types_non_interpretes':m['types_non_interpretes'],
             'ordre_types_sdk_b72':m['ordre_types_sdk_b72'],
             'analyse_bornee':m['analyse_bornee']} for m in modes[:4]
        ],
        'aiguillage_sdk_b72': {
            'selection_par_ordre_des_moyens': 'pipeline_parcourt_communicationModes_dans_l_ordre',
            'ordre_expose_sans_preuve_de_transport_effectif': True,
            'productBean_present': product_bean_present,
            'capability_presente': bool(product_bean_capabilities),
            'capability_8_presente': 8 in product_bean_capabilities,
            'capability_invalide_presente': product_bean_capability_invalide,
            'plusieurs_capabilities_contradictoires': len(product_bean_capabilities) > 1,
            'chemin_runtime_confirme': False,
            'reference_apk': 'AbsThingDevice_publishDpsInPipeline_32870_qpbpqpq_bdpdqbp_33576',
        },
        'enum_communication_b71': 'classes7.dex_CommunicationEnum_clinit_9992',
        'mode_mqtt_annonce': any(item['mqtt'] for item in modes),
        'mode_cloud_annonce': any(item['cloud'] for item in modes),
        'mode_local_annonce': any(item['local'] for item in modes),
        'verdict': verdict,
        'publication_mqtt_effective_confirmee': False,
        'mouvement_physique_confirme': False,
        'arret_physique_confirme': False,
        'identifiants_retournes': False,
        'secrets_retournes': False,
        'appels_reseau': 0,
        'commandes_ptz_envoyees': 0,
    }
