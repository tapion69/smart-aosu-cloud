"""b43: preflight of Tuya online PTZ publishing, strictly offline/read-only.

The existing HA MQTT connection is an RTC *signaling* client; it is NOT the
Android Smart App SDK IThingDevice.publishDps publisher. Never reuse its media
signaling topic to send camera control and never derive a command from TLS sizes.

Every value returned to HA belongs to a fixed, non-sensitive vocabulary.
Raw OEM inventory, device IDs, names, passwords and session material remain in RAM.
"""
from __future__ import annotations

import time
from typing import Any


def audit_ptz_publication(coordinator: Any) -> dict[str, object]:
    """One snapshot, no HTTP, socket, auth refresh, movement, or media changes."""
    from .ptz_readiness import audit_ptz_readiness
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_schema_b38 import inspect_ptz_schema
    from .tuya_uid_gateway import TuyaAuthSession

    client = coordinator.client
    readiness = audit_ptz_readiness(coordinator, client)
    cached = readiness.get('cache_oem_recent') is True
    selected, reason = select_c5l_oem(coordinator)
    record = selected[1] if selected is not None else None
    schema = inspect_ptz_schema(record)  # sanitized; never include raw data
    control = schema['datapoints']['ptz_control']
    stop = schema['datapoints']['ptz_stop']
    source = selected[2] if selected else 'non_validee'

    # A valid OEM auth session is *not* equivalent to SDK DP-publish permission.
    session = getattr(client, '_tuya_oem_session', None)
    age = time.monotonic() - session.acquired_at if isinstance(session, TuyaAuthSession) else -1
    session_fresh = 0 <= age < 1200
    controller = getattr(coordinator, 'live_controller', None)
    live = bool(controller is not None and getattr(controller, 'running', False))

    barriers = []
    if readiness.get('modele_c5l_c5l') is not True:
        barriers.append('modele_c5l_non_confirme')
    if not cached:
        barriers.append('inventaire_oem_absent_ou_expire')
    if selected is None:
        # This is a fixed reason emitted by the existing camera selector.
        barriers.append('cible_oem_non_selectionnee')
    elif source != 'identification_exacte':
        barriers.append('lien_oem_uniquement_par_nom')
    if not control['reference_reconnue'] or not stop['reference_reconnue']:
        barriers.append('datapoints_ptz_non_confirmes')
    if control['type_declare'] not in ('enum',) or stop['type_declare'] not in ('bool',):
        barriers.append('types_datapoints_non_confirmes')
    if not (control['ecriture_annoncee'] and stop['ecriture_annoncee']):
        barriers.append('droits_ecriture_schema_non_confirmes')
    if not session_fresh:
        barriers.append('session_oem_inactive_ou_expiree')
    barriers.extend(('publication_sdk_tuya_non_implementee', 'stop_non_valide_physiquement'))

    # Always refuse to unlock motor controls, even with a complete schema.
    # On-disk PCAP evidence is intentionally not read by Home Assistant.
    if not cached:
        next_step = 'actualiser_inventaire_oem_par_action_existante'
    elif selected is None or not (control['reference_reconnue'] and stop['reference_reconnue']):
        next_step = 'auditer_fiche_detaillee_oem_par_action_existante'
    elif control['type_declare'] != 'enum' or stop['type_declare'] != 'bool':
        next_step = 'confirmer_types_depuis_fiche_detaillee_et_sdk'
    else:
        next_step = 'etudier_transport_publishdps_sdk_sans_envoyer_de_mouvement'

    return {
        'diagnostic': 'aosu_ptz_publication_b43',
        'lecture_seule': True,
        'cible': 'C5L',
        'modele_c5l_confirme': readiness.get('modele_c5l_c5l') is True,
        'inventaire_oem_recent': cached,
        'cible_oem_selectionnee': selected is not None,
        'methode_correspondance': source,
        'raison_selection': 'selection_ok' if selected is not None else (
            reason if reason in ('appareil_aosu_non_confirme','cache_oem_absent_ou_expire',
                                 'cache_oem_non_structure','selection_ambigue',
                                 'identifiant_non_compatible','ptz_absent_fiche_cible')
            else 'selection_indeterminee'),
        'session_oem_recente': session_fresh,
        'direct_video_en_cours': live,
        'schema_depuis_cache': True,
        'datapoints': {
            'ptz_control': {
                'code_reconnu': control['reference_reconnue'],
                'type_declare': control['type_declare'],
                'ecriture_annoncee': control['ecriture_annoncee'],
                'valeurs_enum_disponibles': control['valeurs_enum_chiffrees'],
                'direction_c5l_validee': False,
            },
            'ptz_stop': {
                'code_reconnu': stop['reference_reconnue'],
                'type_declare': stop['type_declare'],
                'ecriture_annoncee': stop['ecriture_annoncee'],
                'arret_c5l_valide': False,
            },
        },
        'canaux': {
            'mqtt_8883_observe_application': 'correlation_pcap_historique_non_dechiffree',
            'mqtt_integration': 'signalisation_video_uniquement',
            'transport_publishdps_c5l_valide': False,
            'publication_de_dp_implementee': False,
            'certification_broker_et_topic_ptz': False,
            'autres_transports_possibles': ['https', 'lan'],
        },
        'barrieres': barriers,
        'etape_suivante': next_step,
        'actions_motrices_autorisees': False,
        'commandes_ptz_envoyees': 0,
        'commandes_arret_envoyees': 0,
        'nouvelles_connexions_mqtt': 0,
        'appels_reseau': 0,
        'session_video_modifiee': False,
        'donnees_brutes_conservees': False,
        'identifiants_retournes': False,
        'secrets_retournes': False,
    }
