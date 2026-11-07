"""b69 — Offline lengths of our current experimental MQTT PTZ packets.

Compares our exact b68 publisher's *theoretical TLS record lengths* with the
149-byte TLS records found in owner-provided AOSU Android PCAPs. These PCAP
records are temporal PTZ candidates, NOT decrypted / attributable datapoints.

The function never opens a socket, never reads a localKey, never constructs a
packet using an owner's device identifier and never publishes motor commands.
Dummy IDs of the same length and an all-zero synthetic AES key are used only in
memory; only numeric lengths and fixed categorical status are returned.
"""
from __future__ import annotations

from typing import Any

TLS12_AES_GCM_RECORD_OVERHEAD = 5 + 8 + 16
OBSERVED_PCAP_TLS_BYTES = 149
SAMPLE_TIME_10_DIGITS = 1793440000


def estimate_lengths_for_id_length(identifier_length: int, layout: str) -> dict:
    """Return output byte sizes from b68's *actual* serializer, never real data.

    QoS1, exact topic syntax, PV2.2 envelope and an independent synthetic key.
    TLS estimates assume a single TLS1.2 AES-GCM application-data record with
    no batching or fragmentation, as observed in the reference analysis.
    """
    if type(identifier_length) is not int or not 5 <= identifier_length <= 128:
        raise ValueError('invalid synthetic identifier length')
    if layout not in ('compact', 'legacy'):
        raise ValueError('invalid layout')
    from .ptz_live_control_b56 import encode_command, _pack_qos1
    dummy_id = 'X' * identifier_length
    dummy_key = b'0' * 16
    topic = 'smart/mb/out/' + dummy_id
    out = {}
    for label, dp, value in (('direction', 119, '0'), ('stop', 116, True)):
        encoded = encode_command(dummy_id, dummy_key,
            device_id=dummy_id, dp=dp, value=value, o=1010, s=4,
            timestamp=SAMPLE_TIME_10_DIGITS, layout=layout)
        packet = _pack_qos1(topic, encoded, 2)
        mqtt_bytes = len(packet)
        estimate = mqtt_bytes + TLS12_AES_GCM_RECORD_OVERHEAD
        out[label] = {
            'mqtt_qos1_bytes': mqtt_bytes,
            'tls12_aes_gcm_record_bytes_theoriques': estimate,
            'ecart_avec_149_bytes': estimate - OBSERVED_PCAP_TLS_BYTES,
            'longueur_compatible_149': estimate == OBSERVED_PCAP_TLS_BYTES,
        }
    return out


def audit_packet_size_b69(coordinator: Any) -> dict:
    """Cache-only diagnostic; no app, camera or network interaction."""
    report = {
        'diagnostic': 'aosu_taille_mqtt_b69',
        'mode': 'calcul_hors_ligne_avec_identifiants_fictifs',
        'lecture_seule': True,
        'appels_reseau': 0,
        'connexion_mqtt': False,
        'commandes_ptz_envoyees': 0,
        'commandes_stop_envoyees': 0,
        'video_modifiee': False,
        'identifiants_retournes': False,
        'secrets_lus': False,
        'secrets_retournes': False,
        'reference_pcap_tls_octets': OBSERVED_PCAP_TLS_BYTES,
        'reference_pcap_dechiffree': False,
    }
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_live_control_b56 import _sdk_cadv_layout
    selected, reason = select_c5l_oem(coordinator)
    if selected is None:
        return {**report, 'etat': 'cache_oem_c5l_indisponible',
                'raison': reason if reason in {
                    'appareil_aosu_non_confirme', 'cache_oem_absent_ou_expire',
                    'cache_oem_non_structure', 'selection_ambigue',
                    'identifiant_non_compatible', 'ptz_absent_fiche_cible'
                } else 'selection_non_validee'}
    device_id, row, method = selected
    if method not in ('nom_unique_confirme_par_utilisateur', 'identification_exacte'):
        return {**report, 'etat': 'selection_non_validee'}
    try:
        layout, status = _sdk_cadv_layout(row)
    except ValueError:
        return {**report, 'etat': 'versions_cadv_contradictoires'}
    length = len(device_id)  # length only; never use the real value to encode
    if not 5 <= length <= 128:
        return {**report, 'etat': 'identifiant_non_compatible'}
    measurements = estimate_lengths_for_id_length(length, layout)
    # Do not assert that the 149-byte observed packets actually contain PTZ.
    match = all(x['longueur_compatible_149'] for x in measurements.values())
    return {
        **report,
        'etat': 'simulation_locale_terminee',
        'version_cadv': status,
        'branche_encodeur': layout,
        'scenario_tls': 'un_enregistrement_tls12_aes128gcm_par_publication_qos1',
        'tailles_simulees': measurements,
        'compatibilite_taille_pcap': (
            'longueur_compatible_sous_hypotheses' if match
            else 'longueur_differente_sous_hypotheses'),
        'publication_camera_confirmee': False,
        'mouvement_physique_confirme': False,
        'arret_physique_confirme': False,
        'conclusion': 'taille_seule_ne_permet_pas_de_decoder_ni_authentifier_une_commande',
    }
