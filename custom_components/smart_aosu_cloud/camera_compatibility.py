"""Read-only offline assessment of available AOSU camera models.

Only hard-coded public model names and feature flags leave the coordinator.
No cloud query, no identifiers, serials, tokens, names, or PTZ commands.
"""
from __future__ import annotations
from typing import Any

_PUBLIC_MODELS = {'c5l': 'C5L', 'c9c3ca11': 'C9C3CA11', 'h1l': 'H1L'}


def audit_camera_compatibility(data: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        'diagnostic': 'aosu_compatibilite_cameras_b33',
        'origine': 'cache_coordinator_home_assistant',
        'appels_reseau': 0, 'commandes_camera': 0,
        'dispositifs_analyses': 0, 'cameras_recensees': 0,
        'stations_h1l': 0, 'cameras': [],
        'ptz_actif': False,
        'identifiants_ou_noms_prives_retournes': False,
    }
    if not isinstance(data, dict):
        report['etat'] = 'aucun_cache_utilisable'
        return report
    for row in list(data.values())[:24]:
        if not isinstance(row, dict):
            continue
        report['dispositifs_analyses'] += 1
        raw = str(row.get('model') or '').strip().lower()
        model = _PUBLIC_MODELS.get(raw, 'non_identifie')
        if model == 'H1L':
            report['stations_h1l'] += 1
        if row.get('is_camera') is not True:
            continue
        report['cameras_recensees'] += 1
        entry: dict[str, Any] = {
            'numero': report['cameras_recensees'],
            'modele_public': model,
            'miniature_cloud_connue': row.get('has_image_ref') is True,
            'methode_video_c5l_disponible_dans_integration': model == 'C5L',
            'transport_station_h1l_a_verifier': model == 'C9C3CA11',
            'ptz_identifie': False,
        }
        report['cameras'].append(entry)
    report['etat'] = 'inventaire_cache_analyse'
    report['note'] = ('La compatibilite C5L indique uniquement le chemin de la camera C5L deja teste; '
                      'la video des autres appareils et le PTZ ne sont pas valides.')
    return report
