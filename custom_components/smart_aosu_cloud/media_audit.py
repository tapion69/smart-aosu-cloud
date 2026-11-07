"""One bounded, privacy-safe media and event diagnostic, with NO controls.

The known event APIs are read-only. Never report camera names, serial numbers,
HTTP Location, signed URLs, tokens, image contents, or event identifiers.
"""
from __future__ import annotations

import hashlib
import threading
import time
import requests

from .image_fetch import fetch_thumbnail
from .event_feed import _category, _event_code
from .api import AosuCloudError
from . import protocol_060 as proto

API_BASE = 'https://api-eu.aosulife.com'
MAX_BODY = 262144
_SAFE_FIELDS = frozenset({
    'uniformType', 'eventTime', 'imageUrl', 'aiVision', 'videoUrl',
    'coverInfo', 'imageInfo', 'imgUrl', 'thumbnailUrl', 'coverUrl',
    'eventType', 'type', 'sn', 'eid', 'records', 'list', 'items',
})


def _kind(v):
    if v is None: return 'null'
    if isinstance(v, bool): return 'booleen'
    if isinstance(v, dict): return 'objet'
    if isinstance(v, list): return 'liste'
    if isinstance(v, str): return 'texte'
    if isinstance(v, (int, float)): return 'nombre'
    return 'autre'


def _rows_from_body(body):
    if not isinstance(body, dict) or body.get('errno') != 0:
        return None
    data = body.get('data')
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for name in ('list', 'records', 'events', 'items'):
            if isinstance(data.get(name), list):
                return data[name]
        # The vendor may use an unknown list name. Only examine item shapes;
        # never report unknown field names or list contents.
        lists = [v for v in data.values() if isinstance(v, list)]
        if len(lists) == 1:
            return lists[0]
    return None


def _event_summary(body):
    if not isinstance(body, dict) or body.get('errno') != 0:
        return {'etat': 'indisponible'}
    rows = _rows_from_body(body)
    if rows is None:
        return {'etat': 'liste_non_identifiee'}
    counts = {}
    event_type_counts = {}
    recognized = {}
    uniform_inner = {'objet': 0, 'nombre': 0, 'texte': 0, 'liste': 0, 'autre': 0}
    visible = {'uniformType': False, 'eventTime': False,
               'imageUrl': False, 'aiVision': False}
    unrecognized = 0
    for item in rows[:100]:
        if not isinstance(item, dict):
            continue
        for name in visible:
            if name in item:
                visible[name] = True
        raw = item.get('eventType')
        code = _event_code(raw)
        if code is not None and (len(event_type_counts) < 20 or code in event_type_counts):
            event_type_counts[code] = event_type_counts.get(code, 0) + 1
        category = _category(raw)
        tokens = item.get('uniformType')
        if not isinstance(tokens, list):
            tokens = [tokens]
        for val in tokens[:12]:
            kind = _kind(val)
            uniform_inner[kind if kind in uniform_inner else 'autre'] += 1
            uniform_code = _event_code(val)
            if uniform_code is not None and (len(counts) < 20 or uniform_code in counts):
                counts[uniform_code] = counts.get(uniform_code, 0) + 1
            category = category or _category(val)
        if category:
            recognized[category] = recognized.get(category, 0) + 1
        else:
            unrecognized += 1
    return {
        'etat': 'types_reconnus' if recognized else ('types_bruts_disponibles' if (counts or event_type_counts) else 'types_non_decodes'),
        'evenements_dans_liste': min(len(rows), 10000),
        'champs_connus_presents': visible,
        'codes_uniformType_bruts': counts,
        'codes_eventType_bruts': event_type_counts,
        'categories_litterales_reconnues': recognized,
        'types_elements_uniformType': {k:v for k,v in uniform_inner.items() if v},
        'non_interpretes': unrecognized,
        'note': 'pass/stay sont des codes AOSU litteraux verifies dans l APK ; leur interpretation humaine reste provisoire, sans equivalence automatique avec mouvement/personne',
    }


def _summarize(body):
    if not isinstance(body, dict):
        return {'etat': 'format_inconnu'}
    code = body.get('errno')
    if type(code) is not int:
        return {'etat': 'code_inconnu'}
    if code != 0:
        return {'etat': 'refus_serveur', 'code_non_nul': True}
    data = body.get('data')
    out = {'etat': 'accepte', 'type_data': _kind(data)}
    if isinstance(data, list):
        out['nombre_entrees'] = min(len(data), 100000)
    elif isinstance(data, dict):
        out['nombre_champs_data'] = min(len(data), 200)
        lengths = [len(v) for v in data.values() if isinstance(v, list)]
        out['nombre_listes'] = len(lengths)
        out['tailles_listes'] = sorted(lengths, reverse=True)[:5]
        out['nombre_objets'] = sum(isinstance(v, dict) for v in data.values())
    return out


def _event_shape(body):
    """Inspect *only allowlisted field names and types* from sample elements."""
    rows = _rows_from_body(body)
    if rows is None:
        return {'etat': 'liste_non_identifiee'}
    result = {'etat': 'liste_lue', 'elements': min(len(rows), 10000)}
    if not rows:
        return result
    result['types_elements'] = {
        name: sum(_kind(item) == name for item in rows[:30])
        for name in ('objet', 'liste', 'texte', 'nombre')
    }
    candidates = [item for item in rows[:10] if isinstance(item, dict)]
    if candidates:
        fields = {}
        for key in sorted(_SAFE_FIELDS):
            examples = [item[key] for item in candidates if key in item]
            if examples:
                fields[key] = {'type': _kind(examples[0]),
                               'nombre_presents': len(examples)}
        result['champs_reconnus'] = fields
        result['champs_non_affiches_premier_objet'] = min(
            len(set(candidates[0]).difference(_SAFE_FIELDS)), 200
        )
    result['classification'] = _event_summary(body)
    return result


def _camera_event_distribution(body, cameras):
    """Counts per camera index only. Never disclose AOSU device identifiers."""
    rows = _rows_from_body(body)
    if rows is None:
        return {'etat': 'liste_non_identifiee'}
    counts = [0] * len(cameras)
    for row in rows[:100]:
        if not isinstance(row, dict):
            continue
        for idx, sn in enumerate(cameras):
            if row.get('sn') == sn:
                counts[idx] += 1
                break
    return [{'camera_index': index+1, 'nombre_evenements': value}
            for index, value in enumerate(counts)]


def _detail_shape(body):
    """For getInfoByEventTime response: no raw event data may leave RAM."""
    if not isinstance(body, dict) or body.get('errno') != 0:
        return _summarize(body)
    data = body.get('data')
    out = _summarize(body)
    if isinstance(data, dict):
        out['champs_reconnus'] = {key: _kind(data[key])
                                  for key in sorted(_SAFE_FIELDS) if key in data}
        val = data.get('uniformType')
        if type(val) is int and 0 <= val <= 9999:
            out['code_uniformType_brut'] = val
        code = _event_code(data.get('eventType'))
        if code is not None:
            out['code_eventType'] = code
    return out


def _post_readonly(client, path, params, headers, form):
    try:
        response = client.session.post(
            API_BASE + path, params=params, data=form, headers=headers,
            timeout=(8, 20), allow_redirects=False, verify=True,
        )
        if response.status_code != 200:
            return None, {'etat': f'http_{response.status_code}'
                          if type(response.status_code) is int and 100 <= response.status_code <= 599
                          else 'http_inattendu'}
        if len(response.content) > MAX_BODY:
            return None, {'etat': 'reponse_trop_volumineuse'}
        body = response.json()
        return body, _summarize(body)
    except (requests.RequestException, ValueError):
        return None, {'etat': 'erreur_transport_ou_json'}


def inspect_media(client):
    """Manual diagnostic: <=4 event POSTs, <=3 GETs, once per hour/session."""
    with client._dp_lock:
        now = time.monotonic()
        last = getattr(client, '_last_media_probe', 0.)
        if last and now - last < 3600:
            raise AosuCloudError('Diagnostic media limite a une tentative par heure')
        if not client._sid or not client._uid or not client._login_headers or not client._camera_sn_index:
            raise AosuCloudError('Session ou liste d appareils indisponible')
        client._last_media_probe = now
        params, headers = proto.build_device_list_request(
            client._suffix, client._login_headers, client._sid, client._uid
        )
        headers = dict(headers)
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        sns = client._camera_sn_index[:3]
        output = {}
        image_reports = []
        for i, sn in enumerate(sns, start=1):
            key = hashlib.sha256(('aosu-device:' + sn).encode()).hexdigest()[:32]
            photo, mime, status = fetch_thumbnail(client.get_image_url(key))
            image_reports.append({'camera_index': i, 'etat': status,
                                  'format': mime if photo else None,
                                  'taille_octets': len(photo) if photo else 0})
            del photo
        # Two known list APIs, authenticated using the existing working client.
        common = [('sn[]', sn) for sn in sns]
        body, report = _post_readonly(client, '/v1/event/getImageList', params, headers,
                                      common + [('count', '10')])
        camera_counts = None
        if body is not None and report.get('etat') == 'accepte':
            report['structure_elements'] = _event_shape(body)
            camera_counts = _camera_event_distribution(body, sns)
            report['repartition_par_camera'] = camera_counts
        output['images'] = report
        # Targeted, read-only verification of AOSU's exact sn[] filter. Only
        # cameras not represented in the grouped list are probed. Bound to two
        # extra HTTP POSTs total, and disclose no identifiers or event payloads.
        output['images_par_camera'] = []
        if camera_counts is not None:
            missing_probes = 0
            for item in camera_counts:
                index = item['camera_index']
                n = item['nombre_evenements']
                if n:
                    output['images_par_camera'].append({
                        'camera_index': index,
                        'etat': 'presente_dans_liste_groupee',
                        'evenements_correspondant_camera': n,
                    })
                    continue
                if missing_probes >= 2:
                    break
                missing_probes += 1
                individual_body, individual_report = _post_readonly(
                    client, '/v1/event/getImageList', params, headers,
                    [('sn[]', sns[index-1]), ('count', '10')],
                )
                detail = {'camera_index': index, 'etat': individual_report['etat']}
                if individual_body is not None and individual_report.get('etat') == 'accepte':
                    rows = _rows_from_body(individual_body)
                    if rows is not None:
                        matches = [row for row in rows[:100] if
                                   isinstance(row, dict) and row.get('sn') == sns[index-1]]
                        detail['evenements_dans_reponse'] = min(len(rows), 10000)
                        detail['evenements_correspondant_camera'] = len(matches)
                        detail['filtrage_sn_confirme'] = all(
                            isinstance(row, dict) and row.get('sn') == sns[index-1]
                            for row in rows[:100]
                        ) if rows else None
                        detail['classification'] = _event_summary(
                            {'errno': 0, 'data': {'list': matches}}
                        )
                output['images_par_camera'].append(detail)

        ts = int(time.time())
        def event_form(factor):
            return common + [('count', '10'),
                             ('eventTimeGt', str((ts - 86400) * factor)),
                             ('eventTimeLt', str(ts * factor))]
        body, report = _post_readonly(client, '/v1/event/getList', params, headers,
                                      event_form(1000))
        if body is not None and report.get('etat') == 'accepte':
            report['classification'] = _event_summary(body)
            report['structure_elements'] = _event_shape(body)
        output['evenements_millisecondes'] = report
        # Only probe alternative timestamp unit when the first query returns an empty list.
        initial_rows = _rows_from_body(body)
        alt_performed = initial_rows is not None and len(initial_rows) == 0
        if alt_performed:
            body_s, report_s = _post_readonly(client, '/v1/event/getList', params, headers,
                                             event_form(1))
            if body_s is not None and report_s.get('etat') == 'accepte':
                report_s['classification'] = _event_summary(body_s)
                report_s['structure_elements'] = _event_shape(body_s)
            output['evenements_secondes'] = report_s
        else:
            output['evenements_secondes'] = {'etat': 'non_necessaire_ou_inapplicable'}

        # Try exactly ONE recent recorded cover event from the existing inventory.
        # This uses the exact APK endpoint field names; no guessing an event ID.
        cover_index = getattr(client, '_cover_time_by_sn', {})
        match = next(((i, sn, cover_index[sn]) for i, sn in enumerate(sns, 1)
                      if sn in cover_index), None)
        if match:
            index, sn, when = match
            body_d, report_d = _post_readonly(
                client, '/v1/event/getInfoByEventTime', params, headers,
                [('sn', sn), ('eventTime', str(when))],
            )
            if body_d is not None and report_d.get('etat') == 'accepte':
                report_d = _detail_shape(body_d)
            output['evenement_couverture'] = {'camera_index': index, **report_d}
        else:
            output['evenement_couverture'] = {'etat': 'horodatage_couverture_absent'}

        return {
            'resultat': 'audit_cible_0_8_5', 'mode': 'lecture_seule',
            'appels_http_max': 6 + len(image_reports),
            'images_evenements': output,
            'miniatures_tests': image_reports,
            'classification': 'Codes numeriques bruts sans correspondance IA validee',
            'video': 'p2p_non_dechiffre_aucun_flux_expose',
            'ptz': 'commande_et_arret_non_valides_aucun_mouvement_envoye',
            'confidentialite': 'aucun_nom_sn_uid_sid_url_token_image_ni_detail_evenement_retourne',
        }
