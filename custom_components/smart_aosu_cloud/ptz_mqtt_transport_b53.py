"""b53: opt-in MQTT TLS CONNECT and SUBSCRIBE for selected C5L.

No publish. No movement. No SDP or video sessions. No authentication refresh.
Reuse existing Tuya UID session and SDK-candidate MQTT identity, but derive the
*subscription topic* from the selected OEM device's communicationNode instead
of the video deviceId. Successful SUBACK is NOT evidence of publishing rights.
Never expose secrets, topic, communicationNode, identifiers, or raw exceptions.
"""
from __future__ import annotations
import re
import threading
import time
from typing import Any

_LOCK = threading.Lock()
_NEXT = {}
_INTERVAL = 600


def _communication_topic_id(row: Any) -> tuple[str | None, str]:
    """Strictly select a single opaque communication node from the OEM row."""
    from .ptz_sdk_sources_b47 import _walk
    candidates = set()
    for node in _walk(row):
        if isinstance(node, dict) and 'communicationNode' in node:
            value = node['communicationNode']
            # No MQTT wildcard, slash, path delimiter or whitespace injection.
            if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{5,128}', value):
                return None, 'noeud_communication_invalide'
            candidates.add(value)
    if not candidates:
        return None, 'noeud_communication_absent'
    if len(candidates) != 1:
        return None, 'noeuds_communication_contradictoires'
    return next(iter(candidates)), 'noeud_communication_unique'


def audit_ptz_mqtt_transport(coordinator: Any, *, mqtt_confirmed=False,
                              camera_confirmed=False) -> dict:
    """One ephemeral TLS connection, CONNECT + SUBSCRIBE + DISCONNECT only."""
    base = {'diagnostic': 'aosu_mqtt_ptz_transport_b53',
            'mode': 'connexion_et_abonnement_uniquement',
            'commandes_ptz_envoyees': 0, 'commandes_arret_envoyees': 0,
            'messages_mqtt_publies': 0, 'offres_video_envoyees': 0,
            'video_modifiee': False, 'appels_http': 0,
            'connexion_mqtt_tentee': False,
            'abonnement_mqtt_ptz_accepte': False,
            'publication_ptz_validee': False, 'arret_moteur_valide': False,
            'mouvement_autorise': False, 'secrets_retournes': False,
            'identifiants_retournes': False}
    if mqtt_confirmed is not True or camera_confirmed is not True:
        return {**base, 'etat': 'confirmations_requises'}
    live = getattr(coordinator, 'live_controller', None)
    if live is not None and getattr(live, 'running', False):
        return {**base, 'etat': 'direct_en_cours'}
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_sdk_sources_b47 import inspect_sdk_properties
    from .tuya_uid_gateway import TuyaAuthSession
    from .uid_token_probe import _ready_identity, _apk_preflight
    from .tuya_mqtt_signaling import _identity, _tls_probe
    selected, why = select_c5l_oem(coordinator)
    if selected is None:
        return {**base, 'etat': why}
    _device_id, row, method = selected
    # A unique name, confirmed by the owner, is adequate for a passive subscribe,
    # not enough for a motor command or signed write to the device.
    base['selection_oem'] = method
    props = inspect_sdk_properties(row)
    if props.get('pv') != '2.2':
        return {**base, 'etat': 'protocole_22_non_valide'}
    base['pv'] = '2.2'
    if not props['local_key_presente']:
        return {**base, 'etat': 'cle_locale_absente'}
    topic_id, why = _communication_topic_id(row)
    if topic_id is None:
        return {**base, 'etat': why}
    session = getattr(coordinator.client, '_tuya_oem_session', None)
    if not isinstance(session, TuyaAuthSession) or not 0 <= time.monotonic()-session.acquired_at < 1200:
        return {**base, 'etat': 'session_oem_absente_ou_expiree'}
    ready = _ready_identity(coordinator.client)
    if ready is None:
        return {**base, 'etat': 'profil_oem_absent'}
    _hints, install_id = ready
    try:
        _stage, material = _apk_preflight(coordinator.client.apk_path)
        if material is None:
            return {**base, 'etat': 'ressources_oem_invalides'}
        identity, signer = material
        auth = _identity(identity, signer, session, install_id, topic_id)
        # No password / key / topic ever persisted or included in reports.
    except (ValueError, TypeError, AttributeError):
        return {**base, 'etat': 'identite_mqtt_non_preparee'}
    key = id(coordinator.client)
    now = time.monotonic()
    if _NEXT.get(key, 0) > now:
        return {**base, 'etat': 'temporisation_mqtt_dix_minutes'}
    if not _LOCK.acquire(blocking=False):
        return {**base, 'etat': 'audit_mqtt_deja_en_cours'}
    try:
        if _NEXT.get(key, 0) > time.monotonic():
            return {**base, 'etat': 'temporisation_mqtt_dix_minutes'}
        _NEXT[key] = time.monotonic()+_INTERVAL
        base['connexion_mqtt_tentee'] = True
        try:
            result = _tls_probe(auth)
        except Exception:
            return {**base, 'etat': 'erreur_mqtt_sans_details'}
        # Publish permission is NEVER inferred from CONNECT or SUBACK.
        base['tls_valide'] = result.get('connexion_tls_validee') is True
        base['connexion_authentifiee'] = result.get('connack_accepte') is True
        base['abonnement_mqtt_ptz_accepte'] = result.get('abonnement_signalisation_accepte') is True
        base['categorie_connack'] = result.get('categorie_connack', 'non_applicable')
        if base['abonnement_mqtt_ptz_accepte']:
            base['etat'] = 'abonnement_canal_ptz_accepte_publication_non_validee'
        else:
            base['etat'] = result.get('etat', 'abonnement_non_confirme')
        return base
    finally:
        _LOCK.release()
