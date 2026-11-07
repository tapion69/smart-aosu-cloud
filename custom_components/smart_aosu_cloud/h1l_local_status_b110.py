"""B110: standard JSON-object Tuya 3.4 status query, with B108 consent and cache.

Keeps one 0x10 query, authenticated responses, local cooldown, no camera
commands or media. The underlying B107 query now encrypts b'{}' instead of
an empty byte string (Tuya DP_QUERY_NEW schema).
"""
from __future__ import annotations
from typing import Any
from .h1l_local_status_b108 import audit_h1l_local_status_b108


def audit_h1l_local_status_b110(
    coordinator: Any, *, ip_station: object, confirm_station: bool,
    confirm_read: bool, autoriser_reconstitution_oem: bool = False,
    confirmation_envoi_mot_de_passe: bool = False, now: float | None = None,
) -> dict:
    result = audit_h1l_local_status_b108(
        coordinator, ip_station=ip_station, confirm_station=confirm_station,
        confirm_read=confirm_read,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
        now=now,
    )
    sent = result.get('commande_lecture_envoyee') == 1
    return {**result, 'diagnostic': 'aosu_h1l_statut_local_b110',
            'requete_json_b110': 'objet_vide' if sent else 'non_envoyee',
            'lecture_acceptee_sans_hmac_session': False,
            'trames_reseau_supplementaires': 0,
            'contenu_prive_retourne': False}
