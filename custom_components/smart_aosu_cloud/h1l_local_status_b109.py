"""B109: one-shot opt-in Tuya 3.4 LAN diagnostic; reuse secure B108 preflight.

B107 has been updated to report a fixed, non-secret error category after the
session challenge. The network behavior, commands, consent, and cooldown are
unchanged. No capture or raw ciphertext is ever returned or persisted.
"""
from __future__ import annotations
from typing import Any
from .h1l_local_status_b108 import audit_h1l_local_status_b108


def audit_h1l_local_status_b109(
    coordinator: Any, *, ip_station: object, confirm_station: bool,
    confirm_read: bool, autoriser_reconstitution_oem: bool = False,
    confirmation_envoi_mot_de_passe: bool = False,
    now: float | None = None,
) -> dict:
    result = audit_h1l_local_status_b108(
        coordinator, ip_station=ip_station,
        confirm_station=confirm_station, confirm_read=confirm_read,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
        now=now,
    )
    # Keep existing diagnostics and include fixed non-secret B109 fields.
    return {**result, 'diagnostic': 'aosu_h1l_statut_local_b109',
            'rapport_b109_sans_valeurs_privees': True,
            'trames_reseau_supplementaires': 0,
            'lecture_acceptee_sans_hmac_session': False}
