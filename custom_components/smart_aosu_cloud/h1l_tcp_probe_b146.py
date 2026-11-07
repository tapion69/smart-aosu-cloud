"""B146: opt-in, single TCP connect test from the same HA process as the C9 engine.

Sends no data and closes immediately; no camera/RTC/PTZ/video commands and no identities.
"""
from __future__ import annotations
import errno
import socket
import time
from .h1l_local_probe_b103 import _validate_target


def tester_port_tcp_h1l_b146(*,ip_station,confirmation_test_tcp_h1l=False):
    result={'diagnostic':'aosu_test_tcp_h1l_b146','test_depuis_home_assistant_core':True,
            'port':6668,'connexion_tcp_etablie':False,'aucune_commande_envoyee':True,
            'aucune_video_demandee':True,'secrets_retournes':False,
            'delai_max_secondes':10}
    if confirmation_test_tcp_h1l is not True:
        return {**result,'etat':'confirmation_requise'}
    try:ip=_validate_target(ip_station)
    except (ValueError,TypeError):return {**result,'etat':'adresse_privee_invalide'}
    start=time.monotonic()
    try:
        with socket.create_connection((ip,6668),timeout=10) as sock:
            # Never use send() or recv() here: this is a transport-only probe.
            elapsed=min(10000,max(0,round((time.monotonic()-start)*1000)))
        return {**result,'connexion_tcp_etablie':True,'latence_connexion_ms':elapsed,
                'etat':'tcp_6668_joignable_depuis_ha_core'}
    except (OSError,TimeoutError) as exc:
        code=getattr(exc,'errno',None)
        if isinstance(exc,TimeoutError) or code==errno.ETIMEDOUT:
            status='tcp_6668_timeout_depuis_ha_core'
        elif code==errno.ECONNREFUSED:status='tcp_6668_refuse_depuis_ha_core'
        elif code in (errno.EHOSTUNREACH,errno.ENETUNREACH):status='tcp_6668_reseau_injoignable'
        else:status='tcp_6668_erreur_transport'
        return {**result,'etat':status,
                'latence_connexion_ms':min(10000,max(0,round((time.monotonic()-start)*1000)))}
