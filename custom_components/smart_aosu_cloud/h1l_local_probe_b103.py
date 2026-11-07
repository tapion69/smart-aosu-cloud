"""B103: manual, bounded LAN reachability check for a suspected AOSU H1L.

One unauthenticated STUN Binding Request (RFC 5389) plus optional TCP
connect-without-payload; these cannot start media or authenticate any camera.
No session credentials, local keys, private frames or UDP payloads are returned.
Absence of STUN reply does NOT imply the station is unreachable: ICE agents may
require a valid USERNAME/MESSAGE-INTEGRITY and intentionally drop this probe.
"""
from __future__ import annotations
import ipaddress
import os
import socket
import struct
import time

_STUN_MAGIC = 0x2112A442
_RETRY_SECONDS = 45
_ATTEMPTS: dict[str,float] = {}


def _validate_target(value: object) -> str:
    if not isinstance(value,str): raise ValueError('Adresse IPv4 locale requise')
    try:
        address=ipaddress.IPv4Address(value.strip())
    except ipaddress.AddressValueError as exc:
        raise ValueError('Adresse IPv4 locale invalide') from exc
    allowed = any(address in ipaddress.ip_network(prefix) for prefix in
                  ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16'))
    if not allowed or address.is_multicast or address.is_loopback or address.is_unspecified:
        raise ValueError('Adresse IPv4 privee RFC1918 requise')
    return str(address)


def audit_local_h1l_b103(ip_station: object, *, confirmed:bool,
                         check_tcp:bool=True, now:float|None=None) -> dict:
    """Single manual LAN test, no camera commands, no recurring scans."""
    target=_validate_target(ip_station)
    if not confirmed: raise ValueError('Confirmation du test STUN local requise')
    timestamp=time.monotonic() if now is None else now
    retry=max(0,int(_RETRY_SECONDS - (timestamp-_ATTEMPTS.get(target,-1e9)) + 0.999))
    if retry:
        return {'diagnostic':'aosu_h1l_reseau_local_b103','etat':'limitation_locale',
                'secondes_restantes':retry,'requetes_udp':0,'tentatives_tcp':0,
                'video_demarre':False,'commandes_camera':0,'secrets_retournes':False}
    _ATTEMPTS[target]=timestamp
    txid=os.urandom(12)
    request=struct.pack('!HHI',0x0001,0,_STUN_MAGIC)+txid
    stun_reply='aucune_reponse'
    peer_ok=False
    received=0
    udp_error=False
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.8)
            sock.sendto(request,(target,9396))
            try:
                response,peer=sock.recvfrom(512)
                peer_ok=peer[0]==target
                received=1
                if peer_ok and len(response)>=20 and response[4:8]==struct.pack('!I',_STUN_MAGIC):
                    stun_type=int.from_bytes(response[:2],'big')
                    msg_len=int.from_bytes(response[2:4],'big')
                    matching=response[8:20]==txid
                    if 20+msg_len > len(response): stun_reply='trame_stun_incomplete'
                    elif matching and stun_type==0x0101: stun_reply='succes_binding_non_authentifie'
                    elif matching and stun_type==0x0111: stun_reply='erreur_stun'
                    elif matching: stun_reply='autre_type_stun'
                    else: stun_reply='transaction_differente'
                elif peer_ok:
                    stun_reply='reponse_non_stun'
                else: stun_reply='origine_inattendue'
            except socket.timeout:
                pass
    except OSError:
        udp_error=True
        stun_reply='erreur_reseau_locale'
    tcp_result='non_teste'
    if check_tcp:
        try:
            with socket.create_connection((target,6668),timeout=1.5):
                tcp_result='connexion_acceptee'
        except (OSError,TimeoutError):
            tcp_result='connexion_indisponible'
    return {
        'diagnostic':'aosu_h1l_reseau_local_b103','etat':'test_reseau_termine',
        'cible_ipv4':target, 'udp_port':9396, 'tcp_port':6668,
        'stun_type':'binding_request_sans_identifiants',
        'stun_reponse':stun_reply,'reponse_udp_recue':bool(received),
        'origine_reponse_attendue':peer_ok if received else None,
        'erreur_envoi_udp':udp_error,'tcp_6668':tcp_result,
        'requetes_udp':1,'tentatives_tcp':int(bool(check_tcp)),
        'commandes_camera':0,'commandes_ptz':0,
        'session_video_creee':False,'offre_mqtt_envoyee':False,
        'authentification_camera':False,'secrets_retournes':False,
        'conclusion':('Un STUN sans identifiants peut etre ignore meme si le relais est fonctionnel. '
                       'La reponse TCP confirme seulement la joignabilite du port, pas le flux video.'),
    }
