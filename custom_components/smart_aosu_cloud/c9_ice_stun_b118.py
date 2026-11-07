"""B118: bounded, *offline* STUN/ICE verification foundation.

Only SDP credentials that have been authenticated/decrypted locally in RAM are
used. Neither SDP strings, credentials, STUN USERNAME, endpoints, candidates,
packet contents nor hashes are included in any return value or log.

See RFC 5389, sections 15.4 and 15.5, for HMAC and FINGERPRINT framing.
This module never opens a network socket and never sends any packet.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from collections import Counter
from typing import Any

COOKIE = b'\x21\x12\xa4\x42'
MAX_STUN = 4096
_ATTR = {'username':0x0006, 'integrity':0x0008, 'fingerprint':0x8028,
         'priority':0x0024, 'controlling':0x802a, 'controlled':0x8029}


def sdp_ice_credentials(sdp: object) -> tuple[str,str] | None:
    """Return short-term ICE credentials privately for verified SDP only."""
    if not isinstance(sdp,str) or len(sdp)>65536:return None
    username=password=None
    for line in sdp.splitlines()[:300]:
        line=line.strip()
        if line.startswith('a=ice-ufrag:'):
            username=line[len('a=ice-ufrag:'):]
        elif line.startswith('a=ice-pwd:'):
            password=line[len('a=ice-pwd:'):]
    if not (username and password and 1<=len(username)<=256 and 1<=len(password)<=256):
        return None
    return username,password


def sdp_application_protocol(sdp: object) -> str:
    """Classify without leaking nonstandard transport tokens from device data."""
    if not isinstance(sdp,str) or len(sdp)>65536:return 'inconnu'
    for line in sdp.splitlines()[:300]:
        parts=line.strip().split()
        if len(parts)>=3 and parts[0]=='m=application':
            proto=parts[2].upper()
            if proto in ('AES/KCP','UDP/KCP','KCP','TCP/KCP','IMM'):
                return 'kcp'
            if proto in ('UDP/DTLS/SCTP','DTLS/SCTP'):
                return 'dtls_sctp'
            if proto in ('UDP/DTLS/RTP/SAVPF','RTP/SAVPF'):
                return 'dtls_rtp'
            if proto in ('UDP','UDP/ICE','UDP/RAW','UDP/TLS/RTP/SAVPF'):
                return 'udp_autre'
            return 'protocole_non_classe'
    return 'pas_de_media_application'


def stun_parse(packet: bytes) -> dict | None:
    """Bounded structural parse; private attributes remain raw in RAM only."""
    if not isinstance(packet,bytes) or not 20<=len(packet)<=MAX_STUN:
        return None
    if packet[0]&0xc0 or packet[4:8]!=COOKIE:return None
    length=int.from_bytes(packet[2:4],'big')
    if length%4 or length+20!=len(packet):return None
    attrs={}; offset=20
    while offset<len(packet):
        if offset+4>len(packet):return None
        typ,n=struct.unpack_from('!HH',packet,offset)
        end=offset+4+n
        pad=(n+3)&~3
        if offset+4+pad>len(packet):return None
        if typ in attrs and typ in (0x0008,0x8028):return None
        attrs[typ]=(offset,packet[offset+4:end])
        offset+=4+pad
    return {'kind':int.from_bytes(packet[:2],'big'), 'attrs':attrs}


def stun_fingerprint_valid(packet:bytes, parsed:dict)->bool|None:
    rec=parsed['attrs'].get(_ATTR['fingerprint'])
    if rec is None:return None
    pos,value=rec
    if len(value)!=4 or pos+8!=len(packet):return False
    calculated=(zlib.crc32(packet[:pos])^0x5354554e)&0xffffffff
    return hmac.compare_digest(struct.pack('!I',calculated),value)


def stun_integrity_valid(packet:bytes, parsed:dict, password:str)->bool|None:
    rec=parsed['attrs'].get(_ATTR['integrity'])
    if rec is None:return None
    pos,value=rec
    if len(value)!=20 or not isinstance(password,str) or not password:return False
    # RFC 5389: HMAC input ends BEFORE the MESSAGE-INTEGRITY attribute;
    # the length in the STUN header nevertheless includes this attribute.
    pre=bytearray(packet[:pos])
    pre[2:4]=struct.pack('!H',pos+24-20)
    expected=hmac.new(password.encode('utf-8'),pre,hashlib.sha1).digest()
    return hmac.compare_digest(expected,value)


def verify_capture_stun(samples:list[tuple[str,bytes]],
                        phone_credentials:tuple[str,str]|None,
                        station_credentials:tuple[str,str]|None)->dict:
    """Offline integrity verification, deriving credential side from requests.

    For STUN requests from phone to station, remote (station) ICE pwd applies;
    for requests from station to phone, remote (phone) ICE pwd applies.
    The response uses the request transaction's credential.
    """
    total=Counter(); transactions={}; valid_packets=[]
    for direction,packet in samples[:300]:
        parsed=stun_parse(packet)
        if parsed is None:total['trames_invalides']+=1;continue
        kind=parsed['kind']
        total['stun_valides_structure']+=1
        if kind==0x0001:
            total['binding_request']+=1
            pwd=(station_credentials or (None,None))[1] if direction=='telephone_vers_station' else (phone_credentials or (None,None))[1]
            transactions[packet[8:20]]=pwd
        elif kind==0x0101:total['binding_success']+=1
        elif kind==0x0111:total['binding_error']+=1
        elif kind==0x0011:total['binding_indication']+=1
        else:total['autre_type_stun']+=1
        attrs=parsed['attrs']
        for flag,code in _ATTR.items():
            if code in attrs and flag not in ('integrity','fingerprint'):
                total['attribut_'+flag]+=1
        fingerprint=stun_fingerprint_valid(packet,parsed)
        if fingerprint is True:total['fingerprints_valides']+=1
        if fingerprint is False:total['fingerprints_invalides']+=1
        if fingerprint is None:total['fingerprints_absents']+=1
        valid_packets.append((direction,packet,parsed))
    # Two-pass verification resolves replies appearing before request in PCAP.
    for direction,packet,parsed in valid_packets:
        if _ATTR['integrity'] not in parsed['attrs']:
            total['hmac_absent']+=1;continue
        kind=parsed['kind']
        if kind==0x0001:
            credentials=station_credentials if direction=='telephone_vers_station' else phone_credentials
            pwd=credentials[1] if credentials else None
        else:
            pwd=transactions.get(packet[8:20])
        if not pwd:
            total['hmac_cle_indisponible']+=1;continue
        ok=stun_integrity_valid(packet,parsed,pwd)
        total['hmac_valides' if ok is True else 'hmac_invalides']+=1
    return {'paquets_stun':len(samples),'comptage':dict(total),
            'sdp_ice_telephone_present':phone_credentials is not None,
            'sdp_ice_station_present':station_credentials is not None,
            'trames_brutes_retournees':False,
            'mot_de_passe_ou_username_retourne':False,
            'aucun_paquet_envoye':True}
