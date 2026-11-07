"""B111: offline/opt-in forensic analysis of ONE locally stored PCAP.

No camera, UDP, TCP or video command. The capture is read only from the
allowlisted /config/smart_aosu_traces directory; station key never leaves RAM.
No decrypted packet bytes, personal identifiers, device names, serials,
nonce values, derived keys or hashes are returned or logged.

Tuya 3.4 handshakes are verified under station local key, and later frames
ONLY under the derived session key; invalid MACs are never accepted.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import socket
import struct
import time
from collections import Counter, defaultdict
from typing import Any

from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_auth_b104 import _aes_decrypt
from .h1l_local_status_b107 import _session_key
from .h1l_local_status_b108 import _cache_state
from .c9_ice_stun_b118 import sdp_ice_credentials, sdp_application_protocol, verify_capture_stun
from .tuya_rtc_inventory import run_tuya_oem_inventory

_MAX_FILE = 32 * 1024 * 1024
_MAX_PACKET = 131072
_MAX_PACKETS = 100000
_MAX_FLOW = 4 * 1024 * 1024
_MAX_FRAME = 65536
_NAME = re.compile(r'^[A-Za-z0-9_-]{1,48}\.pcap$')
_PREFIX = b'\x00\x00\x55\xaa'
_SUFFIX = b'\x00\x00\xaa\x55'
_KEY_HINTS = frozenset({
    'subDic', 'subDid', 'subDevId', 'nodeId', 'parentId', 'gatewayId',
    'channel', 'channelId', 'communicationId', 'nvrDevId', 'baseDevId',
    'deviceId', 'devId', 'type', 'cmd', 'method', 'data', 'dps',
})


def _read_pcap(path: Path, station_ip: str) -> dict:
    """Collect only station Tuya TCP and station UDP counters; no payload export."""
    raw = path.read_bytes()
    if not 24 <= len(raw) <= _MAX_FILE:
        raise ValueError('taille_capture_invalide')
    magic = raw[:4]
    signatures = {b'\xd4\xc3\xb2\xa1': ('<', False),
                  b'\xa1\xb2\xc3\xd4': ('>', False),
                  b'\x4d\x3c\xb2\xa1': ('<', True),
                  b'\xa1\xb2\x3c\x4d': ('>', True)}
    if magic not in signatures:
        raise ValueError('format_pcap_invalide')
    endian, ns = signatures[magic]
    network = struct.unpack_from(endian+'I', raw, 20)[0]
    if network not in (1, 101):
        raise ValueError('format_lien_non_supporte')
    flows = defaultdict(lambda: {'client': [], 'station': []})
    lan_others = set()
    udp_counts = Counter()
    stun_samples=[]
    # B113: timestamps of protocol milestones only, no network contents.
    first_milestones = {}
    station_epoch = None
    packets = 0
    offset = 24
    earliest = None
    while offset + 16 <= len(raw):
        _ts, _frac, length, _orig = struct.unpack_from(endian+'IIII', raw, offset)
        offset += 16
        if length > _MAX_PACKET or offset+length > len(raw):
            raise ValueError('paquet_pcap_invalide')
        pkt = raw[offset:offset+length]
        offset += length
        packets += 1
        if packets > _MAX_PACKETS:
            raise ValueError('capture_trop_de_paquets')
        timestamp = _ts + _frac/(1e9 if ns else 1e6)
        if earliest is None: earliest = timestamp
        if network == 1:
            if len(pkt) < 14 or pkt[12:14] != b'\x08\x00':
                continue
            pkt = pkt[14:]
        if len(pkt) < 20 or pkt[0] >> 4 != 4:
            continue
        ihl = (pkt[0] & 0x0f) * 4
        if ihl < 20 or len(pkt) < ihl+8:
            continue
        iplen = struct.unpack_from('!H', pkt, 2)[0]
        if iplen < ihl+8 or iplen > len(pkt):
            continue
        pkt = pkt[:iplen]
        # Avoid treating IPv4 fragments as independent TCP packets.
        if struct.unpack_from('!H', pkt, 6)[0] & 0x3fff:
            continue
        src, dst = socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20])
        for ip in (src,dst):
            # Classify only private peers; the PCAP alone cannot establish the subnet.
            try:
                if ip != station_ip and ipaddress.ip_address(ip).is_private:
                    lan_others.add(ip)
            except ValueError:
                pass
        if station_ip not in (src,dst):
            continue
        if station_epoch is None:
            station_epoch = timestamp
        protocol = pkt[9]
        segment = pkt[ihl:]
        sport, dport = struct.unpack_from('!HH', segment, 0)
        if protocol == 17:
            if len(segment) >= 8:
                body = segment[8:]
                side = 'station_vers_telephone' if src==station_ip else 'telephone_vers_station'
                udp_counts[(side,'total')] += 1
                if len(body) >= 20 and body[4:8] == b'\x21\x12\xa4\x42':
                    udp_counts[(side,'stun')] += 1
                    if len(stun_samples)<300 and len(body)<=4096:
                        stun_samples.append((side,bytes(body)))
                    first_milestones.setdefault('premier_stun',timestamp)
                elif len(body) >= 44 and body[4] in (81,82,83,84):
                    length_kcp = struct.unpack_from('<I', body, 20)[0]
                    if length_kcp + 44 == len(body):
                        udp_counts[(side,'kcp')] += 1
                        conv = struct.unpack_from('<I',body,0)[0]
                        if conv==0:
                            first_milestones.setdefault('premier_kcp_controle',timestamp)
                        elif conv in (1,2):
                            first_milestones.setdefault('premier_kcp_media',timestamp)
            continue
        if protocol != 6 or len(segment) < 20 or (sport != 6668 and dport != 6668):
            continue
        tcphl = (segment[12] >> 4)*4
        if tcphl < 20 or len(segment) < tcphl:
            continue
        content = segment[tcphl:]
        if not content:
            continue
        # Inspect visible TCP headers only. Do not retain cipher text or parse
        # arbitrary payload bytes into user-facing diagnostic values.
        off = 0
        while True:
            off = content.find(_PREFIX,off)
            if off < 0 or off+16>len(content):
                break
            cmd = struct.unpack_from('>I',content,off+8)[0]
            if cmd==0x20 and dst==station_ip:
                first_milestones.setdefault('premier_tcp_0x20',timestamp)
            off += 4
        # Destination station means the phone initiated this flow.
        clientport = sport if dst == station_ip else dport
        if not 1 <= clientport <= 65535:
            continue
        side = 'client' if dst == station_ip else 'station'
        seq = struct.unpack_from('!I', segment, 4)[0]
        flows[clientport][side].append((seq,content))
    return {'flows': flows, 'stun_samples':stun_samples, 'nombre_paquets': packets,
            'autres_ips_lan_vues': len(lan_others),
            'udp': udp_counts, 'duree_capture_s': round(
                max(0, timestamp-earliest), 2) if earliest is not None else 0,
            'chronologie_b113': {
                label + '_s': round(at-station_epoch, 3)
                for label,at in first_milestones.items()
            } if station_epoch is not None else {}}


def _frames_from_segments(chunks: list[tuple[int,bytes]]) -> list[tuple[int,bytes,bytes]]:
    """Assemble TCP by SEQ; respect gaps and remove retransmission duplicates."""
    if not chunks:
        return []
    chunks = sorted(chunks, key=lambda it:it[0])
    expected = chunks[0][0]
    stream = bytearray()
    for seq,chunk in chunks:
        if seq > expected:
            # A sequence gap invalidates subsequent decryption in this flow.
            break
        skip = expected-seq
        if skip >= len(chunk):
            continue
        part = chunk[skip:]
        if len(stream)+len(part) > _MAX_FLOW:
            break
        stream.extend(part)
        expected += len(part)
    result=[]
    pos=0
    while pos+16 <= len(stream) and len(result)<2048:
        n=stream.find(_PREFIX,pos)
        if n < 0 or n+16 > len(stream):
            break
        _seq, command, length = struct.unpack_from('>III', stream, n+4)
        if length < 36 or length > _MAX_FRAME:
            pos=n+4
            continue
        end=n+16+length
        if end > len(stream):
            break
        payload=bytes(stream[n+16:end])
        if payload[-4:] == _SUFFIX:
            result.append((command,bytes(stream[n:n+16]),payload))
        pos=end
    return result


def _frame_mac_valid(frame: tuple[int,bytes,bytes], key: bytes) -> bool:
    """Authenticate the complete frame before any attempt to decrypt it."""
    _command, header, body=frame
    return (len(body)>=36 and body[-4:]==_SUFFIX and hmac.compare_digest(
        body[-36:-4],hmac.new(key,header+body[:-36],hashlib.sha256).digest()
    ))


def _verify_and_decode(frame: tuple[int,bytes,bytes], key: bytes, incoming: bool) -> bytes|None:
    _command, header, body=frame
    if not _frame_mac_valid(frame,key):
        return None
    envelope=body[:-36]
    if incoming:
        if len(envelope)<4 or int.from_bytes(envelope[:4],'big')!=0:
            return None
        envelope=envelope[4:]
    if not envelope:
        return b''
    if len(envelope)%16:
        return None
    try:
        return _aes_decrypt(key,envelope)
    except (ValueError, TypeError):
        return None


def _schema_only(blob: bytes) -> dict:
    """No decoded data ever returned, only small whitelisted field-presence flags."""
    # Version header may be encrypted with JSON under Tuya 3.4.
    for offset in (0,15):
        if offset==15 and not (blob[:3] in (b'3.3',b'3.4',b'3.5')):
            continue
        candidate=blob[offset:].strip(b'\0 \t\n\r')
        if not candidate.startswith((b'{',b'[')):
            continue
        try: data=json.loads(candidate.decode('utf-8'))
        except (UnicodeError, ValueError): continue
        keys=set()
        def traverse(v, depth=0):
            if depth>5 or len(keys)>48:return
            if isinstance(v,dict):
                for k,value in list(v.items())[:80]:
                    if k in _KEY_HINTS:keys.add(k)
                    traverse(value,depth+1)
            elif isinstance(v,list):
                for value in v[:20]:traverse(value,depth+1)
        traverse(data)
        return {'format':'json','cles_structurelles_presentes':sorted(keys)}
    return {'format':'binaire_ou_non_json','cles_structurelles_presentes':[]}


# B113: Only generic command classes and whitelisted field NAMES may leave RAM.
# These fields never include a device name, ID, secret, or decrypted field VALUE.
_SAFE_KEYS_B113 = frozenset({
    'type','event','action','cmd','method','methodName','request','response',
    'message','msg','payload','body','data','params','result','status','code',
    'video','audio','stream','channel','channelId','subDic','subDid','subDevId',
    'deviceId','devId','nodeId','parentId','gatewayId','session','sessionId',
    'offer','answer','candidate','ice','sdp','p2p','rtc','stun','dps','state',
    'connection','command','requestId','version','timestamp','uri','ip','port',
    'push','ack','param','ret','nvr','camera','values','value','protocol',
    'requestType','responseType','content','args','arg','topic','online',
})
_ALLOWED_TYPE_LABELS_B113 = frozenset({
    'offer','answer','candidate','start','stop','video','audio','stream',
    'media','rtc','p2p','ice','stun','event','request','response','status',
    'heartbeat','notify','notification','ack','config','query','result',
    'connect','disconnect','online','offline','control','data','message',
    'device','channel','play','pause',
})


def _profile_0x20_b113(blob: bytes) -> dict:
    """Classify decryptable JSON without returning strings/values from the payload."""
    if not blob:
        return {'format':'vide', 'type':'absent', 'champs':[], 'racine':'vide'}
    for offset in (0,15):
        if offset == 15 and blob[:3] not in (b'3.3',b'3.4',b'3.5'):
            continue
        body = blob[offset:].strip(b'\0 \t\n\r')
        if not body.startswith((b'{',b'[')):
            continue
        try:
            obj = json.loads(body.decode('utf-8'))
        except (UnicodeError, ValueError):
            continue
        if isinstance(obj,dict):
            typ = obj.get('type')
            if isinstance(typ,int) and not isinstance(typ,bool) and 0 <= typ <= 255:
                label = f'numerique_{typ}'
            elif isinstance(typ,str) and typ.lower() in _ALLOWED_TYPE_LABELS_B113:
                label = 'texte_' + typ.lower()
            elif typ is None:
                label = 'absent'
            elif isinstance(typ,str):
                label = 'texte_non_classe'
            else:
                label = 'autre_type'
            return {'format':'json','type':label,
                    'champs':sorted(k for k in obj if k in _SAFE_KEYS_B113),
                    'racine':'objet'}
        if isinstance(obj,list):
            return {'format':'json','type':'absent','champs':[],'racine':'liste'}
    return {'format':'non_json', 'type':'non_classable','champs':[],'racine':'autre'}



# B114: profile the structure *inside* msg, without exporting any message data.
# No decoding of opaque strings, identifiers or credentials; JSON-encoded msg
# strings are parsed only in memory and only whitelisted field names leave RAM.
def _nested_message_b114(blob: bytes) -> dict:
    result = {'formes_msg': 'absent', 'types_imbriques': 'absent',
              'champs_msg_autorises': [], 'emplacement_type': 'absent'}
    if not blob:
        return result
    obj = None
    for offset in (0, 15):
        if offset == 15 and blob[:3] not in (b'3.3', b'3.4', b'3.5'):
            continue
        candidate = blob[offset:].strip(b'\0 \t\r\n')
        if not candidate.startswith((b'{', b'[')):
            continue
        try:
            obj = json.loads(candidate.decode('utf-8'))
        except (UnicodeError, ValueError):
            continue
        break
    if not isinstance(obj, dict):
        return result
    if 'msg' not in obj:
        return result
    msg = obj['msg']
    if msg is None:
        result['formes_msg'] = 'nul'
        return result
    if isinstance(msg, dict):
        result['formes_msg'] = 'objet'
    elif isinstance(msg, list):
        result['formes_msg'] = 'liste'
    elif isinstance(msg, str):
        # A message can itself contain a JSON serialization. Never return
        # its literal content, whether parsing succeeds or not.
        result['formes_msg'] = 'texte'
        if len(msg) <= 65536 and msg.lstrip().startswith(('{','[')):
            try:
                candidate = json.loads(msg)
            except ValueError:
                pass
            else:
                if isinstance(candidate,(dict,list)):
                    msg = candidate
                    result['formes_msg'] = 'texte_json'
    elif isinstance(msg, bool):
        result['formes_msg'] = 'booleen'
    elif isinstance(msg, (int,float)):
        result['formes_msg'] = 'nombre'
    else:
        result['formes_msg'] = 'autre'
    if not isinstance(msg,(dict,list)):
        return result

    seen=set()
    types=[]
    found_paths=[]
    def walk(v, depth, location):
        if depth > 5 or len(seen)>=48 or len(types)>=16:
            return
        if isinstance(v,dict):
            # Whitelist, never emit attacker-controlled/private JSON keys.
            for name, value in list(v.items())[:80]:
                if name in _SAFE_KEYS_B113:
                    seen.add(name)
                if name == 'type':
                    if isinstance(value,int) and not isinstance(value,bool) and 0<=value<=255:
                        label=f'numerique_{value}'
                    elif isinstance(value,str) and value.lower() in _ALLOWED_TYPE_LABELS_B113:
                        label='texte_'+value.lower()
                    elif value is None:
                        label='nul'
                    elif isinstance(value,str):
                        label='texte_non_classe'
                    else:
                        label='autre_type'
                    types.append(label)
                    found_paths.append(location)
                if isinstance(value,(dict,list)):
                    # No arbitrary keys in paths. Generic labels only.
                    walk(value,depth+1,'msg_direct' if depth==0 else 'msg_profond')
        elif isinstance(v,list):
            for value in v[:20]:
                if isinstance(value,(dict,list)):
                    walk(value,depth+1,'msg_liste' if depth==0 else 'msg_profond')
    walk(msg,0,'msg_direct')
    result['champs_msg_autorises']=sorted(seen)
    # Avoid collapsing multiple types in one blob into guessed semantics.
    result['types_imbriques']=types[0] if len(types)==1 else ('multiples' if types else 'absent')
    result['emplacement_type']=found_paths[0] if len(found_paths)==1 else ('multiples' if found_paths else 'absent')
    return result

# B115: characterize the direction and order of authenticated signaling records.
# Only a fixed vocabulary of booleans/classes leaves RAM, never SDP, candidate,
# identifiers, topic strings, addresses, ports, keys, or their hashes.
def _signaling_profile_b115(blob: bytes) -> dict:
    empty = {'classe':'autre', 'sdp_present':False, 'candidate_present':False,
             'session_id_present':False, 'topic_present':False,
             'port_present':False, 'sdp_ice_present':False,
             'sdp_video_present':False, 'sdp_audio_present':False}
    if not blob or len(blob)>65536:
        return empty.copy()
    envelope = None
    for offset in (0,15):
        if offset == 15 and blob[:3] not in (b'3.3', b'3.4', b'3.5'):
            continue
        raw=blob[offset:].strip(b'\0 \t\r\n')
        if not raw.startswith(b'{'):
            continue
        try:
            envelope=json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeError):
            continue
        break
    if not isinstance(envelope,dict) or 'msg' not in envelope:
        return empty.copy()
    msg=envelope['msg']
    if isinstance(msg,str) and len(msg)<=32768 and msg.lstrip().startswith('{'):
        try:
            msg=json.loads(msg)
        except (ValueError, TypeError):
            return empty.copy()
    if not isinstance(msg,dict):
        return empty.copy()
    result=empty.copy()
    # Parse at most six nested levels; keys are matched literally to fixed names.
    def walk(node,depth=0):
        if depth>5:
            return
        if isinstance(node,dict):
            for name,value in list(node.items())[:80]:
                if name=='sdp' and value is not None:
                    result['sdp_present']=True
                    if isinstance(value,str) and len(value)<=65536:
                        # Boolean token detection only: no SDP contents exported.
                        sdp=value.lower()
                        result['sdp_ice_present'] |= ('a=ice-ufrag:' in sdp or 'a=ice-pwd:' in sdp)
                        result['sdp_video_present'] |= 'm=video ' in sdp
                        result['sdp_audio_present'] |= 'm=audio ' in sdp
                if name=='candidate' and value is not None:
                    result['candidate_present']=True
                if name in ('sessionId','session_id') and value is not None:
                    result['session_id_present']=True
                if name=='topic' and value is not None:
                    result['topic_present']=True
                if name=='port' and value is not None:
                    result['port_present']=True
                if isinstance(value,(dict,list)):
                    walk(value,depth+1)
        elif isinstance(node,list):
            for v in node[:20]:
                if isinstance(v,(dict,list)):
                    walk(v,depth+1)
    walk(msg)
    if result['sdp_present'] and result['candidate_present']:
        result['classe']='sdp_et_candidate'
    elif result['sdp_present']:
        result['classe']='sdp'
    elif result['candidate_present']:
        result['classe']='candidate'
    elif result['session_id_present'] or result['topic_present'] or result['port_present']:
        result['classe']='parametres_session'
    return result


# B116: memory-only relation checks; never return the SDP, topic, device ID,
# session ID, candidate, hashes, raw ciphertext or token fragments.
def _msg_fields_b116(blob: bytes) -> dict:
    if not blob or len(blob)>65536:
        return {}
    for offset in (0,15):
        if offset==15 and blob[:3] not in (b'3.3',b'3.4',b'3.5'):
            continue
        raw=blob[offset:].strip(b'\0 \t\r\n')
        if not raw.startswith(b'{'):
            continue
        try:
            env=json.loads(raw.decode('utf-8'))
        except (UnicodeError,ValueError):
            continue
        if not isinstance(env,dict):
            return {}
        msg=env.get('msg')
        if isinstance(msg,str) and len(msg)<=32768 and msg.lstrip().startswith('{'):
            try:msg=json.loads(msg)
            except (UnicodeError,ValueError):return {}
        return msg if isinstance(msg,dict) else {}
    return {}


def _topic_match_b116(msg: dict, camera_did: str | None, station_did: str | None) -> str:
    topic=msg.get('topic')
    if not isinstance(topic,str) or len(topic)>8192:
        return 'topic_absent_ou_invalide'
    # Reject short or untrusted identifiers so substring coincidences do not
    # get presented as device-target evidence.
    cam=isinstance(camera_did,str) and 8<=len(camera_did)<=128 and camera_did in topic
    station=isinstance(station_did,str) and 8<=len(station_did)<=128 and station_did in topic
    if cam and station:return 'deux_identifiants_candidats_presents'
    if cam:return 'identifiant_c9_candidate_present'
    if station:return 'identifiant_station_candidate_present'
    return 'aucun_identifiant_candidat_dans_topic'


def _media_sdp_b116(value: object) -> dict:
    if not isinstance(value,str) or len(value)>65536:
        return {'media_application':False,'media_video':False,'media_audio':False,'aucun_media':True}
    lines=[line.strip().lower() for line in value.splitlines()[:200]]
    found={tag:any(line.startswith('m='+tag+' ') for line in lines) for tag in ('application','video','audio')}
    return {'media_application':found['application'],'media_video':found['video'],
            'media_audio':found['audio'],'aucun_media':not any(line.startswith('m=') for line in lines)}



# B117: recursively locate *only* fixed signaling field names. All contents remain
# in RAM, and output classes are from hardcoded vocabularies (no raw user strings).
def _field_values_b117(msg: object, field: str) -> list[tuple[str,object]]:
    found=[]
    def walk(node, depth: int, path: str) -> None:
        if depth>6 or len(found)>=16:return
        if isinstance(node,dict):
            for name,value in list(node.items())[:80]:
                if name==field and value is not None:
                    found.append((path,value))
                if isinstance(value,(dict,list)):
                    walk(value,depth+1,'imbrique')
        elif isinstance(node,list):
            for value in node[:20]:
                if isinstance(value,(dict,list)):walk(value,depth+1,'imbrique')
    walk(msg,0,'direct')
    return found


def _value_type_b117(v: object) -> str:
    if isinstance(v,str):return 'texte' if len(v)<=8192 else 'texte_long'
    if isinstance(v,bool):return 'booleen'
    if isinstance(v,int):return 'nombre_entier'
    if isinstance(v,float):return 'nombre_decimal'
    if isinstance(v,dict):return 'objet'
    if isinstance(v,list):return 'liste'
    return 'autre'


def _topic_profile_b117(msg:dict, camera_did:str|None, station_did:str|None)->dict:
    values=_field_values_b117(msg,'topic')
    kinds=Counter(_value_type_b117(v) for _,v in values)
    paths=Counter(path for path,_ in values)
    match=[]
    for _,v in values:
        if isinstance(v,str):
            match.append(_topic_match_b116({'topic':v},camera_did,station_did))
    # Never export actual topic, ID, or a hash that can be correlated externally.
    return {'nombre':len(values),'types':dict(kinds),'positions':dict(paths),
            'cibles_texte':dict(Counter(match))}


def _session_tokens_b117(msg: dict)->list[tuple[str,object]]:
    tokens=[]
    for field in ('sessionId','session_id'):
        for path,val in _field_values_b117(msg,field):
            if isinstance(val,(str,int)) and not isinstance(val,bool) and 0<len(str(val))<=128:
                tokens.append((path,val))
    return tokens[:16]


def _sdp_transport_b117(msg:dict)->dict:
    result={'sdp':0,'media_application':0,'media_video':0,'media_audio':0,
            'transport_webrtc_datachannel':0,'transport_udp_dtls_sctp':0,
            'transport_dtls_sctp':0,'transport_autre':0,
            'sdp_fingerprint_present':0,'sdp_ice_ufrag_present':0,
            'sdp_ice_pwd_present':0,'sdp_sctp_present':0,'sdp_setup_present':0}
    for _,sdp in _field_values_b117(msg,'sdp'):
        if not isinstance(sdp,str) or len(sdp)>65536:continue
        result['sdp']+=1
        lines=[line.strip().lower() for line in sdp.splitlines()[:300]]
        for line in lines:
            if line.startswith('m='):
                parts=line[2:].split()
                if not parts:continue
                medium=parts[0]
                if medium in ('application','video','audio'):
                    result['media_'+medium]+=1
                # SDP protocol classification uses *only* exact public names.
                if medium=='application':
                    proto=parts[2].upper() if len(parts)>=3 else ''
                    if proto=='UDP/DTLS/SCTP':result['transport_udp_dtls_sctp']+=1
                    elif proto=='DTLS/SCTP':result['transport_dtls_sctp']+=1
                    else:result['transport_autre']+=1
                    if any(token.lower()=='webrtc-datachannel' for token in parts[3:]):
                        result['transport_webrtc_datachannel']+=1
            if line.startswith('a=fingerprint:'):result['sdp_fingerprint_present']+=1
            if line.startswith('a=ice-ufrag:'):result['sdp_ice_ufrag_present']+=1
            if line.startswith('a=ice-pwd:'):result['sdp_ice_pwd_present']+=1
            if line.startswith(('a=sctp-port:','a=sctpmap:')):result['sdp_sctp_present']+=1
            if line.startswith('a=setup:'):result['sdp_setup_present']+=1
    return result


def _candidate_profile_b117(msg:dict)->dict:
    result=Counter()
    for _,v in _field_values_b117(msg,'candidate'):
        if not isinstance(v,str) or len(v)>4096:
            result['non_textuel']+=1
            continue
        tokens=v.lower().replace('a=candidate:','candidate:').split()
        # Parse only bounded public SDP tokens. Never return address/port strings.
        if len(tokens)>=8 and (tokens[0].startswith('candidate:') or tokens[0].startswith('a=candidate:')):
            if tokens[2] in ('udp','tcp'):result['transport_'+tokens[2]]+=1
            else:result['transport_autre']+=1
            try:
                i=tokens.index('typ')
                category=tokens[i+1] if i+1<len(tokens) else ''
            except ValueError: category=''
            result['type_'+category if category in ('host','srflx','prflx','relay') else 'type_autre']+=1
        else:result['forme_non_standard']+=1
    return dict(result)


def _analyze_sessions(flows: dict, key: bytes, *, camera_did: str | None = None, station_did: str | None = None, stun_samples: list | None = None) -> dict:
    status={'sessions_tcp_6668':len(flows),'sessions_challenge_verifie':0,
            'sessions_avec_cle_derivee':0,'commandes_0x20_sortantes':0,
            'reponses_0x20_entrantes':0,'commandes_0x20_hmac_verifiees':0,
            'reponses_0x20_hmac_verifiees':0,'commandes_0x20_dechiffrees':0,
            'reponses_0x20_dechiffrees':0,'formats_0x20':{},
            'champs_structures_0x20':[], 'trace_dechiffrement_incomplet':False}
    # B113: direction-specific aggregation (not raw JSON or decryptable bytes).
    profiles = {'commandes':Counter(),'reponses':Counter()}
    classes = {'commandes':Counter(),'reponses':Counter()}
    keynames = {'commandes':set(),'reponses':set()}
    nested_forms={'commandes':Counter(),'reponses':Counter()}
    nested_types={'commandes':Counter(),'reponses':Counter()}
    nested_paths={'commandes':Counter(),'reponses':Counter()}
    nested_keys={'commandes':set(),'reponses':set()}
    signaling_counts={'commandes':Counter(),'reponses':Counter()}
    signaling_order={'commandes':[],'reponses':[]}
    b116_sdp_cipher={'commandes':[],'reponses':[]}
    b116_candidate_cipher={'commandes':[],'reponses':[]}
    b116_sessions={'commandes':[],'reponses':[]}
    b116_topics=[]
    b116_media=Counter()
    b117_topic=Counter(); b117_topic_positions=Counter(); b117_topic_types=Counter(); b117_topic_cibles=Counter()
    b117_sessions={'commandes':[],'reponses':[]}
    b117_sdp={'commandes':Counter(),'reponses':Counter()}
    b117_candidate={'commandes':Counter(),'reponses':Counter()}
    formats=Counter(); foundkeys=set()
    b118_ice={'commandes':None,'reponses':None}
    b118_proto={'commandes':Counter(),'reponses':Counter()}
    for flow in flows.values():
        outbound=_frames_from_segments(flow['client'])
        inbound=_frames_from_segments(flow['station'])
        # Count commands from unencrypted headers even when the capture's
        # session-key material is missing. Never claim they were decrypted.
        status['commandes_0x20_sortantes']+=sum(f[0]==0x20 for f in outbound)
        status['reponses_0x20_entrantes']+=sum(f[0]==0x20 for f in inbound)
        if not outbound or not inbound: continue
        starts=[f for f in outbound if f[0]==3]
        challenges=[f for f in inbound if f[0]==4]
        finishes=[f for f in outbound if f[0]==5]
        if not (starts and challenges and finishes): continue
        nonce=_verify_and_decode(starts[0],key,False)
        response=_verify_and_decode(challenges[0],key,True)
        finish=_verify_and_decode(finishes[0],key,False)
        if (nonce is None or response is None or finish is None or
                len(nonce)!=16 or len(response)!=48 or len(finish)!=32):
            status['trace_dechiffrement_incomplet']=True
            continue
        peer_nonce, proof=response[:16],response[16:]
        if not (hmac.compare_digest(proof,hmac.new(key,nonce,hashlib.sha256).digest())
                and hmac.compare_digest(finish,hmac.new(key,peer_nonce,hashlib.sha256).digest())):
            status['trace_dechiffrement_incomplet']=True
            continue
        status['sessions_challenge_verifie']+=1
        session_key=_session_key(key,nonce,peer_nonce)
        status['sessions_avec_cle_derivee']+=1
        for direction,frames in [('sortantes',outbound),('entrantes',inbound)]:
            for frame in frames:
                if frame[0]!=0x20:continue
                if not _frame_mac_valid(frame,session_key):continue
                status['commandes_0x20_hmac_verifiees' if direction=='sortantes' else 'reponses_0x20_hmac_verifiees']+=1
                plain=_verify_and_decode(frame,session_key,direction=='entrantes')
                if plain is None:
                    continue
                schema={'format':'reponse_vide','cles_structurelles_presentes':[]} if not plain else _schema_only(plain)
                formats[schema['format']]+=1
                foundkeys.update(schema['cles_structurelles_presentes'])
                status['commandes_0x20_dechiffrees' if direction=='sortantes' else 'reponses_0x20_dechiffrees']+=1
                label='commandes' if direction=='sortantes' else 'reponses'
                profile=_profile_0x20_b113(plain)
                profiles[label][profile['format']]+=1
                classes[label][profile['type']]+=1
                keynames[label].update(profile['champs'])
                nested=_nested_message_b114(plain)
                nested_forms[label][nested['formes_msg']]+=1
                nested_types[label][nested['types_imbriques']]+=1
                nested_paths[label][nested['emplacement_type']]+=1
                nested_keys[label].update(nested['champs_msg_autorises'])
                sig=_signaling_profile_b115(plain)
                # Compare *authenticated* encrypted bodies for exact duplicate
                # contents. No cryptographic bytes or digests are emitted.
                msg_b116=_msg_fields_b116(plain)
                if sig['sdp_present']:
                    encrypted_body=frame[2][4:-36] if direction=='entrantes' else frame[2][:-36]
                    b116_sdp_cipher[label].append(encrypted_body)
                    if isinstance(msg_b116.get('sessionId'),str):
                        b116_sessions[label].append(msg_b116['sessionId'])
                    media_b116=_media_sdp_b116(msg_b116.get('sdp'))
                    for media_name,enabled in media_b116.items():
                        if enabled:b116_media[media_name]+=1
                if sig['candidate_present']:
                    encrypted_body=frame[2][4:-36] if direction=='entrantes' else frame[2][:-36]
                    b116_candidate_cipher[label].append(encrypted_body)
                if label=='commandes' and sig['topic_present']:
                    b116_topics.append(_topic_match_b116(msg_b116,camera_did,station_did))
                topic_b117=_topic_profile_b117(msg_b116,camera_did,station_did)
                b117_topic[label]+=topic_b117['nombre']
                b117_topic_positions.update({label+'_'+k:v for k,v in topic_b117['positions'].items()})
                b117_topic_types.update({label+'_'+k:v for k,v in topic_b117['types'].items()})
                b117_topic_cibles.update(topic_b117['cibles_texte'])
                if sig['sdp_present']:
                    for _,sdp in _field_values_b117(msg_b116,'sdp'):
                        b118_proto[label][sdp_application_protocol(sdp)]+=1
                        pair=sdp_ice_credentials(sdp)
                        if pair and b118_ice[label] is None:b118_ice[label]=pair
                    b117_sessions[label].extend(_session_tokens_b117(msg_b116))
                    b117_sdp[label].update(_sdp_transport_b117(msg_b116))
                if sig['candidate_present']:
                    b117_candidate[label].update(_candidate_profile_b117(msg_b116))
                signaling_counts[label][sig['classe']]+=1
                for fld in ('sdp_present','candidate_present','session_id_present','topic_present','port_present','sdp_ice_present','sdp_video_present','sdp_audio_present'):
                    if sig[fld]: signaling_counts[label][fld]+=1
                if len(signaling_order[label])<24:
                    # Ordinal is local to the 0x20 frames within each direction.
                    signaling_order[label].append({'numero_0x20':len(signaling_order[label])+1, **sig})
    status['fondation_ice_b118']={
        'protocoles_application_sdp':{side:dict(b118_proto[side]) for side in ('commandes','reponses')},
        'verification_stun':verify_capture_stun(stun_samples or [], b118_ice['commandes'], b118_ice['reponses']),
        'analyse_passive_uniquement':True,'video_demarre':False}
    status['formats_0x20']=dict(formats)
    status['champs_structures_0x20']=sorted(foundkeys)
    status['analyse_messages_b113']={
        'commandes': {'formats':dict(profiles['commandes']),
                      'types_sanitises':dict(classes['commandes']),
                      'champs_racine_autorises':sorted(keynames['commandes'])},
        'reponses': {'formats':dict(profiles['reponses']),
                     'types_sanitises':dict(classes['reponses']),
                     'champs_racine_autorises':sorted(keynames['reponses'])},
        'aucune_valeur_json_retournee':True,
        'aucun_identifiant_retourne':True}
    status['structure_msg_b114']={
        direction:{
            'formes_msg':dict(nested_forms[direction]),
            'types_imbriques_sanitises':dict(nested_types[direction]),
            'position_type':dict(nested_paths[direction]),
            'champs_msg_autorises':sorted(nested_keys[direction])}
        for direction in ('commandes','reponses')}
    status['structure_msg_b114']['aucune_valeur_msg_retournee']=True
    status['signalisation_0x20_b115']={
        direction:{'compteurs':dict(signaling_counts[direction]),
                   'ordre_par_sens':signaling_order[direction]}
        for direction in ('commandes','reponses')}
    status['signalisation_0x20_b115'].update({
        'ordre_global_entre_sens_non_deduit':True,
        'aucune_valeur_sdp_ni_candidate_retournee':True,
        'aucune_offre_mqtt_envoyee':True,
        'aucune_commande_rejouee':True,
        'interpretation_role_offre_reponse_non_prouvee':True})
    first_c=b116_sessions['commandes'][:1]
    station_s=b116_sessions['reponses']
    session_match=(first_c[0] in station_s) if first_c and station_s else None
    send_ids={value for _,value in b117_sessions['commandes']}
    reply_ids={value for _,value in b117_sessions['reponses']}
    status['preparation_transport_b117']={
        'topic_total':sum(b117_topic.values()),
        'topic_positions':dict(b117_topic_positions),
        'topic_types':dict(b117_topic_types),
        'topic_correspondance_identifiants_candidats':dict(b117_topic_cibles),
        'sessions_sdp_par_sens':{
            side:{'champs_session_id_trouves':len(b117_sessions[side]),
                  'types':dict(Counter(_value_type_b117(v) for _,v in b117_sessions[side])),
                  'positions':dict(Counter(path for path,_ in b117_sessions[side]))}
            for side in ('commandes','reponses')},
        'session_id_commun_sdp':bool(send_ids & reply_ids) if send_ids and reply_ids else None,
        'sdp_transports_par_sens':{side:dict(b117_sdp[side]) for side in ('commandes','reponses')},
        'candidats_ice_par_sens':{side:dict(b117_candidate[side]) for side in ('commandes','reponses')},
        'analyse_locale_uniquement':True,
        'aucun_identifiant_topic_sdp_candidate_retourne':True,
        'aucun_paquet_envoye':True,
        'direct_c9_demarre':False,
    }
    status['ciblage_session_b116']={
        'sdp_reponses_total':len(b116_sdp_cipher['reponses']),
        'sdp_reponses_distincts':len(set(b116_sdp_cipher['reponses'])),
        'sdp_reponses_repetes':len(b116_sdp_cipher['reponses'])-len(set(b116_sdp_cipher['reponses'])),
        'candidats_reponses_total':len(b116_candidate_cipher['reponses']),
        'candidats_reponses_distincts':len(set(b116_candidate_cipher['reponses'])),
        'candidats_reponses_repetes':len(b116_candidate_cipher['reponses'])-len(set(b116_candidate_cipher['reponses'])),
        'candidats_commandes_distincts':len(set(b116_candidate_cipher['commandes'])),
        'id_session_commande_sdp_trouve_dans_reponse_sdp':session_match,
        'indices_topic_cibles':dict(Counter(b116_topics)),
        'indicateurs_media_sdp':dict(b116_media),
        'comparaison_contenus_chiffres_sans_export':True,
        'indice_topic_non_preuve_identite':True,
        'session_rejouee':False,
        'secret_ou_identifiant_retourne':False,
        'video_demarre':False,
    }
    return status


def audit_capture_h1l_b111(coordinator:Any, *, config_dir:str|Path,
                            nom_capture:object, ip_station:object,
                            confirmation_analyse_capture:bool,
                            autoriser_reconstitution_oem:bool=False,
                            confirmation_envoi_mot_de_passe:bool=False,
                            now:float|None=None)->dict:
    """One offline read, optional explicit OEM inventory, never send to camera."""
    base={'diagnostic':'aosu_pcap_local_c9_b111','analyse_hors_ligne':True,
          'appels_camera':0,'offres_mqtt':0,'connexions_p2p':0,
          'commandes_video':0,'commandes_ptz':0,'commandes_lan':0,
          'aucun_paquet_capture_renvoye':True,'aucun_secret_renvoye':True,
          'aucune_ecriture_fichier':True,
          'reconstitution_oem_autorisee':autoriser_reconstitution_oem is True,
          'consentement_capture':confirmation_analyse_capture is True}
    if confirmation_analyse_capture is not True:
        return {**base,'etat':'confirmation_analyse_requise'}
    if not isinstance(nom_capture,str) or not _NAME.fullmatch(nom_capture):
        return {**base,'etat':'nom_capture_invalide'}
    try:
        ip=ipaddress.ip_address(ip_station)
        if not isinstance(ip,ipaddress.IPv4Address) or not ip.is_private or ip.is_loopback:
            raise ValueError
        station_ip=str(ip)
    except (TypeError,ValueError):
        return {**base,'etat':'ip_station_invalide'}
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    requested=(root/nom_capture).resolve()
    if requested.parent != root:
        return {**base,'etat':'capture_hors_dossier_autorise'}
    try:
        if not requested.is_file():return {**base,'etat':'capture_absente'}
        if not 24<=requested.stat().st_size<=_MAX_FILE:
            return {**base,'etat':'taille_capture_invalide'}
    except OSError:
        return {**base,'etat':'capture_inaccessible'}
    client=getattr(coordinator,'client',None)
    tick=time.monotonic() if now is None else now
    state=_cache_state(client,tick)
    base['etat_cache_avant']=state
    if state!='cache_utilisable':
        if not (autoriser_reconstitution_oem is True and confirmation_envoi_mot_de_passe is True):
            return {**base,'etat':'inventaire_oem_requis'}
        try:
            inv=run_tuya_oem_inventory(client,confirmation_envoi_mot_de_passe=True,
                tester_rtc=False,tester_mqtt=False,tester_offre_mqtt=False,
                tester_relais_tcp=False,tester_kcp=False,tester_media=False)
        except Exception:
            return {**base,'etat':'erreur_inventaire_oem'}
        base['appels_http_oem']=inv.get('appel_reseau',0)
        base['mot_de_passe_envoye']=inv.get('mot_de_passe_envoye') is True
        if inv.get('etat')!='inventaire_termine':
            return {**base,'etat':'inventaire_oem_non_termine','etat_inventaire':inv.get('etat','indetermine')}
        state=_cache_state(client,time.monotonic() if now is None else now)
        if state!='cache_utilisable':
            return {**base,'etat':'cache_reconstitue_invalide'}
    cache=getattr(client,'_tuya_oem_inventory_cache',None)
    data=getattr(coordinator,'data',None)
    if not isinstance(data,dict) or not isinstance(cache,dict):
        return {**base,'etat':'inventaire_aosu_non_disponible'}
    camera_candidate, candidate=_candidate(data,client,1)
    if camera_candidate is None:
        return {**base,'etat':'correspondance_noms_non_unique'}
    stations=[v for v in data.values() if isinstance(v,dict) and v.get('model')=='H1L' and v.get('is_camera') is False]
    if len(stations)!=1:return {**base,'etat':'station_h1l_ambigue'}
    stname=stations[0].get('name')
    matches=[(did,v) for did,v in cache['devices'].items() if isinstance(v,dict) and _match_name(v,stname)]
    if len(matches)!=1 or matches[0][0]==camera_candidate:
        return {**base,'etat':'station_tuya_non_identifiee'}
    key=matches[0][1].get('localKey')
    if not isinstance(key,str) or len(key.encode('utf-8'))!=16:
        return {**base,'etat':'cle_locale_station_indisponible'}
    try:
        pcap=_read_pcap(requested,station_ip)
        crypto=_analyze_sessions(pcap['flows'],key.encode('utf-8'), camera_did=camera_candidate, station_did=matches[0][0], stun_samples=pcap['stun_samples'])
    except (OSError,ValueError,struct.error):
        return {**base,'etat':'capture_invalide_ou_incomplete'}
    return {**base,'etat':'analyse_hors_ligne_terminee',
            'correspondance_station_basee_sur_noms':True,
            'nombre_paquets_pcap':pcap['nombre_paquets'],
            'autres_ips_192_168_1_vues':pcap['autres_ips_lan_vues'],
            'precision_ips':'capture_application_uniquement; absence ne prouve pas absence IP camera',
            'udp_stun_station_vers_telephone':pcap['udp'][('station_vers_telephone','stun')],
            'udp_kcp_station_vers_telephone':pcap['udp'][('station_vers_telephone','kcp')],
            'chronologie_b113':pcap['chronologie_b113'],
            **crypto}
