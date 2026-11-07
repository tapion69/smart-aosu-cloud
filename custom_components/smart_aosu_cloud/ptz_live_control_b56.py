"""b66 SDK-confirmed gatewayVerCAD branch selection, experimental PTZ envelope with preserved MQTT safeguards.

A short *single* directional MQTT DP 119 publish is always followed by at
least one DP 116 STOP while using the same broker connection. Browser release,
blur, navigation and disconnection are extra signals; the server watchdog is
independent of the browser and caps motor commands at 0.75 seconds.

Neither the C5L physical reaction nor execution has been proven. A broker
PUBACK is transport receipt only. This module never claims physical control.
No device IDs/keys/topics/messages are returned or logged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
import secrets
import socket
import ssl
import struct
import threading
import time
import zlib
from typing import Any

_CADV_PATTERN = re.compile(r'^([0-9]{1,2})\.([0-9]{1,2})\.([0-9]{1,2})$')

def _sdk_cadv_layout(row: Any) -> tuple[str,str]:
    """APK classes4.dex 31697: CADV >= 1.0.2 omits devId for normal camera.

    The Android SDK copies DeviceRespBean.gatewayVerCAD into DeviceBean.cadv.
    The selected OEM inventory row must be inspected for this original field.
    If absent, preserve the previous experimental branch without claiming proof.
    """
    versions = set()
    queue = [(row, 0)]
    count = 0
    while queue and count < 140:
        item, depth = queue.pop()
        count += 1
        if depth > 5:
            continue
        if isinstance(item, dict):
            for key in ('gatewayVerCAD', 'cadv', 'cAdv'):
                val = item.get(key)
                if isinstance(val, str):
                    match = _CADV_PATTERN.fullmatch(val.strip())
                    if match:
                        versions.add(tuple(int(x) for x in match.groups()))
            for value in list(item.values())[:45]:
                if isinstance(value, (dict,list)):
                    queue.append((value,depth+1))
        elif isinstance(item, list):
            for value in item[:35]:
                if isinstance(value,(dict,list)):
                    queue.append((value,depth+1))
    if len(versions)>1:
        raise ValueError('cadv_contradictoire')
    if len(versions)==1:
        version=next(iter(versions))
        if version >= (1,0,2):
            return 'compact','cadv_confirme_au_moins_1_0_2'
        return 'legacy','cadv_confirme_ancien'
    return 'compact','cadv_non_disponible_format_compact_experimental_pcap'

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from .ptz_mqtt_stop_b54 import _key_from_row

MAX_HOLD_SECONDS = 0.75
COOLDOWN_SECONDS = 4.0
REPLY_OBSERVATION_SECONDS = 1.75
_DIRECTION = {'up': '0', 'right': '2', 'down': '4', 'left': '6'}


def encode_command(topic_id: str, local_key: bytes, *, device_id: str, dp: int, value: Any,
                   o: int, s: int, timestamp: int, layout: str = 'legacy') -> bytes:
    """SDK-derived pv2.2 envelope. Device/DP map matches Android sendCommand.

    A valid broker PUBACK does NOT establish camera execution. The exact
    C5L routing semantics remain experimentally unverified.
    """
    if not isinstance(topic_id,str) or not 5 <= len(topic_id) <= 128:
        raise ValueError('invalid topic')
    if not isinstance(local_key,bytes) or len(local_key) != 16:
        raise ValueError('invalid key')
    import re
    if not isinstance(device_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}',device_id):
        raise ValueError('invalid device')
    if dp == 119 and type(value) is str and value in _DIRECTION.values():
        pass
    elif dp == 116 and value is True:
        pass
    else:
        raise ValueError('invalid PTZ DP')
    if not (1000 <= o <= 1000999 and 3 <= s <= 8 and 1 <= timestamp < 2**32):
        raise ValueError('invalid counters')
    # APK classes4.dex dqdpbbd.bdpdqbp (#31697): DeviceBean -> JSONObject
    # containing 'devId' + 'dps' (and optionally gateway fields).
    # For an ordinary direct IPC the mandatory fields are these two.
    # APK classes4.dex dqdpbbd.bdpdqbp (#31697) calls
    # bbppbbd.bdpdqbp (#29611), which forwards literal int 5 to
    # bbppbbd.bdpdqbp (#29613) -> MqttControlBuilder.setProtocol.
    # Both protocol=4 (b55-b57) and protocol=0 (b58-b61) were wrong
    # for that specific MQTT publishDps SDK path. C5L still unverified.
    if layout == 'legacy':
        data={'devId':device_id,'dps':{str(dp):value}}
    elif layout == 'compact':
        data={'dps':{str(dp):value}}
    else:
        raise ValueError('invalid SDK CADV layout')
    plain=json.dumps({'data':data,'protocol':5,'t':timestamp},
                     ensure_ascii=False,separators=(',',':')).encode('utf-8')
    padder=PKCS7(128).padder()
    padded=padder.update(plain)+padder.finalize()
    encryptor=Cipher(algorithms.AES(local_key),modes.ECB()).encryptor()
    encrypted=encryptor.update(padded)+encryptor.finalize()
    body=struct.pack('!II',o,s)+encrypted
    return topic_id.encode('utf-8')+struct.pack('!I',zlib.crc32(body)&0xffffffff)+body


def _pack_qos1(topic: str, body: bytes, packet_id: int) -> bytes:
    from .tuya_mqtt_signaling import _u16_string, _packet_remaining_length
    if not topic.startswith('smart/mb/out/') or any(c in topic for c in ('#','+','\x00','\r','\n')):
        raise ValueError('invalid topic')
    if type(body) is not bytes or not 16 <= len(body) <= 4096 or not packet_id in (2,3,4):
        raise ValueError('invalid MQTT packet')
    content=_u16_string(topic)+struct.pack('!H',packet_id)+body
    return b'\x32'+_packet_remaining_length(len(content))+content


def _inspect_incoming_publish(header: int, body: bytes, topic_id: str, key: bytes) -> dict:
    """Inspect incoming MQTT PUBLISH, without reporting raw data or identities.

    The SDK may transmit unrelated status or signaling on this subscription.
    An inbound message is NOT camera acknowledgment unless it can be correlated
    with the motor command (correlation is not implemented here).
    """
    if header >> 4 != 3 or len(body) < 2:
        return {'valid': False}
    topic_len = struct.unpack('!H', body[:2])[0]
    if topic_len < 1 or topic_len > 256 or len(body) < 2 + topic_len:
        return {'valid': False}
    try:
        received_topic = body[2:2 + topic_len].decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        return {'valid': False}
    qos = (header >> 1) & 0x03
    if qos == 3:
        return {'valid': False}
    offset = 2 + topic_len
    packet_id = None
    if qos:
        if len(body) < offset + 2:
            return {'valid': False}
        packet_id = struct.unpack('!H', body[offset:offset + 2])[0]
        if packet_id == 0:
            return {'valid': False}
        offset += 2
    # Nothing identifying is returned; only one trusted inbound topic counts.
    expected = 'smart/mb/in/' + topic_id
    if received_topic != expected:
        return {'valid': True, 'matched': False, 'packet_id': packet_id if qos == 1 else None}
    result = {'valid': True, 'matched': True, 'packet_id': packet_id if qos == 1 else None,
              'frame22_integrity_valid': False, 'frame22_json_decoded': False}
    payload = body[offset:]
    prefix = topic_id.encode('utf-8')
    if not payload.startswith(prefix) or len(payload) < len(prefix) + 12 + 16:
        return result
    segment = payload[len(prefix):]
    crc = struct.unpack('!I', segment[:4])[0]
    encrypted = segment[12:]
    if len(encrypted) % 16 or not encrypted or zlib.crc32(segment[4:]) & 0xffffffff != crc:
        return result
    result['frame22_integrity_valid'] = True
    try:
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        raw = decryptor.update(encrypted) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(raw) + unpadder.finalize()
        decoded = json.loads(plaintext.decode('utf-8'))
        if isinstance(decoded, dict) and isinstance(decoded.get('protocol'), int) and 'data' in decoded:
            result['frame22_json_decoded'] = True
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    return result


def _preflight(coordinator: Any):
    """Read only cached OEM attributes and in-memory auth; no login/refresh."""
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_sdk_sources_b47 import inspect_sdk_properties
    from .ptz_mqtt_transport_b53 import _communication_topic_id
    from .tuya_uid_gateway import TuyaAuthSession
    from .uid_token_probe import _ready_identity,_apk_preflight
    from .tuya_mqtt_signaling import _identity

    if not getattr(getattr(coordinator,'live_controller',None),'running',False):
        raise ValueError('direct_requis')
    selected,reason=select_c5l_oem(coordinator)
    if selected is None:
        raise ValueError('cache_oem_absent_ou_expire')
    _device_id,row,method=selected
    if method != 'nom_unique_confirme_par_utilisateur':
        raise ValueError('selection_oem_non_confirmee')
    if inspect_sdk_properties(row).get('pv') != '2.2':
        raise ValueError('pv22_non_confirme')
    key=_key_from_row(row)
    if key is None:
        raise ValueError('cle_locale_invalide')
    # b60: the APK's real DP publication route is
    # dqdpbbd.bdpdqbp -> bbppbbd.bdpdqbp -> MqttControlBuilder.setTopicId.
    # The first argument of that chain is the OEM DeviceBean devId, not the
    # `communicationNode` inventory attribute used experimentally in b53-b59.
    # Keep communicationNode as a presence check only (never use it as topicId).
    node,reason=_communication_topic_id(row)
    if node is None:
        raise ValueError('noeud_communication_indisponible')
    # select_c5l_oem already validates the ASCII device ID and uniquely
    # selects the owner's named C5L.  Never export ID or topic in diagnostics.
    if not isinstance(_device_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}',_device_id):
        raise ValueError('identifiant_camera_invalide')
    topic_id=_device_id
    layout,cadv_status=_sdk_cadv_layout(row)
    session=getattr(coordinator.client,'_tuya_oem_session',None)
    if not isinstance(session,TuyaAuthSession) or not 0<=time.monotonic()-session.acquired_at<1200:
        raise ValueError('session_oem_absente_ou_expiree')
    ready=_ready_identity(coordinator.client)
    if ready is None:
        raise ValueError('profil_oem_absent')
    _,install_id=ready
    _,material=_apk_preflight(coordinator.client.apk_path)
    if material is None:
        raise ValueError('ressources_oem_invalides')
    identity,signer=material
    # Use separate MQTT client id from video: the broker must not kick the
    # existing video session when the test controller connects.
    auth=_identity(identity,signer,session,install_id+'-ptz-hold',topic_id)
    return key,topic_id,auth,_device_id,layout,cadv_status


@dataclass
class _Gesture:
    direction: str
    identifier: str
    release: threading.Event=field(default_factory=threading.Event)


class ExperimentalPtzLiveController:
    """Only one gesture at a time, fail-closed and bounded independently of UI."""
    def __init__(self,coordinator:Any):
        self.coordinator=coordinator
        self._lock=threading.Lock()
        self._active:_Gesture|None=None
        self._next_allowed=0.0
        self._closing=False
        self._worker:threading.Thread|None=None
        self._state='inactif'
        self._prepared=None
        self._arming=False
        self._early_releases={}
        self._counters={'arm_recus':0,'press_recus':0,'release_recus':0,
                        'directions_envoyees_socket':0,'stops_envoyes_socket':0,'direction_pubacks':0,'stop_pubacks':0,
                        'mqtt_messages_entrants':0,'mqtt_messages_topic_ptz':0}
        self._last_press='aucun'
        self._last_arm='aucun'
        self._last_release='aucun'
        self._last_cycle='aucun'
        self._cadv_branch='pas_encore_prepare'
        self._last_observation={'mqtt_publish_inbound':0,'mqtt_publish_topic_attendu':0,
                                'trames_22_crc_valides':0,'trames_22_json_decodees':0,
                                'direction_puback_observe':False,'stops_puback_observes':0,
                                'reponse_camera_ptz_correlable':False}

    def status(self)->dict:
        with self._lock:
            prepared=self._prepared is not None and time.monotonic()<self._prepared[3]
            return {'diagnostic':'aosu_ptz_live_b56','etat':self._state,
                    'direct_en_cours':bool(getattr(getattr(self.coordinator,'live_controller',None),'running',False)),
                    'session_preparee_valide':bool(prepared),
                    'compteurs':dict(self._counters),
                    'interpretation_compteurs':'sendall_socket_ne_prouve_pas_reception_broker_ni_camera',
                    'dernier_appui':self._last_press,
                    'dernier_armement':self._last_arm,
                    'dernier_relachement':self._last_release,
                    'dernier_cycle_mqtt':self._last_cycle,
                    'observation_dernier_cycle':dict(self._last_observation),
                    'mouvement_physique_confirme':False,
                    'arret_physique_confirme':False,
                    'schema_implementation_experimental':True,
                    'controle_actif':self._active is not None,
                    'duree_max_seconde':MAX_HOLD_SECONDS,
                    'format_sdk_b63':'cadv_dps_sans_devId_si_cadv_au_moins_1_0_2_protocol_5',
                    'selection_cadv_b66':'gatewayVerCAD_lu_depuis_inventaire_oem_si_disponible',
                    'branche_cadv':self._cadv_branch,
                    'observation_b59':'reponses_mqtt_non_identifiantes_apres_stop',
                    'transport_b60':'topic_sdk_device_id_au_lieu_communication_node',
                    'publication_camera_confirmee':False,
                    'pas_de_confirmation_camera':True}

    def _arm_result(self,result:dict)->dict:
        with self._lock:self._last_arm=result.get('etat','inconnu')
        return result

    def _press_result(self,result:dict)->dict:
        with self._lock:self._last_press=result.get('etat','inconnu')
        return result

    def arm(self,*,consent:bool)->dict:
        """Pre-connect MQTT; no PTZ publish. Must finish before a pointer press."""
        with self._lock:self._counters['arm_recus']+=1
        if consent is not True:return self._arm_result({'etat':'consentement_test_requis'})
        with self._lock:
            if self._closing:
                self._last_arm='controle_ferme'
                return {'etat':'controle_ferme'}
            if self._active:
                self._last_arm='direction_deja_active'
                return {'etat':'direction_deja_active'}
            if self._arming:
                self._last_arm='connexion_ptz_deja_en_cours'
                return {'etat':'connexion_ptz_deja_en_cours'}
            if self._prepared and time.monotonic()<self._prepared[3]:
                self._last_arm='session_prete'
                return {'etat':'session_prete','commandes_motrices_envoyees':0}
            old=self._prepared
            self._prepared=None
            self._arming=True
        if old:
            try:old[0].close()
            except OSError:pass
        conn=None
        try:
            key,topic_id,auth,device_id,layout,cadv_status=_preflight(self.coordinator)
            from .tuya_mqtt_signaling import (_BROKER,_PORT,_TIMEOUT_SECONDS,_mqtt_connect_packet,
                                              _mqtt_subscribe_packet,_read_packet)
            ctx=ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ctx.check_hostname=True
            ctx.verify_mode=ssl.CERT_REQUIRED
            tcp=socket.create_connection((_BROKER,_PORT),timeout=_TIMEOUT_SECONDS)
            try:conn=ctx.wrap_socket(tcp,server_hostname=_BROKER)
            except BaseException:
                tcp.close()
                raise
            conn.settimeout(_TIMEOUT_SECONDS)
            conn.sendall(_mqtt_connect_packet(auth))
            typ,data=_read_packet(conn)
            if typ!=0x20 or data!=b'\x00\x00':return self._arm_result({'etat':'connexion_mqtt_refusee'})
            conn.sendall(_mqtt_subscribe_packet(auth.topic))
            typ,data=_read_packet(conn)
            if typ!=0x90 or len(data)!=3 or data[:2]!=b'\x00\x01' or data[2] not in (0,1):
                return self._arm_result({'etat':'abonnement_mqtt_refuse'})
            with self._lock:
                if self._closing:
                    self._last_arm='controle_ferme'
                    return {'etat':'controle_ferme'}
                self._prepared=(conn,key,topic_id,time.monotonic()+20,device_id,layout)
                self._cadv_branch=cadv_status
                conn=None
                self._state='session_ptz_prete_sans_publication'
                self._last_arm='session_prete'
            return self._arm_result({'etat':'session_prete','commandes_motrices_envoyees':0})
        except ValueError:
            return self._arm_result({'etat':'preparation_mqtt_impossible'})
        except (OSError,ssl.SSLError,TimeoutError,EOFError):
            return self._arm_result({'etat':'connexion_mqtt_impossible'})
        finally:
            if conn:
                try:conn.close()
                except OSError:pass
            with self._lock:self._arming=False

    def press(self,direction:str,identifier:str,*,consent:bool)->dict:
        with self._lock:self._counters['press_recus']+=1
        if consent is not True:
            return self._press_result({'etat':'consentement_test_requis'})
        if direction not in _DIRECTION or not isinstance(identifier,str) or not identifier.isalnum() or not 12 <= len(identifier) <= 64:
            return self._press_result({'etat':'commande_invalide'})
        if not getattr(getattr(self.coordinator,'live_controller',None),'running',False):
            return self._press_result({'etat':'direct_requis'})
        with self._lock:
            if self._closing:
                self._last_press='controle_ferme'
                return {'etat':'controle_ferme'}
            self._early_releases={k:v for k,v in self._early_releases.items() if v>time.monotonic()}
            if identifier in self._early_releases:
                self._early_releases.pop(identifier,None)
                self._last_press='relache_deja_recu_aucun_mouvement'
                return {'etat':'relache_deja_recu_aucun_mouvement'}
            if self._active:
                self._last_press='direction_deja_active'
                return {'etat':'direction_deja_active'}
            if time.monotonic()<self._next_allowed:
                self._last_press='temporisation_quatre_secondes'
                return {'etat':'temporisation_quatre_secondes'}
            prepared=self._prepared
            self._prepared=None
            if prepared is None:
                self._last_press='session_non_armee'
                return {'etat':'session_non_armee'}
            if time.monotonic() >= prepared[3]:
                try:prepared[0].close()
                except OSError:pass
                self._last_press='session_ptz_expiree'
                return {'etat':'session_ptz_expiree'}
            gesture=_Gesture(direction,identifier)
            self._active=gesture
            self._state='preparation_commande'
            self._next_allowed=time.monotonic()+COOLDOWN_SECONDS
            thread=threading.Thread(target=self._run,args=(gesture,prepared),daemon=True,name='aosu-ptz-hold-b56')
            self._worker=thread
            thread.start()
        return self._press_result({'etat':'demande_direction_en_cours','mouvement_physique_confirme':False})

    def release(self,identifier:str)->dict:
        with self._lock:
            self._counters['release_recus']+=1
            g=self._active
            if g and g.identifier==identifier:
                g.release.set()
                self._last_release='arret_demande'
                return {'etat':'arret_demande','arret_physique_confirme':False}
            if isinstance(identifier,str) and identifier.isalnum() and 12<=len(identifier)<=64:
                # A release may arrive before a press due to async scheduling.
                # Never start motion if we already saw its matching release.
                if len(self._early_releases)<40:
                    self._early_releases[identifier]=time.monotonic()+20
        with self._lock:self._last_release='aucune_direction_active'
        return {'etat':'aucune_direction_active'}

    def shutdown(self):
        with self._lock:
            self._closing=True
            g=self._active
            worker=self._worker
            prepared=self._prepared
            self._prepared=None
            if g:g.release.set()
        if prepared:
            try:prepared[0].close()
            except OSError:pass
        if worker and worker.is_alive():worker.join(timeout=5)

    def _update(self,g,state):
        with self._lock:
            if self._active is g:self._state=state

    def _run(self,g:_Gesture,prepared):
        conn,key,topic_id,_expires,device_id,layout=prepared
        try:
            state=self._send_prepared(g,conn,key,topic_id,device_id,layout=layout)
        except Exception:
            state='erreur_mqtt_stop_non_confirme_ouvrir_appli_aosu'
        finally:
            try:conn.close()
            except OSError:pass
            with self._lock:
                if self._active is g:
                    self._active=None
                    self._state=state
                self._last_cycle=state

    def _send_prepared(self,g:_Gesture,conn:Any,key:bytes,topic_id:str,device_id:str,*,layout:str='legacy')->str:
        """Send one bounded pulse + two STOPs; read MQTT responses without secrets.

        The reply window records only metadata. Receipt by the broker, including
        a device-like inbound packet, is never proof of a physical motor action.
        """
        from .tuya_mqtt_signaling import _read_packet
        published=False
        stop_sent=False
        observation={'mqtt_publish_inbound':0,'mqtt_publish_topic_attendu':0,
                     'trames_22_crc_valides':0,'trames_22_json_decodees':0,
                     'direction_puback_observe':False,'stops_puback_observes':0,
                     'reponse_camera_ptz_correlable':False}
        acked=set()
        o=secrets.randbelow(1_000_000)+1000
        try:
            if g.release.is_set() or not getattr(self.coordinator.live_controller,'running',False):
                return 'relache_avant_publication_aucun_mouvement'
            frame=encode_command(topic_id,key,device_id=device_id,dp=119,value=_DIRECTION[g.direction],
                                 o=o,s=3,timestamp=int(time.time()),layout=layout)
            conn.sendall(_pack_qos1('smart/mb/out/'+topic_id,frame,2))
            published=True
            with self._lock:self._counters['directions_envoyees_socket']+=1
            self._update(g,'direction_publiee_non_confirmee')
            g.release.wait(MAX_HOLD_SECONDS)
        finally:
            if published:
                # Independent STOP watchdog: no dependency on browser events.
                for sequence,packet in ((4,3),(5,4)):
                    try:
                        stop=encode_command(topic_id,key,device_id=device_id,dp=116,value=True,o=o,s=sequence,
                                            timestamp=int(time.time()),layout=layout)
                        conn.sendall(_pack_qos1('smart/mb/out/'+topic_id,stop,packet))
                        stop_sent=True
                        with self._lock:self._counters['stops_envoyes_socket']+=1
                    except (OSError,ssl.SSLError,ValueError):pass
                # Observe all broker ack IDs, not just the first STOP ack.
                # Observe inbound publish packets on the known reply topic.
                # No identifiers / topic / ciphertext / plaintext leave memory.
                deadline=time.monotonic()+REPLY_OBSERVATION_SECONDS
                count=0
                while time.monotonic()<deadline and count<24:
                    count+=1
                    conn.settimeout(max(0.1, deadline-time.monotonic()))
                    try:typ,data=_read_packet(conn)
                    except (OSError,TimeoutError,EOFError,ValueError):break
                    if typ==0x40 and len(data)==2:
                        packet_id=struct.unpack('!H',data)[0]
                        if packet_id in (2,3,4) and packet_id not in acked:
                            acked.add(packet_id)
                            if packet_id==2:
                                observation['direction_puback_observe']=True
                                with self._lock:self._counters['direction_pubacks']+=1
                            else:
                                observation['stops_puback_observes']+=1
                                with self._lock:self._counters['stop_pubacks']+=1
                    elif typ >> 4 == 3:
                        item=_inspect_incoming_publish(typ,data,topic_id,key)
                        if item.get('valid'):
                            observation['mqtt_publish_inbound']+=1
                            with self._lock:self._counters['mqtt_messages_entrants']+=1
                            if item.get('matched'):
                                observation['mqtt_publish_topic_attendu']+=1
                                with self._lock:self._counters['mqtt_messages_topic_ptz']+=1
                            if item.get('frame22_integrity_valid'):
                                observation['trames_22_crc_valides']+=1
                            if item.get('frame22_json_decoded'):
                                observation['trames_22_json_decodees']+=1
                            if item.get('packet_id') is not None:
                                try:conn.sendall(b'\x40\x02'+struct.pack('!H',item['packet_id']))
                                except (OSError,ssl.SSLError):pass
                with self._lock:self._last_observation=observation
            try:conn.sendall(b'\xe0\x00')
            except (OSError,ssl.SSLError):pass
        if not published:return 'aucun_mouvement_publie'
        if not stop_sent:return 'direction_publiee_stop_non_transmis_ouvrir_appli_aosu'
        if not observation['stops_puback_observes']:
            return 'stop_publie_sans_puback_ouvrir_appli_aosu'
        return 'stop_puback_broker_aucune_confirmation_camera'
