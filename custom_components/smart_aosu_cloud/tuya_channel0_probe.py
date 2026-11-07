"""Explicitly opt-in, bounded Tuya AES/KCP channel-0 startup / media observation.

No PTZ, audio transmission, persistent media data, secret-bearing diagnostics.
Protocol based on independent MIT-licensed tuya-ipc-p2p-sdk (Rodrigo Roque).
See THIRD_PARTY_NOTICES.md. C5L media support remains experimental.
"""
from __future__ import annotations
import hashlib
import hmac
import time
from typing import Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .tuya_kcp_probe import _segment, _media_frame, _parse_segment, _unwrap_media, _next_frame
from .tuya_codec_fingerprint import CodecFingerprint
from .tuya_hevc_structure import MediaStructureProbe
from .tuya_frame_envelope import FrameEnvelopeProbe
from .tuya_fragment_continuity import FragmentContinuityProbe
from .tuya_run_assembly import RunAssemblyProbe
from .tuya_local_media_capture import LocalMediaCapture
from .tuya_kcp_receive_b87 import KcpReceiveB87
from .tuya_tcp_frames_b90 import RelayFrameReaderB90
from .tuya_relay_keepalive_b92 import RelayKeepaliveB92
from .tuya_control_kcp_b96 import ControlDeliveryB96

_CONTROL_MAGIC=0x12345678
_MAX_FRAME=4*1024*1024
_MEDIA_MARKER=b"\x00\xff\x50\x3c"
_CAPABILITY=(b'{"cmd":"capability_exchange_req","protocol_version":1,'
             b'"data":{"capabilities":{"opus_encode":1,"opus_decode":1}}}\x00')

def _parse_answer_key(sdp: Any) -> bytes|None:
    if not isinstance(sdp,str) or len(sdp)>16384: return None
    for line in sdp.splitlines():
        if line.startswith('a=aes-key:'):
            try: val=bytes.fromhex(line[10:].strip())
            except ValueError: return None
            return val if len(val)==16 else None
    return None

def _record_encrypt(key:bytes, plain:bytes, iv:bytes) -> bytes:
    if len(key)!=16 or len(iv)!=16:raise ValueError('bad aes record key')
    pad=16-len(plain)%16
    encryptor=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
    return iv+encryptor.update(plain+bytes([pad])*pad)+encryptor.finalize()

def _record_decrypt(key:bytes, record:bytes) -> bytes:
    if len(key)!=16 or len(record)<32 or len(record)%16:raise ValueError('bad record length')
    decryptor=Cipher(algorithms.AES(key),modes.CBC(record[:16])).decryptor()
    plain=decryptor.update(record[16:])+decryptor.finalize()
    pad=plain[-1]
    if pad<1 or pad>16 or plain[-pad:] != bytes([pad])*pad:raise ValueError('invalid record padding')
    return plain[:-pad]

def _u32(x:int)->bytes:return x.to_bytes(4,'little')

def _auth(device_password:str,local_key:str)->bytes:
    token=hashlib.md5((device_password+'||'+local_key).encode(),usedforsecurity=False).hexdigest().encode()
    body=bytearray(96);body[:5]=b'admin';body[32:64]=token
    return _u32(_CONTROL_MAGIC)+_u32(1)+bytes(body)

def _command(t:int,sub:int,payload:bytes)->bytes:
    return _u32(_CONTROL_MAGIC)+_u32(t)+_u32(0)+_u32(sub)+_u32(len(payload))+payload

def _startup_commands(device_password:str,local_key:str)->tuple[bytes,...]:
    return (
       _auth(device_password,local_key),
       _command(0,0x0A,_u32(0x00010001)),
       _command(0,0x15,_CAPABILITY),
       _command(2,0x02,_u32(0)),
       _command(0x00010004,0x09,_u32(0)+_u32(4)),
       _command(0x00010003,0x06,_u32(0)+_u32(0)),
       _command(0x00010005,0x00040006,_u32(0)+_u32(4)),
    )

def _maybe_jpeg_chunks(plain:bytes) -> list[tuple[int,bytes]]:
    found=[];cursor=0
    while True:
        marker=plain.find(_MEDIA_MARKER,cursor)
        if marker<0:return found
        head=marker-16
        if head>=4:
            size=int.from_bytes(plain[head-4:head],'little')
            if 20<=size<=len(plain)-head and size<=_MAX_FRAME:
                offset=int.from_bytes(plain[head+12:head+16],'big')
                found.append((offset,plain[head+20:head+size]))
                cursor=head+size
                continue
        cursor=marker+4

def run_media_start(sock:Any,offer_key:bytes,answer_sdp:str,local_key:str,device_password:str,
                    *,wait_seconds:float=11.0,max_frames:int=320,
                    local_capture_directory:str|None=None,live_preview=None)->dict[str,object]:
    """Called on an authenticated relay after its tunneled offer.

    Manual diagnostics are bounded; interactive live runs until explicit Stop,
    transport closure, or 45 seconds without valid decrypted video.
    """
    out={'diagnostic':'aosu_tuya_media_start_b27', 'confirmation_requise':True,
         'reponse_sdp_key_valide':False,'commandes_controle_envoyees':0,
         'segments_media_valides_recus':0,'segments_media_acquittes':0,
         'acquittements_controle_recus':0,'conversation_controle_detectee':False,
         'conversation_video_detectee':False,'paquets_video_chiffres_recus':0,
         'paquets_video_dechiffres':0,'blocs_jpeg_detectes':0,'image_jpeg_complete_detectee':False,
         'commande_ptz':0,'images_exportees':0,'secrets_retournes':False,
         'etat':'demarrage_media_non_execute',
         'cause_fin_session_b85':'non_determinee'}
    answer_key=_parse_answer_key(answer_sdp)
    if answer_key is None or len(offer_key)!=16 or not isinstance(local_key,str) or len(local_key.encode()) not in (16,24,32):
        out['etat']='cles_media_ou_sdp_invalides';return out
    if not isinstance(device_password,str) or len(device_password)>2048:
        out['etat']='mot_de_passe_appareil_invalide';return out
    out['reponse_sdp_key_valide']=True
    from secrets import token_bytes
    # Seven existing control commands; B96 adds bounded KCP resend ONLY when ACK is missing.
    control_b96 = ControlDeliveryB96()
    for seq,packet in enumerate(_startup_commands(device_password,local_key)):
        record=_record_encrypt(offer_key,packet,token_bytes(16))
        try:
            frame = _media_frame(offer_key,_segment(0,0x51,seq,0,int(time.monotonic()*1000)&0xffffffff,record))
            sock.sendall(frame)
            if live_preview is not None: control_b96.sent(seq, frame)
        except (OSError, EOFError, ConnectionError):
            out['cause_fin_session_b85']='relais_ferme_pendant_demarrage'
            out['etat']='demarrage_media_interrompu'
            return out
        out['commandes_controle_envoyees']+=1
        if live_preview is not None:live_preview._b87_control_sent=out['commandes_controle_envoyees']
    deadline = (float('inf') if live_preview is not None
                else time.monotonic() + min(15,max(0.1,wait_seconds)))
    last_video = time.monotonic()
    # Bounded de-dup history: long sessions must not accumulate every KCP seq.
    receivers:dict[int,KcpReceiveB87]={}
    image=bytearray();image_started=False
    codec_probe=CodecFingerprint()
    structure_probe=MediaStructureProbe()
    envelope_probe=FrameEnvelopeProbe()
    continuity_probe=FragmentContinuityProbe()
    assembly_probe=RunAssemblyProbe()
    local_capture=LocalMediaCapture(local_capture_directory) if local_capture_directory else None
    count=0
    frame_reader = RelayFrameReaderB90()
    keepalive = RelayKeepaliveB92()
    out['kcp_reception_b87'] = {}
    out['transport_tcp_b90'] = {}
    out['relais_keepalive_b92'] = keepalive.summary()
    out['fiabilite_controle_b96'] = control_b96.summary()
    # B90: report live KCP counters even if the session is interrupted.
    def _snapshot():
        tcp = frame_reader.summary()
        kcp = {
            'controle': receivers[0].summary() if 0 in receivers else {},
            'video': receivers[1].summary() if 1 in receivers else {},
        }
        out['transport_tcp_b90'] = tcp
        out['kcp_reception_b87'] = kcp
        out['relais_keepalive_b92'] = keepalive.summary()
        out['fiabilite_controle_b96'] = control_b96.summary()
        if live_preview is not None:
            live_preview._b90_tcp = tcp
            live_preview._b87_kcp = kcp
            live_preview._b92_keepalive = out['relais_keepalive_b92']
            live_preview._b96_control = out['fiabilite_controle_b96']

    while (time.monotonic() < deadline
           and (live_preview is not None or count < max_frames)
           and (live_preview is None or not live_preview.stopped)):
        if live_preview is not None and time.monotonic()-last_video>45.0:
            out['arret_inactivite_video']=True
            out['cause_fin_session_b85']='absence_video_45s'
            break
        if (live_preview is not None and getattr(live_preview, '_process', None) is not None
                and live_preview._process.poll() is not None):
            out['arret_dechiffreur']=True
            out['cause_fin_session_b85']='ffmpeg_termine'
            break
        # B96: resend non-acknowledged channel-0 pushes, never the relay offer.
        if live_preview is not None:
            try:
                control_b96.retransmit_if_due(sock)
            except (OSError, ConnectionError, EOFError):
                out['cause_fin_session_b85']='erreur_retransmission_controle_b96'
                _snapshot()
                break
        # B92: the relay requires *outbound* F5 keepalives about once a
        # second. Replying only to inbound F5 (B91) does not satisfy this.
        try:
            keepalive.send_if_due(sock)
        except (OSError, ConnectionError, EOFError):
            out['cause_fin_session_b85']='erreur_keepalive_relais_b92'
            _snapshot()
            break
        sock.settimeout(max(.1,min(1.0,deadline-time.monotonic())))
        try:
            frame = frame_reader.read(sock)
            if frame is None:
                _snapshot()
                continue
            kind, payload = frame
        except (EOFError, ConnectionError, OSError):
            out['cause_fin_session_b85']='connexion_relais_fermee'
            _snapshot()
            break
        except ValueError:
            out['cause_fin_session_b85']='trame_tcp_invalide'
            _snapshot()
            break
        count+=1
        if kind==0xF5:
            # The inbound F5 is informational; the dedicated outbound timer
            # above supplies the mandatory client keepalive independently.
            keepalive.receive()
            continue
        if kind!=0xF6:continue
        try:segment=_parse_segment(_unwrap_media(offer_key,payload))
        except ValueError:continue
        if segment is None:continue
        conv,cmd,frag,stamp,seq,una,data=segment
        if conv == 0 and live_preview is not None:
            control_b96.input(cmd=cmd, sequence=seq, una=una)
        out['segments_media_valides_recus']+=1
        if conv==0:
            out['conversation_controle_detectee']=True
            if live_preview is not None:
                live_preview.ptz_control_observer.segment()
        if conv==1:out['conversation_video_detectee']=True
        if cmd==0x52 and conv==0:out['acquittements_controle_recus']+=1
        if cmd==0x53:
            try:
                sock.sendall(_media_frame(offer_key,_segment(conv,0x54,0,receivers.get(conv, KcpReceiveB87()).next_sequence)))
            except (OSError, ConnectionError):
                out['cause_fin_session_b85']='erreur_envoi_acquittement_kcp'
                break
        if cmd!=0x51:continue
        receiver = receivers.setdefault(conv, KcpReceiveB87())
        # Only ack complete received segment, with contiguous UNA (not arrival order).
        messages = receiver.accept(seq, frag, data)
        try:
            sock.sendall(_media_frame(offer_key,_segment(conv,0x52,seq,receiver.next_sequence,stamp)))
        except (OSError, ConnectionError):
            out['cause_fin_session_b85']='erreur_envoi_ack_video'
            break
        out['segments_media_acquittes'] += 1
        if conv not in (0,1):continue
        for joined in messages:
            if conv==1:out['paquets_video_chiffres_recus']+=1
            try:plain=_record_decrypt(answer_key,joined)
            except ValueError:
                if conv == 0 and live_preview is not None:
                    live_preview.ptz_control_observer.decrypt_error()
                continue
            if conv == 0 and live_preview is not None:
                live_preview.ptz_control_observer.decrypted_control_record(plain)
            if conv==1:
                out['paquets_video_dechiffres']+=1
                if live_preview is not None:live_preview._b87_decrypted_media=out['paquets_video_dechiffres']
                last_video=time.monotonic()
                if live_preview is not None:
                    live_preview.feed(plain)
                if local_capture is not None:
                    local_capture.feed(plain)
                codec_probe.feed(plain)
                structure_probe.feed(plain)
                envelope_probe.feed(plain)
                continuity_probe.feed(plain)
                assembly_probe.feed(plain)
                for offset,chunk in _maybe_jpeg_chunks(plain):
                    out['blocs_jpeg_detectes']+=1
                    if offset==0 and chunk.startswith(b'\xff\xd8'):
                        if image_started and image.endswith(b'\xff\xd9'):
                            out['image_jpeg_complete_detectee']=True
                        image=bytearray();image_started=True
                    if image_started and offset<=_MAX_FRAME and offset+len(chunk)<=_MAX_FRAME:
                        if len(image)<offset+len(chunk):image.extend(bytes(offset+len(chunk)-len(image)))
                        image[offset:offset+len(chunk)]=chunk
                        if image.startswith(b'\xff\xd8') and image.endswith(b'\xff\xd9'):
                            out['image_jpeg_complete_detectee']=True
        if out['image_jpeg_complete_detectee'] and live_preview is None:break
        if live_preview is not None and count % 16 == 0:
            _snapshot()
    _snapshot()
    if live_preview is not None:
        if live_preview.stopped and out['cause_fin_session_b85']=='non_determinee':
            out['cause_fin_session_b85']='arret_demande_par_utilisateur'
        out['apercu_direct_b29']=live_preview.summary()
    if local_capture is not None:
        out['capture_locale_b27']=local_capture.result()
    else:
        out['capture_locale_b27']={'capture_explicite_autorisee':False,'fichier_cree':False}
    out['codec_diagnostic']=codec_probe.result()
    out['codec_diagnostic']['analyse_structurelle_b23']=structure_probe.result()
    out['codec_diagnostic']['enveloppe_media_b24']=envelope_probe.result()
    out['codec_diagnostic']['continuite_fragments_b25']=continuity_probe.result()
    out['codec_diagnostic']['reassemblage_series_b26']=assembly_probe.result()
    if out['image_jpeg_complete_detectee']:out['etat']='premiere_image_jpeg_dechiffree_en_memoire'
    elif out['paquets_video_dechiffres']:out['etat']='donnees_video_dechiffrees_codec_a_identifier'
    elif out['conversation_video_detectee']:out['etat']='conversation_video_detectee_non_dechiffree'
    elif out['acquittements_controle_recus'] or out['conversation_controle_detectee']:
        out['etat']='canal_controle_actif_attente_media'
    else:out['etat']='commandes_envoyees_sans_canal_media'
    return out
