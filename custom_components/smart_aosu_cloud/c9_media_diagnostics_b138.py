"""B138: bounded, aggregate-only diagnostics of authenticated H1L/C9 KCP media.

Consumes only already authenticated and decrypted in-memory frames. Performs
no networking, disk writes, FFmpeg spawning, media sharing, or raw ID logging.
"""
from __future__ import annotations
from .tuya_kcp_receive_b87 import KcpReceiveB87
from .tuya_hevc_rtp import C5LHevcDepacketizer, extract_rtp

_MAX_SAMPLES = 2048
_MAX_RECORD = 128 * 1024

class C9MediaProbeB138:
    def __init__(self):
        self._rx = {1: KcpReceiveB87(), 2: KcpReceiveB87()}
        self._hevc = {1: C5LHevcDepacketizer(), 2: C5LHevcDepacketizer()}
        self._observed = {1: 0, 2: 0}
        self._samples = {1: 0, 2: 0}
        self._rtp_matches = {1: 0, 2: 0}
        self._annexb_matches = {1: 0, 2: 0}
        self._direct_rtp_matches = {1: 0, 2: 0}
        self._record_too_large = 0

    def accept(self, conv: int, sn: int, frg: int, plain: bytes) -> int:
        """Accept a fully authenticated decrypted KCP PUSH; return contiguous UNA.

        A packet is not necessarily a unique frame. KCP sequence numbers are
        tracked independently for conv 1 and 2; repeated packets are ignored.
        """
        if conv not in self._rx or not isinstance(plain, bytes):
            raise ValueError('canal_media_invalide')
        self._observed[conv] += 1
        completed = self._rx[conv].accept(sn, frg, plain)
        for record in completed:
            if self._samples[conv] >= _MAX_SAMPLES:
                continue
            if len(record) > _MAX_RECORD:
                self._record_too_large += 1
                continue
            self._samples[conv] += 1
            if record.startswith(b'\x00\x00\x00\x01') or record.startswith(b'\x00\x00\x01'):
                self._annexb_matches[conv] += 1
            # C5L's format: 28/36-byte AOSU wrapper followed by RTP-like HEVC.
            # This is a signature check only; unsupported C9 layouts stay unknown.
            if extract_rtp(record) is not None:
                self._rtp_matches[conv] += 1
                self._hevc[conv].feed(record)
            elif len(record)>=14 and record[0] in (0x80,0x90) and (record[1]&0x7f)==95:
                self._direct_rtp_matches[conv] += 1
        return self._rx[conv].next_sequence

    def una(self, conv: int) -> int:
        return self._rx[conv].next_sequence if conv in self._rx else 0

    def summary(self) -> dict:
        rows=[]
        for conv in (1,2):
            rx=self._rx[conv].summary()
            hevc=self._hevc[conv].report()
            rows.append({
                'canal':conv,
                'paquets_authentifies_analyzes':self._observed[conv],
                'sequences_contigues_uniques':rx['sequence_continue'],
                'messages_reconstitues':rx['messages_reconstitues'],
                'retransmissions':rx['doublons'],
                'hors_ordre':rx['hors_ordre'],
                'hors_fenetre':rx['hors_fenetre'],
                'segments_en_attente':rx['segments_en_attente'],
                'fragments_max_message':rx['max_fragments_par_message'],
                'messages_echantillonnes':self._samples[conv],
                'enveloppes_rtp_c5l_reconnues':self._rtp_matches[conv],
                'signatures_annexb_directes':self._annexb_matches[conv],
                'signatures_rtp_sans_enveloppe':self._direct_rtp_matches[conv],
                'hevc_vps':hevc['hevc_vps'],
                'hevc_sps':hevc['hevc_sps'],
                'hevc_pps':hevc['hevc_pps'],
                'hevc_idr':hevc['hevc_idr'],
                'hevc_images_inter':hevc['hevc_images_inter'],
                'hevc_structure_complete':hevc['hevc_structure_complete'],
            })
        rtp=sum(x['enveloppes_rtp_c5l_reconnues'] for x in rows)
        direct=sum(x['signatures_rtp_sans_enveloppe'] for x in rows)
        annexb=sum(x['signatures_annexb_directes'] for x in rows)
        return {'diagnostic_media_b138':rows,
            'kcp_media_retransmissions':sum(x['retransmissions'] for x in rows),
            'kcp_media_messages_uniques':sum(x['messages_reconstitues'] for x in rows),
            'kcp_media_enveloppes_rtp_c5l':rtp,
            'kcp_media_hevc_structure_complete':any(x['hevc_structure_complete'] for x in rows),
            'format_media_probable':('enveloppe_rtp_c5l' if rtp else
                'annexb_direct' if annexb else 'rtp_sans_enveloppe' if direct else 'encore_inconnu'),
            'enregistrements_media_trop_grands':self._record_too_large,
            'donnees_video_retournees':False,
            'octets_media_retournes':False}
