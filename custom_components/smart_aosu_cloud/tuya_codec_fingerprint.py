"""Privacy-preserving inspection of decrypted Tuya KCP video record *structure*.

The analyzer never stores frames, never returns payload bytes, headers, keys,
addresses, hashes, or image information. No proof of H.264/H.265 is inferred
from generic activity alone. Experimental, bounded and non-persistent.
"""
from __future__ import annotations
from collections import Counter

_MAX_RECORDS = 256
_MAX_SCAN_BYTES = 128 * 1024
_MAX_BYTES_TOTAL = 8 * 1024 * 1024
_MAX_HITS_PER_RECORD = 32
_H264_TYPES = {1, 5, 6, 7, 8, 9}
_HEVC_TYPES = {0, 1, 19, 20, 21, 32, 33, 34, 35, 39, 40}


def _h264_type(b: int) -> int | None:
    n = b & 0x1f
    return n if (b & 0x80) == 0 and n in _H264_TYPES else None


def _hevc_type(first: int, second: int) -> int | None:
    n = (first >> 1) & 0x3f
    return n if not (first & 0x80) and (second & 7) and n in _HEVC_TYPES else None


class CodecFingerprint:
    """Incrementally tally codec signatures, not private frames or payloads."""

    def __init__(self) -> None:
        self.records = 0
        self.scanned = 0
        self.annex_h264: Counter[int] = Counter()
        self.annex_hevc: Counter[int] = Counter()
        self.length_h264: Counter[int] = Counter()
        self.length_hevc: Counter[int] = Counter()
        self.jpeg_soi = 0
        self.jpeg_eoi = 0
        self.tuya_mjpeg = 0
        self.tuya_marker_types: Counter[int] = Counter()
        self.possible_rtp = 0
        self.length_prefixed_packets = 0

    def feed(self, plaintext: bytes) -> None:
        if (self.records >= _MAX_RECORDS or self.scanned >= _MAX_BYTES_TOTAL or
                not isinstance(plaintext, bytes)):
            return
        buf = plaintext[:min(len(plaintext), _MAX_SCAN_BYTES, _MAX_BYTES_TOTAL - self.scanned)]
        self.records += 1
        self.scanned += len(buf)
        self.jpeg_soi += buf.count(b'\xff\xd8')
        self.jpeg_eoi += buf.count(b'\xff\xd9')
        self.tuya_mjpeg += buf.count(b'\x00\xff\x50\x3c')
        # Candidate variants of Tuya media marker: byte 00 ff <media-type> 3c.
        index = 0
        for _ in range(_MAX_HITS_PER_RECORD):
            pos = buf.find(b'\x00\xff', index)
            if pos < 0: break
            if pos + 3 < len(buf) and buf[pos + 3] == 0x3c:
                self.tuya_marker_types[buf[pos + 2]] += 1
            index = pos + 2
        # Annex B NAL start-codes, including those inside proprietary frame headers.
        start = 0
        count = 0
        while count < _MAX_HITS_PER_RECORD:
            at = buf.find(b'\x00\x00\x01', start)
            if at < 0: break
            nal_pos = at + 3
            if at > 0 and buf[at - 1] == 0:  # 4-byte 00 00 00 01
                pass
            if nal_pos < len(buf):
                h = _h264_type(buf[nal_pos])
                if h is not None: self.annex_h264[h] += 1
                if nal_pos + 1 < len(buf):
                    h = _hevc_type(buf[nal_pos], buf[nal_pos + 1])
                    if h is not None: self.annex_hevc[h] += 1
            start = nal_pos + 1
            count += 1
        # AVCC/HVCC may have a size prefix after a fixed device-specific header.
        # Validate declared lengths against available decrypted record, not just byte type.
        for off in range(0, min(96, len(buf) - 5) + 1, 4):
            n = int.from_bytes(buf[off:off + 4], 'big')
            if not 2 <= n <= len(buf) - (off + 4): continue
            self.length_prefixed_packets += 1
            first = buf[off + 4]
            h = _h264_type(first)
            if h is not None: self.length_h264[h] += 1
            if off + 5 < len(buf):
                h = _hevc_type(first, buf[off + 5])
                if h is not None: self.length_hevc[h] += 1
        # Optional RTP header at the start or following a small proprietary header.
        for off in (0, 4, 8, 12, 16, 20, 24):
            if len(buf) >= off + 12 and buf[off] >> 6 == 2 and (buf[off] & 0x0f) < 6:
                pt = buf[off + 1] & 0x7f
                if pt in (96, 97, 98, 99, 100, 101, 102):
                    self.possible_rtp += 1
                    break

    def result(self) -> dict[str, object]:
        h264_sps = self.annex_h264[7] + self.length_h264[7]
        h264_pps = self.annex_h264[8] + self.length_h264[8]
        hevc_vps = self.annex_hevc[32] + self.length_hevc[32]
        hevc_sps = self.annex_hevc[33] + self.length_hevc[33]
        hevc_pps = self.annex_hevc[34] + self.length_hevc[34]
        h264_nal = sum(self.annex_h264.values()) + sum(self.length_h264.values())
        hevc_nal = sum(self.annex_hevc.values()) + sum(self.length_hevc.values())
        if hevc_vps and hevc_sps:
            fmt, conf = 'h265_parametres_detectes', 'indicative_non_confirmee'
        elif h264_sps and h264_pps:
            fmt, conf = 'h264_parametres_detectes', 'indicative_non_confirmee'
        elif hevc_nal >= 4 and (hevc_sps or hevc_pps):
            fmt, conf = 'h265_probable', 'moyenne'
        elif h264_nal >= 4 and (h264_sps or h264_pps or self.annex_h264[5] > 0):
            fmt, conf = 'h264_probable', 'moyenne'
        elif self.tuya_mjpeg and self.jpeg_soi:
            fmt, conf = 'mjpeg_probable', 'moyenne'
        elif self.jpeg_soi and self.jpeg_eoi:
            fmt, conf = 'jpeg_present_hors_parseur', 'moyenne'
        elif self.tuya_marker_types:
            fmt, conf = 'trames_tuya_proprietaires_a_analyser', 'faible'
        elif h264_nal or hevc_nal or self.possible_rtp:
            fmt, conf = 'indices_codec_non_concluants', 'faible'
        else:
            fmt, conf = 'format_multiplexage_inconnu', 'indeterminee'
        return {
            'diagnostic': 'aosu_codec_fingerprint_b22',
            'enregistrements_video_analyses': self.records,
            'octets_dechiffres_inspectes': self.scanned,
            'jpeg_debuts_detectes': self.jpeg_soi,
            'jpeg_fins_detectees': self.jpeg_eoi,
            'marqueurs_mjpeg_reference_detectes': self.tuya_mjpeg,
            'types_marqueurs_tuya_detectes': [
                {'type_numerique': t, 'occurrences': n}
                for t, n in self.tuya_marker_types.most_common(8)
            ],
            'signatures_h264_annexb': sum(self.annex_h264.values()),
            'signatures_h265_annexb': sum(self.annex_hevc.values()),
            'signatures_h264_longueur': sum(self.length_h264.values()),
            'signatures_h265_longueur': sum(self.length_hevc.values()),
            'h264_sps_detecte': bool(h264_sps),
            'h264_pps_detecte': bool(h264_pps),
            'h264_idr_detecte': bool(self.annex_h264[5] + self.length_h264[5]),
            'h265_vps_detecte': bool(hevc_vps),
            'h265_sps_detecte': bool(hevc_sps),
            'h265_pps_detecte': bool(hevc_pps),
            'h265_idr_detecte': bool(self.annex_hevc[19] + self.annex_hevc[20] +
                                    self.length_hevc[19] + self.length_hevc[20]),
            'indices_rtp': self.possible_rtp,
            'candidats_taille_avcc_hvcc': self.length_prefixed_packets,
            'format_probable': fmt,
            'confiance_detection': conf,
            'images_exportees': 0,
            'donnees_brutes_retournees': False,
            'secrets_retournes': False,
        }
