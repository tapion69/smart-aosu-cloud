"""AOSU C5L: depacketize already-decrypted AES/KCP video records into HEVC Annex B.

Verified against a user-authorized AOSU C5L .aosudump (2026-10-30):
- 28 or 36-byte private AOSU transport header with exact little-endian size.
- 12-byte RTP-like header: V=2; first byte 0x80 on IDR, 0x90 on interframes.
  The 0x90 bit 4 resembles RTP X but is NOT followed by a standard RTP extension.
- HEVC RFC 7798 single NALs and FU (type 49) carried after 12-byte header.
- C5L sends VPS/SPS/PPS (32/33/34), FU of IDR type 19, and type 1 interframes.
No secret, network access, disk writes or FFmpeg dependency in this module.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import struct

CAPTURE_MAGIC = b'AOSUMEDIA27\x00'
MAX_RECORDS = 2000
MAX_DUMP_BYTES = 4 * 1024 * 1024
MAX_RECORD_BYTES = 128 * 1024
MAX_NAL_BYTES = 2 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
ANNEXB = b'\x00\x00\x00\x01'

@dataclass(frozen=True)
class RtpMedia:
    data: bytes
    seq: int
    timestamp: int
    payload: bytes
    nal_type: int
    private_header: int


def extract_rtp(record: bytes) -> RtpMedia | None:
    """Return the C5L video packet, not an RFC3550-compliant generic RTP packet."""
    if not isinstance(record, bytes) or len(record) > MAX_RECORD_BYTES:
        return None
    options = [h for h in (36, 28) if len(record) >= h + 14
               and int.from_bytes(record[h-4:h], 'little') == len(record)-h]
    if len(options) != 1:
        return None
    h = options[0]
    if record[:4] != b'\x03\x00\x01\x00':
        return None
    p = record[h:]
    if p[0] not in (0x80, 0x90) or (p[1] & 0x7f) != 95:
        return None
    if p[8:12] == b'\0\0\0\0':
        return None
    payload = p[12:]
    if len(payload) < 2:
        return None
    # HEVC NAL header: forbidden_zero_bit=0, nuh_temporal_id_plus1 nonzero.
    if payload[0] & 0x80 or (payload[1] & 0x07) == 0:
        return None
    return RtpMedia(p, int.from_bytes(p[2:4], 'big'),
                    int.from_bytes(p[4:8], 'big'), payload,
                    (payload[0] >> 1) & 0x3f, h)


class C5LHevcDepacketizer:
    """Reconstruct HEVC NALs using FU start/end and contiguous RTP sequence ids."""
    def __init__(self) -> None:
        self.nals: list[bytes] = []
        self.packets = 0
        self.discarded = 0
        self.sequence_discontinuities = 0
        self._last_seq: int | None = None
        self._fu: bytearray | None = None
        self._fu_timestamp: int | None = None
        self._fu_type: int | None = None
        self.types: dict[int, int] = {}
        self.fu_start: dict[int, int] = {}
        self.fu_end: dict[int, int] = {}
        self.fu_in_progress_type: int | None = None
        self.envelope_variants: dict[int, int] = {}
        self._size = 0

    def _add(self, nal: bytes) -> None:
        if len(nal) < 3 or len(nal) > MAX_NAL_BYTES or self._size + 4 + len(nal) > MAX_STREAM_BYTES:
            self.discarded += 1
            return
        typ = (nal[0] >> 1) & 0x3f
        self.types[typ] = self.types.get(typ, 0) + 1
        self.nals.append(nal)
        self._size += len(nal) + 4

    def feed(self, record: bytes) -> None:
        packet = extract_rtp(record)
        if packet is None:
            self.discarded += 1
            self._fu = None
            return
        self.packets += 1
        self.envelope_variants[packet.private_header] = self.envelope_variants.get(packet.private_header, 0) + 1
        gap = self._last_seq is not None and packet.seq != ((self._last_seq + 1) & 0xffff)
        if gap:
            self.sequence_discontinuities += 1
            self._fu = None
        self._last_seq = packet.seq
        nal_type = packet.nal_type
        payload = packet.payload
        if nal_type == 49:
            if len(payload) < 4:
                self.discarded += 1
                self._fu = None
                return
            fu_header = payload[2]
            start, end = bool(fu_header & 0x80), bool(fu_header & 0x40)
            original_type = fu_header & 0x3f
            if original_type >= 48 or (start and end):
                self.discarded += 1
                self._fu = None
                return
            if start:
                self.fu_start[original_type] = self.fu_start.get(original_type, 0) + 1
                self.fu_in_progress_type = original_type
                header = bytes([(payload[0] & 0x81) | (original_type << 1), payload[1]])
                self._fu = bytearray(header + payload[3:])
                self._fu_timestamp = packet.timestamp
                self._fu_type = original_type
            elif self._fu is not None and self._fu_timestamp == packet.timestamp and self._fu_type == original_type:
                self._fu.extend(payload[3:])
            else:
                self.discarded += 1
                self._fu = None
                return
            if self._fu is not None and len(self._fu) > MAX_NAL_BYTES:
                self._fu = None
                self.discarded += 1
                return
            if end and self._fu is not None:
                self.fu_end[original_type] = self.fu_end.get(original_type, 0) + 1
                self._add(bytes(self._fu))
                self._fu = None
                self.fu_in_progress_type = None
        elif nal_type == 48:  # HEVC aggregation packet, RFC7798
            self._fu = None
            cursor = 2
            while cursor + 2 <= len(payload):
                n = int.from_bytes(payload[cursor:cursor+2], 'big')
                cursor += 2
                if n < 3 or n > MAX_NAL_BYTES or cursor+n > len(payload):
                    self.discarded += 1
                    break
                self._add(payload[cursor:cursor+n])
                cursor += n
        elif nal_type < 48:
            self._fu = None
            self._add(payload)
        else:
            self.discarded += 1
            self._fu = None

    def stream(self) -> bytes:
        return b''.join(ANNEXB + n for n in self.nals)

    def report(self) -> dict:
        return {
            'paquets_video_rtp': self.packets,
            'enveloppes_par_taille': dict(sorted(self.envelope_variants.items())),
            'nal_reconstituees': len(self.nals),
            'hevc_vps': self.types.get(32, 0),
            'hevc_sps': self.types.get(33, 0),
            'hevc_pps': self.types.get(34, 0),
            'hevc_idr': self.types.get(19, 0) + self.types.get(20, 0),
            'hevc_images_inter': self.types.get(0, 0) + self.types.get(1, 0),
            'ruptures_sequence_rtp': self.sequence_discontinuities,
            'paquets_ignores': self.discarded,
            'octets_annexb_en_memoire': self._size,
            'hevc_structure_complete': all(self.types.get(x, 0)>0 for x in (32,33,34)) and any(self.types.get(x,0)>0 for x in (19,20)),
            'donnees_video_retournees': False,
        }


def parse_capture_bytes(data: bytes) -> C5LHevcDepacketizer:
    if len(data)>MAX_DUMP_BYTES or not data.startswith(CAPTURE_MAGIC):
        raise ValueError('invalid_or_oversized_capture')
    offset = len(CAPTURE_MAGIC)
    parser = C5LHevcDepacketizer()
    n_records = 0
    while offset < len(data):
        if offset+4>len(data):
            raise ValueError('truncated_record_length')
        n = struct.unpack_from('<I',data,offset)[0]
        offset+=4
        if n < 14 or n > MAX_RECORD_BYTES or offset+n>len(data):
            raise ValueError('invalid_record_bounds')
        parser.feed(data[offset:offset+n]);offset+=n
        n_records +=1
        if n_records>MAX_RECORDS:
            raise ValueError('too_many_records')
    return parser


def read_capture(path: Path) -> C5LHevcDepacketizer:
    if path.stat().st_size > MAX_DUMP_BYTES:
        raise ValueError('oversized_capture')
    return parse_capture_bytes(path.read_bytes())
