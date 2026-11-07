"""AOSU/Tuya media envelope investigation (b24), metadata only.

Infers two *hypothetical* little-endian trailing-payload size fields from
already-decrypted AES/KCP records. It never exposes bytes, network identifiers,
video frames, decoded frames, secrets, nor any raw values from the stream.

A payload-length field does not imply a codec or a frame boundary. We therefore
keep the codec conclusion explicitly unconfirmed until independently validated.
"""
from __future__ import annotations

from collections import Counter, deque
from statistics import median

_MAX_RECORDS = 320
_MAX_BYTES = 4 * 1024 * 1024
_MAX_RECORD_BYTES = 128 * 1024
_MAX_SCAN = 256 * 1024
_MAX_NAL_SIZE = 2 * 1024 * 1024
_HEADERS = (24, 32)
_FIELD_OFFSETS = tuple(range(0, 32, 4))


def _hevc_type_at(data: bytes, off: int) -> int | None:
    """Check HEVC NAL header, not merely the NAL-type bits."""
    if off < 0 or off + 2 > len(data):
        return None
    first, second = data[off], data[off + 1]
    if (first & 0x81) or second != 1:
        return None
    typ = (first >> 1) & 0x3f
    return typ if typ <= 40 else None


class FrameEnvelopeProbe:
    """Count size-field variants and continuity signals using only numeric stats."""

    def __init__(self) -> None:
        self.records = 0
        self.byte_count = 0
        self.matches: Counter[int] = Counter()
        self.ambiguous = 0
        self.unmatched = 0
        self.payload_lengths: dict[int, list[int]] = {24: [], 32: []}
        self.payload_starts: Counter[tuple[int, int]] = Counter()
        self.codec_header_offsets: Counter[tuple[int, int, int]] = Counter()
        self.start_codes_at_payload: Counter[int] = Counter()
        self.same_value: Counter[int] = Counter()
        self.increment_one: Counter[int] = Counter()
        self.increment_other: Counter[int] = Counter()
        self.counter_pairs: Counter[int] = Counter()
        self.variants: Counter[tuple[int, int]] = Counter()
        self._previous: dict[int, int] | None = None
        self._previous_variant: int | None = None
        self._payload_tail = b''
        self.cross_record_annexb = 0
        self._scan = bytearray()
        self._scan_nal_headers: Counter[int] = Counter()
        self._scan_nal_positions = set()
        self._stream_pos = 0
        self._streams_with_length = 0
        self._processed_scan_bytes = 0

    def feed(self, record: bytes) -> None:
        if not isinstance(record, bytes) or self.records >= _MAX_RECORDS or self.byte_count >= _MAX_BYTES:
            return
        buf = record[: min(len(record), _MAX_RECORD_BYTES, _MAX_BYTES - self.byte_count)]
        self.records += 1
        self.byte_count += len(buf)
        matches = [off for off in _HEADERS if len(buf) > off + 4 and
                   int.from_bytes(buf[off:off+4], 'little') == len(buf) - off - 4]
        if len(matches) != 1:
            if matches:
                self.ambiguous += 1
            else:
                self.unmatched += 1
            self._previous = None
            self._previous_variant = None
            self._payload_tail = b''
            return
        off = matches[0]
        self.matches[off] += 1
        self.payload_lengths[off].append(len(buf) - off - 4)
        if self._previous_variant is not None:
            self.variants[(self._previous_variant, off)] += 1
        self._previous_variant = off

        # The LE size field marks a candidate payload boundary, *not* a NAL.
        start = off + 4
        payload = buf[start:]
        for shift in (0, 4, 8, 12, 16, 20, 24):
            nal = _hevc_type_at(buf, start + shift)
            if nal is not None:
                self.codec_header_offsets[(off, shift, nal)] += 1
                if nal in (19, 20, 32, 33, 34):
                    self.payload_starts[(shift, nal)] += 1
        if payload.startswith((b'\x00\x00\x01', b'\x00\x00\x00\x01')):
            self.start_codes_at_payload[off] += 1

        # Consecutive field-level similarity: frame IDs, offsets or timestamps
        # may be inferred in a subsequent capture. Never return actual values.
        fields = {p: int.from_bytes(buf[p:p+4], 'little') for p in _FIELD_OFFSETS if p+4 <= off}
        if self._previous is not None:
            for p, value in fields.items():
                old = self._previous.get(p)
                if old is None:
                    continue
                self.counter_pairs[p] += 1
                diff = (value - old) & 0xFFFFFFFF
                if diff == 0:
                    self.same_value[p] += 1
                elif diff == 1:
                    self.increment_one[p] += 1
                elif 1 < diff < 100000:
                    self.increment_other[p] += 1
        self._previous = fields

        # Annex-B probe on candidate payload concatenation; deliberately only
        # hypothesis-generating, because records can be separate video frames.
        # Joining size-delimited chunks lets us detect start codes crossing the
        # record boundary without retaining any video in output.
        self._scan_annexb(payload)
        if self._payload_tail and payload:
            cross = self._payload_tail + payload[:4]
            for marker in (b'\x00\x00\x01', b'\x00\x00\x00\x01'):
                p = cross.find(marker)
                if p >= 0 and p < len(self._payload_tail) and p+len(marker) > len(self._payload_tail):
                    self.cross_record_annexb += 1
                    break
        self._payload_tail = payload[-3:]

    def _scan_annexb(self, payload: bytes) -> None:
        # Process payload plus last three bytes to preserve cross-boundary
        # start codes, preserving only a bounded short tail internally.
        buf = self._scan[-3:] + payload
        prefix_len = len(self._scan[-3:])
        offset = self._stream_pos - prefix_len
        pos = 0
        while True:
            p = buf.find(b'\x00\x00\x01', pos)
            if p < 0:
                break
            npos = p + 3
            if npos+1 < len(buf):
                typ = _hevc_type_at(buf, npos)
                absolute = offset + p
                if typ is not None and absolute not in self._scan_nal_positions:
                    self._scan_nal_headers[typ] += 1
                    self._scan_nal_positions.add(absolute)
            pos = npos + 1
        self._stream_pos += len(payload)
        self._processed_scan_bytes += len(payload)
        self._scan = bytearray(buf[-3:])

    def result(self) -> dict[str, object]:
        kind_stats = []
        for off in _HEADERS:
            lengths = self.payload_lengths[off]
            kind_stats.append({
                'champ_taille_le_octet': off,
                'entete_total_octets_hypothese': off + 4,
                'nombre_paquets': self.matches[off],
                'taille_charge_min_mediane_max': [min(lengths), int(median(lengths)), max(lengths)] if lengths else [],
                'start_code_annexb_en_debut_charge': self.start_codes_at_payload[off],
                'types_hevc_en_tete_aux_positions_suivantes': [
                    {'distance_apres_charge': shift,
                     'vps': self.codec_header_offsets[(off, shift, 32)],
                     'sps': self.codec_header_offsets[(off, shift, 33)],
                     'pps': self.codec_header_offsets[(off, shift, 34)],
                     'idr': self.codec_header_offsets[(off, shift, 19)] +
                            self.codec_header_offsets[(off, shift, 20)]}
                    for shift in (0, 4, 8, 12, 16, 20, 24)
                    if sum(self.codec_header_offsets[(off, shift, t)] for t in (32,33,34,19,20))
                ][:5],
            })
        # Highest-value fields for future reconstruction, never actual values.
        fields = []
        for off, count in sorted(self.counter_pairs.items(), key=lambda p: -p[1]):
            if count < 5:
                continue
            fields.append({
                'offset': off,
                'echantillons_consecutifs': count,
                'identiques': self.same_value[off],
                'increments_de_un': self.increment_one[off],
                'increments_positifs': self.increment_other[off],
            })
        hevc = self._scan_nal_headers
        enough = self.records >= 16 and self.unmatched <= max(1, self.records // 20)
        # No codec proof: even coherent VPS/SPS may occur by coincidence in
        # a scan over unrelated media. Neither output nor logs contain bytes.
        return {
            'diagnostic': 'aosu_enveloppe_video_b24',
            'paquets_analyses': self.records,
            'paquets_champ_longueur_coherent': sum(self.matches.values()),
            'paquets_champ_longueur_ambigu': self.ambiguous,
            'paquets_sans_champ_longueur': self.unmatched,
            'deux_variantes_entete_probables': enough and all(self.matches[off] >= 3 for off in _HEADERS),
            'variantes': kind_stats,
            'transitions_entre_variantes': [
                {'de': old+4, 'vers': new+4, 'nombre': n}
                for (old, new), n in sorted(self.variants.items())
            ],
            'champs_entete_debut_de_flux': fields[:8],
            'signatures_annexb_dans_charges_concatenees': sum(hevc.values()),
            'vps_apres_extraction': hevc[32],
            'sps_apres_extraction': hevc[33],
            'pps_apres_extraction': hevc[34],
            'idr_apres_extraction': hevc[19] + hevc[20],
            'annexb_aux_limites_de_paquets': self.cross_record_annexb,
            'unites_video_reconstituees': 0,
            'codec_video_confirme': False,
            'verdict': 'deux_entetes_longueur_identifies_reassemblage_a_determiner' if enough else
                       'structure_a_confirmer_sur_plus_de_paquets',
            'octets_video_retournes': False,
            'image_exportee': False,
            'secrets_retournes': False,
        }
