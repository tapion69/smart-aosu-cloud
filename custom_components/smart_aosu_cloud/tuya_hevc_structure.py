"""Strict, bounded HEVC/H.264 NAL framing diagnostic (no image data retained).

A 4-byte size followed by two arbitrary bytes is *not* evidence of H.265.
This class looks for size-prefix consistency at repeatable offsets across
multiple records and HEVC's two-byte NAL header layer/temporal constraints.
It reports counts/offsets only, never plaintext, keys, addresses or hashes.
"""
from __future__ import annotations
from collections import Counter
from statistics import median

_MAX_RECORDS = 256
_MAX_BYTES = 8 * 1024 * 1024
_MAX_RECORD = 128 * 1024
_MAX_NAL = 4 * 1024 * 1024
# No speculative full decoding; metadata only.
_PARAMETER_NALS = (32, 33, 34)


def _hevc_type(first: int, second: int, *, strict: bool) -> int | None:
    if first & 0x80:  # forbidden_zero_bit
        return None
    n = (first >> 1) & 0x3f
    if n > 40 or second & 7 == 0:
        return None
    if strict and ((first & 1) or (second & 0xf8) or (second & 7) != 1):
        return None
    return n


def _h264_type(first: int) -> int | None:
    n = first & 31
    return n if not first & 0x80 and n in (1, 5, 6, 7, 8, 9) else None


class MediaStructureProbe:
    """Collect only anonymized repeated-structure statistics."""

    def __init__(self) -> None:
        self.records = 0
        self.bytes = 0
        self.sizes: list[int] = []
        self.length_exact: Counter[tuple[str, int]] = Counter()
        self.length_near: Counter[tuple[str, int]] = Counter()
        self.strict_hevc_at_length: Counter[tuple[str, int, int]] = Counter()
        self.strict_hevc_at_fixed: Counter[tuple[int, int]] = Counter()
        self.h264_at_length: Counter[tuple[str, int, int]] = Counter()
        self.annex_hevc: Counter[int] = Counter()
        self.annex_h264: Counter[int] = Counter()
        self.nal_chains = 0

    def feed(self, record: bytes) -> None:
        if (not isinstance(record, bytes) or self.records >= _MAX_RECORDS
                or self.bytes >= _MAX_BYTES):
            return
        buf = record[:min(len(record), _MAX_RECORD, _MAX_BYTES-self.bytes)]
        self.records += 1
        self.bytes += len(buf)
        self.sizes.append(len(buf))
        if len(buf) < 8:
            return
        # A real unit header tends to recur at a single offset and to carry
        # layer_id=0 and temporal_id_plus1=1; false positives do not cluster.
        for off in range(min(128, len(buf)-2)):
            typ = _hevc_type(buf[off], buf[off+1], strict=True)
            if typ is not None:
                self.strict_hevc_at_fixed[(off, typ)] += 1
        # Check exact length, and length with <= 16 bytes trailing. These
        # are stronger than a generic "fits anywhere" length condition.
        # Track a single offset per record/mode to avoid inflated counts.
        for off in range(0, min(96, len(buf)-6)+1, 2):
            remaining = len(buf) - off - 4
            if remaining < 4:
                continue
            for endian in ('big', 'little'):
                n = int.from_bytes(buf[off:off+4], endian)
                if n < 4 or n > min(_MAX_NAL, remaining):
                    continue
                gap = remaining-n
                tag = (endian, off)
                if gap == 0:
                    self.length_exact[tag] += 1
                if gap <= 16:
                    self.length_near[tag] += 1
                    typ = _hevc_type(buf[off+4], buf[off+5], strict=True)
                    if typ is not None:
                        self.strict_hevc_at_length[(*tag, typ)] += 1
                    ht = _h264_type(buf[off+4])
                    if ht is not None:
                        self.h264_at_length[(*tag, ht)] += 1
                # Check a short, fully-contained AVCC/HVCC NAL chain. At
                # least two units must exactly exhaust the record.
                if endian == 'big' and gap >= 8:
                    next_off = off+4+n
                    if next_off+6 <= len(buf):
                        n2 = int.from_bytes(buf[next_off:next_off+4], 'big')
                        if n2 >= 2 and next_off+4+n2 == len(buf):
                            t1 = _hevc_type(buf[off+4],buf[off+5],strict=True)
                            t2 = _hevc_type(buf[next_off+4],buf[next_off+5],strict=True)
                            if t1 is not None and t2 is not None:
                                self.nal_chains += 1
        # Only properly bounded Annex-B start codes are counted.
        scan = 0
        hits = 0
        while hits < 64:
            p = buf.find(b'\x00\x00\x01', scan)
            if p < 0:
                break
            start = p+3
            if start+1 < len(buf):
                t = _hevc_type(buf[start],buf[start+1],strict=True)
                if t is not None:
                    self.annex_hevc[t] += 1
                h = _h264_type(buf[start])
                if h is not None:
                    self.annex_h264[h] += 1
            scan = start+1
            hits += 1

    def result(self) -> dict[str, object]:
        # The most common *exactly fitting* length field, not merely fitting
        # somewhere inside the record, is the primary structural candidate.
        ranked = self.length_exact.most_common(5)
        good = []
        for (endian, off), exact_count in ranked:
            types = Counter({t: n for (e, o, t), n in self.strict_hevc_at_length.items()
                             if e == endian and o == off})
            h264 = sum(n for (e, o, _), n in self.h264_at_length.items()
                       if e == endian and o == off)
            good.append({
                'endianness': 'BE' if endian == 'big' else 'LE',
                'decalage_octets': off,
                'correspondances_longueur_exacte': exact_count,
                'correspondances_longueur_avec_marge_16': self.length_near[(endian, off)],
                'entetes_hevc_stricts': sum(types.values()),
                'hevc_vps': types[32], 'hevc_sps': types[33], 'hevc_pps': types[34],
                'hevc_images_intra': types[19]+types[20],
                'h264_candidats': h264,
            })
        ranked_offsets = Counter()
        for (off, typ), hits in self.strict_hevc_at_fixed.items():
            ranked_offsets[off] += hits
        stable_headers = []
        for off, hits in ranked_offsets.most_common(6):
            if hits < 3:
                continue
            types = Counter({t: n for (o, t), n in self.strict_hevc_at_fixed.items() if o == off})
            stable_headers.append({
                'decalage_octets': off,
                'entetes_stricts': hits,
                'vps': types[32], 'sps': types[33], 'pps': types[34],
                'images_idr': types[19]+types[20],
            })
        hevc_params = sum(n for (e, o, t), n in self.strict_hevc_at_length.items()
                          if t in _PARAMETER_NALS)
        # High-confidence HEVC requires recurring *strict* headers at a
        # stable offset, with >= 2 distinct configuration NALs, not one-off
        # VPS/SPS labels from an arbitrary byte pair.
        confirmed = any(item['correspondances_longueur_exacte'] >= 8
                        and item['entetes_hevc_stricts'] >= 8
                        and item['hevc_vps'] >= 1 and item['hevc_sps'] >= 1
                        for item in good)
        if confirmed:
            verdict = 'encapsulation_hevc_structurellement_coherente'
        elif good and good[0]['correspondances_longueur_exacte'] >= 8:
            verdict = 'champ_longueur_recurrent_codec_non_confirme'
        elif self.annex_hevc[32] and self.annex_hevc[33]:
            verdict = 'hevc_annexb_parametres_a_confirmer'
        else:
            verdict = 'encapsulation_encore_indeterminee'
        return {
            'diagnostic': 'aosu_structure_video_b23',
            'enregistrements_analyses': self.records,
            'octets_inspectes': self.bytes,
            'tailles_paquets_min_mediane_max': (
                [min(self.sizes),int(median(self.sizes)),max(self.sizes)] if self.sizes else []),
            'prefixes_longueur_exacts': sum(self.length_exact.values()),
            'decalages_longueur_recurs': good,
            'decalages_entete_hevc_recurs': stable_headers,
            'unites_hevc_entete_strict_sur_prefixe': sum(self.strict_hevc_at_length.values()),
            'parametres_hevc_entete_strict_sur_prefixe': hevc_params,
            'annexb_hevc_entetes_stricts': sum(self.annex_hevc.values()),
            'annexb_h264_entetes': sum(self.annex_h264.values()),
            'chaines_nal_hevc_consecutives': self.nal_chains,
            'hevc_structure_confirmee': confirmed,
            'codec_identifie_definitivement': False,
            'verdict': verdict,
            'octets_bruts_retournes': False,
            'images_exportees': 0,
            'secrets_retournes': False,
        }
