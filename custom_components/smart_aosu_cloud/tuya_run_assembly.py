"""AOSU b26: bounded run-level media reconstruction, private by design.

Data comes from authenticated, already AES-CBC-decrypted KCP channel 1.
A valid length envelope alone never means an image or codec is confirmed.
Assemble homogeneous groups in memory, probe a few standard NAL framings,
and return aggregate counts only, never media bytes/keys/device IDs.
"""
from __future__ import annotations

from collections import Counter
from statistics import median

_MAX_RECORDS = 320
_MAX_RECORD_BYTES = 128 * 1024
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_RUNS = 12
_MAX_NAL_LENGTH = 2 * 1024 * 1024
_HEADERS = {24: 28, 32: 36}


def _hevc_type(data: bytes, pos: int) -> int | None:
    if pos < 0 or pos + 2 > len(data):
        return None
    a, b = data[pos], data[pos + 1]
    # forbidden_zero_bit=0, layer_id=0, temporal_id_plus1 nonzero
    if a & 0x81 or b & 0xF8 or not (b & 7):
        return None
    n = (a >> 1) & 0x3f
    return n if n <= 40 else None


def _h264_type(data: bytes, pos: int) -> int | None:
    if pos < 0 or pos >= len(data) or data[pos] & 0x80:
        return None
    n = data[pos] & 31
    return n if n in (1, 5, 6, 7, 8, 9) else None


def _annexb(data: bytes) -> dict[str, int]:
    hevc, h264, starts = Counter(), Counter(), 0
    pos = 0
    while starts < 512:
        i = data.find(b'\x00\x00\x01', pos)
        if i < 0:
            break
        starts += 1
        at = i + 3
        h = _hevc_type(data, at)
        if h is not None:
            hevc[h] += 1
        a = _h264_type(data, at)
        if a is not None:
            h264[a] += 1
        pos = at + 1
    return {'codes_depart': starts, 'hevc_parametres': sum(hevc[t] for t in (32, 33, 34)),
            'hevc_images': sum(hevc[t] for t in range(0, 22)),
            'h264_parametres': h264[7] + h264[8],
            'h264_images': h264[1] + h264[5]}


def _probe_length_chains(data: bytes) -> dict[str, object]:
    """Count *consecutive* complete length-prefixed NAL units, not random fits.

    Seek a few plausible initial offsets. Accept no isolated single-NAL hit
    as confirmed media; a chain needs at least three complete units.
    """
    best = {'codec': 'aucun', 'unites': 0, 'offset_debut': 0, 'taille_prefixe': 0,
            'boutisme': 'aucun', 'octets_valides': 0, 'parametres': 0}
    for width in (2, 4):
        for endian in ('big', 'little'):
            for start in range(0, min(96, max(0, len(data) - 4))):
                for codec in ('h265', 'h264'):
                    pos = start
                    units, param = 0, 0
                    while pos + width + 2 <= len(data) and units < 512:
                        length = int.from_bytes(data[pos:pos + width], endian)
                        if length < (2 if codec == 'h265' else 1) or length > _MAX_NAL_LENGTH:
                            break
                        nxt = pos + width + length
                        if nxt > len(data):
                            break
                        typ = (_hevc_type(data, pos + width) if codec == 'h265'
                               else _h264_type(data, pos + width))
                        if typ is None:
                            break
                        if codec == 'h265' and typ in (32, 33, 34):
                            param += 1
                        if codec == 'h264' and typ in (7, 8):
                            param += 1
                        units += 1
                        pos = nxt
                    if units > best['unites'] or (units == best['unites'] and param > best['parametres']):
                        best = {'codec': codec, 'unites': units, 'offset_debut': start,
                                'taille_prefixe': width, 'boutisme': 'BE' if endian == 'big' else 'LE',
                                'octets_valides': pos - start, 'parametres': param}
    # Isolated NAL headers are too weak to declare a recognized codec.
    if best['unites'] < 3:
        return {'chaines_nal_consecutives': best['unites'], 'codec_chaine': 'non_confirme',
                'parametres_chaines': best['parametres']}
    return {'chaines_nal_consecutives': best['unites'], 'codec_chaine': best['codec'],
            'parametres_chaines': best['parametres'], 'taille_prefixe': best['taille_prefixe'],
            'boutisme': best['boutisme'], 'offset_initial': best['offset_debut']}


class RunAssemblyProbe:
    def __init__(self) -> None:
        self.records = 0
        self.total_bytes = 0
        self.unclassified = 0
        self._current_kind: int | None = None
        self._current_records = 0
        self._current_payloads: list[bytes] = []
        self._current_specials: Counter[tuple[int, int]] = Counter()
        self._current_special_pos: dict[int, list[int]] = {32: [], 33: [], 34: [], 19: [], 20: []}
        self._current_field8: list[int] = []
        self._runs: list[dict[str, object]] = []
        self._overflow = False

    def feed(self, record: bytes) -> None:
        if not isinstance(record, bytes) or self.records >= _MAX_RECORDS or self.total_bytes >= _MAX_TOTAL_BYTES:
            self._overflow = True
            return
        if len(record) > _MAX_RECORD_BYTES or len(record) + self.total_bytes > _MAX_TOTAL_BYTES:
            self._overflow = True
            return
        self.records += 1
        self.total_bytes += len(record)
        matches = [end for off, end in _HEADERS.items()
                   if len(record) > off + 4 and
                   int.from_bytes(record[off:off + 4], 'little') == len(record) - off - 4]
        if len(matches) != 1:
            self.unclassified += 1
            self._flush_run()
            return
        kind = matches[0]
        if self._current_kind != kind:
            self._flush_run()
            self._current_kind = kind
        self._current_records += 1
        payload = record[kind:]
        self._current_payloads.append(payload)
        if len(record) >= 12:
            self._current_field8.append(int.from_bytes(record[8:12], 'little'))
        # Look for strict NAL parameter signatures in the first 32 bytes of
        # each payload, preserving only type and position within the run.
        for offset in range(0, min(32, max(0, len(payload) - 1))):
            typ = _hevc_type(payload, offset)
            if typ in (32, 33, 34, 19, 20):
                self._current_specials[(offset, typ)] += 1
                self._current_special_pos[typ].append(self._current_records - 1)

    def _flush_run(self) -> None:
        if self._current_kind is None:
            return
        if len(self._runs) >= _MAX_RUNS:
            self._overflow = True
        else:
            joined = b''.join(self._current_payloads)
            annex = _annexb(joined)
            chain = _probe_length_chains(joined)
            fields = self._current_field8
            # No raw field values, only deltas and constant/value-change counts.
            diffs = [((fields[i] - fields[i-1]) & 0xffffffff)
                     for i in range(1, len(fields))]
            small = [d for d in diffs if 0 < d <= 100000]
            meta = {
                'entete_octets': self._current_kind,
                'paquets': self._current_records,
                'octets_charge_agreges': len(joined),
                'champ_8_identique': sum(d == 0 for d in diffs),
                'champ_8_avance': len(small),
                'champ_8_pas_median': int(median(small)) if small else 0,
                'annexb': annex,
                'chaines_nal': chain,
                'marqueurs_hevc_debut_charge': [
                    {'type': typ, 'decalage': off, 'occurrences': n}
                    for (off, typ), n in self._current_specials.most_common(8)
                ],
                'positions_parametres_dans_serie': {
                    name: self._current_special_pos[typ][:8]
                    for name, typ in (('vps', 32), ('sps', 33), ('pps', 34))
                    if self._current_special_pos[typ]
                },
            }
            self._runs.append(meta)
        self._current_kind = None
        self._current_records = 0
        self._current_payloads = []
        self._current_specials = Counter()
        self._current_special_pos = {32: [], 33: [], 34: [], 19: [], 20: []}
        self._current_field8 = []

    def result(self) -> dict[str, object]:
        self._flush_run()
        confirmed = [run for run in self._runs if run['chaines_nal'].get('codec_chaine') in ('h265', 'h264')
                     and run['chaines_nal'].get('chaines_nal_consecutives', 0) >= 3]
        return {
            'diagnostic': 'aosu_reassemblage_series_b26',
            'paquets_analyses': self.records,
            'paquets_sans_classement': self.unclassified,
            'series_reconstituees_en_memoire': len(self._runs),
            'series': self._runs,
            'chaines_nal_structurellement_coherentes': len(confirmed),
            'codecs_candidats_par_chaine': [r['chaines_nal']['codec_chaine'] for r in confirmed],
            'codec_decode_confirme': False,
            'frames_video_decodees': 0,
            'avertissement': 'Le reassemblage d une serie de fragments ne prouve pas qu il s agit d une image',
            'capture_tronquee': self._overflow,
            'octets_video_retournes': False,
            'images_exportees': 0,
            'secrets_retournes': False,
        }
