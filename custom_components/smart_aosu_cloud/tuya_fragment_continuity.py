"""AOSU/Tuya b25: bounded, privacy-preserving fragment continuity analysis.

Operates on already-decrypted channel-1 records. Distinguishes the 28-byte and
36-byte envelopes, then follows candidate counters *within the same variant*.
No source bytes, identifiers, frame data, keys, or fingerprints leave this probe.
A counter transition is not itself proof of a frame boundary or video codec.
"""
from __future__ import annotations

from collections import Counter
from statistics import median

_MAX_RECORDS = 320
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_RECORD_BYTES = 128 * 1024
_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28)
_VARIANTS = {24: 28, 32: 36}


def _median_min_max(vals: list[int]) -> list[int]:
    return [min(vals), int(median(vals)), max(vals)] if vals else []


class FragmentContinuityProbe:
    """Summarize contiguous variant runs and 32-bit header-field continuity."""

    def __init__(self) -> None:
        self.count = 0
        self.total_bytes = 0
        self.variants = Counter()
        self.unclassified = 0
        self.runs: list[dict[str, int]] = []
        self._current_run: dict[str, int] | None = None
        self._last_fields: dict[int, dict[int, int]] = {}
        self._field_stats: dict[tuple[int, int], Counter[str]] = {}
        self._candidate_groups: dict[tuple[int, int], list[int]] = {}
        self._group_length: dict[tuple[int, int], int] = {}
        self._first4: dict[int, Counter[bytes]] = {28: Counter(), 36: Counter()}
        self._lengths: dict[int, list[int]] = {28: [], 36: []}
        self._starts: Counter[int] = Counter()
        self._prefix16: dict[int, Counter[bytes]] = {28: Counter(), 36: Counter()}

    def _finish_run(self) -> None:
        if self._current_run is not None:
            self.runs.append(dict(self._current_run))
            self._current_run = None
            for key,length in self._group_length.items():
                if length:
                    self._candidate_groups.setdefault(key, []).append(length)
            self._group_length.clear()
            self._last_fields.clear()

    def feed(self, record: bytes) -> None:
        if not isinstance(record, bytes) or self.count >= _MAX_RECORDS or self.total_bytes >= _MAX_TOTAL_BYTES:
            return
        buf = record[:min(len(record), _MAX_RECORD_BYTES, _MAX_TOTAL_BYTES-self.total_bytes)]
        self.count += 1
        self.total_bytes += len(buf)
        matches = [o for o in _VARIANTS if len(buf)>o+4 and int.from_bytes(buf[o:o+4], 'little') == len(buf)-o-4]
        if len(matches) != 1:
            self.unclassified += 1
            self._finish_run()
            self._last_fields.clear()
            return
        off = matches[0]
        variant = _VARIANTS[off]
        self.variants[variant] += 1
        self._lengths[variant].append(len(buf))
        payload = buf[variant:]
        if len(payload) >= 4:
            self._first4[variant][payload[:4]] += 1
        self._prefix16[variant][payload[:min(16,len(payload))]] += 1
        if self._current_run and self._current_run['entete_octets'] == variant:
            self._current_run['paquets'] += 1
        else:
            self._finish_run()
            self._current_run = {'entete_octets':variant, 'depart_index':self.count-1,'paquets':1}
            self._starts[variant] += 1

        # No cross-variant comparisons, and no 4-byte field can overlap the
        # candidate length field itself.
        fields = {i: int.from_bytes(buf[i:i+4], 'little') for i in _OFFSETS if i+4 <= off}
        prev = self._last_fields.get(variant)
        if prev:
            for pos, value in fields.items():
                if pos not in prev:
                    continue
                change = (value - prev[pos]) & 0xffffffff
                stats = self._field_stats.setdefault((variant,pos), Counter())
                stats['comparaisons'] += 1
                if change == 0: stats['identique'] += 1
                elif change == 1: stats['plus_un'] += 1
                elif change < 100000: stats['avance'] += 1
                elif change > 0xffffffff-100000: stats['retour'] += 1
                else: stats['rupture'] += 1
        self._last_fields[variant] = fields

        # For every candidate 32-bit field, count runs of identical values.
        # This is a *hypothesis* for frame grouping, not yet a reconstruction.
        for pos, value in fields.items():
            key = (variant,pos)
            if prev is not None and prev.get(pos) == value:
                self._group_length[key] = self._group_length.get(key,0)+1
            else:
                old = self._group_length.get(key,0)
                if old:
                    self._candidate_groups.setdefault(key, []).append(old)
                self._group_length[key] = 1

    def result(self) -> dict[str, object]:
        self._finish_run()
        groups: dict[tuple[int,int],list[int]] = {k:list(v) for k,v in self._candidate_groups.items()}
        for key,length in self._group_length.items():
            if length: groups.setdefault(key,[]).append(length)
        fields = []
        for (variant,pos),counts in sorted(self._field_stats.items()):
            lengths = groups.get((variant,pos), [])
            if counts['comparaisons'] < 3: continue
            fields.append({
                'entete_octets':variant,
                'offset':pos,
                'comparaisons_meme_type':counts['comparaisons'],
                'identiques':counts['identique'],
                'increments_de_un':counts['plus_un'],
                'autres_avances':counts['avance'],
                'retours':counts['retour'],
                'ruptures':counts['rupture'],
                'groupes_valeur_constante':len(lengths),
                'paquets_par_groupe_min_mediane_max':_median_min_max(lengths),
            })
        # Prefer changing counters with repeated run lengths; constant fields
        # cannot be frame IDs just because the whole recording had one value.
        ranked = sorted(
            (f for f in fields if f['autres_avances']+f['increments_de_un']>0),
            key=lambda f: (f['autres_avances']+f['increments_de_un'],f['groupes_valeur_constante']),
            reverse=True,
        )
        distinct_prefix = []
        for variant in (28,36):
            prefixes = self._first4[variant]
            prefix16 = self._prefix16[variant]
            distinct_prefix.append({
                'entete_octets':variant,
                'nombre_paquets':self.variants[variant],
                'tailles_totales_min_mediane_max':_median_min_max(self._lengths[variant]),
                'prefixes_charge_4_octets_distincts':len(prefixes),
                'prefixe_charge_4_octets_le_plus_recurrent':prefixes.most_common(1)[0][1] if prefixes else 0,
                'prefixes_charge_16_octets_distincts':len(prefix16),
                'prefixe_charge_16_octets_le_plus_recurrent':prefix16.most_common(1)[0][1] if prefix16 else 0,
            })
        runs = self.runs[:12]
        return {
            'diagnostic':'aosu_continuite_fragments_b25',
            'paquets_analyses':self.count,
            'paquets_reconnus':sum(self.variants.values()),
            'paquets_non_classes':self.unclassified,
            'series_consecutives_par_variante':runs,
            'nombre_series_total':len(self.runs),
            'statistiques_charge_par_variante':distinct_prefix,
            'champs_comparaison_par_variante':fields,
            'meilleurs_compteurs_candidats':[
                {'entete_octets':f['entete_octets'], 'offset':f['offset'],
                 'avances':f['increments_de_un']+f['autres_avances'],
                 'groupes':f['groupes_valeur_constante'],
                 'taille_mediane_groupe':f['paquets_par_groupe_min_mediane_max'][1]}
                for f in ranked[:5]
            ],
            'trames_video_reconstituees':0,
            'codec_identifie':False,
            'verdict':'candidats_compteurs_a_valider_par_reassemblage' if ranked else 'aucun_compteur_variable_confirme',
            'donnees_brutes_retournees':False,
            'images_exportees':0,
            'secrets_retournes':False,
        }
