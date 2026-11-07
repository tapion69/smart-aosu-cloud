"""B94: correlate ingress, FFmpeg write and JPEG timing without recording media.

Only bounded counters and monotonic timing; no video, addresses, keys or timestamps.
Does not attempt recovery, reconnect or extra camera commands.
"""
from __future__ import annotations
import time
from typing import Callable

_STAGES = ("rtp", "ffmpeg_ecriture", "jpeg")

class StreamTimingB94:
    def __init__(self, *, clock: Callable[[], float] | None = None) -> None:
        self._clock = clock or time.monotonic
        self._started = self._clock()
        self._last = {stage: None for stage in _STAGES}
        self._total = {stage: 0 for stage in _STAGES}
        self._pauses_2s = {stage: 0 for stage in _STAGES}
        self._pauses_05s = {stage: 0 for stage in _STAGES}
        self._max_gap = {stage: 0.0 for stage in _STAGES}
        self._last_gap = {stage: None for stage in _STAGES}

    def note(self, stage: str) -> None:
        if stage not in self._last:
            return
        now = self._clock()
        previous = self._last[stage]
        if previous is not None:
            gap = max(0.0, now-previous)
            self._last_gap[stage] = gap
            self._max_gap[stage] = max(self._max_gap[stage], gap)
            if gap > 0.5:
                self._pauses_05s[stage] += 1
            if gap >= 2.0:
                self._pauses_2s[stage] += 1
        self._last[stage] = now
        self._total[stage] += 1

    def summary(self) -> dict:
        now = self._clock()
        ages = {stage: (max(0.0, now-at) if at is not None else None)
                for stage,at in self._last.items()}
        jpeg = ages['jpeg']
        rtp = ages['rtp']
        writer = ages['ffmpeg_ecriture']
        if self._total['jpeg'] == 0:
            classification = 'aucune_image_initiale'
        elif jpeg is None or jpeg < 2:
            classification = 'pas_de_gel_actuel'
        elif rtp is None or rtp >= 2:
            classification = 'interruption_apport_rtp'
        elif writer is None or writer >= 2:
            classification = 'entree_ffmpeg_non_alimentee'
        else:
            classification = 'sortie_jpeg_en_attente_malgre_flux'
        return {
            'diagnostic': 'aosu_fluidite_b94',
            'classification_gel_courant': classification,
            'phases': {
                stage: {
                    'evenements_total': self._total[stage],
                    'pauses_plus_500ms': self._pauses_05s[stage],
                    'pauses_2s_ou_plus': self._pauses_2s[stage],
                    'plus_longue_pause_entre_evenements_s': round(self._max_gap[stage],2),
                    'derniere_pause_entre_evenements_s': (
                        round(self._last_gap[stage],2) if self._last_gap[stage] is not None else None),
                    'secondes_depuis_dernier_evenement': round(ages[stage],2) if ages[stage] is not None else None,
                } for stage in _STAGES
            },
            'duree_observation_s': round(max(0.,now-self._started),1),
            'horloge_monotone_sans_date': True,
            'aucune_action_reseau': True,
            'video_enregistree': False,
            'secrets_retournes': False,
        }
