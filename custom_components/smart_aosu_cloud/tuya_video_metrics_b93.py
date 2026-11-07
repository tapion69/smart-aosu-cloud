"""B93: bounded, read-only performance counters for experimental C5L video.

Only timestamps / aggregate counters, never frames, secrets, media bytes or URLs.
"""
from __future__ import annotations
from collections import deque
import time
from typing import Callable

_PHASES = frozenset(('lecture_demandee','ffmpeg_demarre','mqtt_tls_connecte',
                     'offre_mqtt_envoyee','reponse_sdp_recue','relais_tcp_pret',
                     'premier_rtp','premiere_idr','premiere_ecriture_ffmpeg','premier_jpeg'))

class VideoMetricsB93:
    def __init__(self, clock: Callable[[],float] | None = None):
        self._clock = clock or time.monotonic
        self._start = self._clock()
        self._phases: dict[str,float] = {'lecture_demandee':self._start}
        self._last_jpeg:float|None = None
        self._frames=0
        self._gaps_05=0
        self._gaps_2=0
        self._max_gap=0.0
        self._last_gap=None
        self._recent:deque[float] = deque(maxlen=128)

    def mark(self, phase:str) -> None:
        if phase in _PHASES and phase not in self._phases:
            self._phases[phase]=self._clock()

    def jpeg(self) -> None:
        now=self._clock()
        self.mark('premier_jpeg')
        if self._last_jpeg is not None:
            gap=max(0.0,now-self._last_jpeg)
            self._last_gap=gap
            self._max_gap=max(self._max_gap,gap)
            if gap>.5:self._gaps_05+=1
            if gap>=2:self._gaps_2+=1
        self._last_jpeg=now
        self._frames+=1
        self._recent.append(now)

    def summary(self) -> dict:
        now=self._clock()
        # Compute a rolling cadence from *real* JPEG completions; no extrapolated
        # source fps or invented packet loss. Three seconds of silence => 0 fps.
        recent=[t for t in self._recent if t>=now-10]
        if len(recent)>=2:
            fps=round((len(recent)-1)/max(.001,now-recent[0]),2)
        else:fps=0.0
        milestones={k:round(max(0.0,t-self._start),2) for k,t in self._phases.items()}
        stages={}
        for k,previous in (('tls_apres_lecture_s','lecture_demandee'),
                           ('offre_apres_tls_s','mqtt_tls_connecte'),
                           ('sdp_apres_offre_s','offre_mqtt_envoyee'),
                           ('relais_apres_sdp_s','reponse_sdp_recue'),
                           ('rtp_apres_relais_s','relais_tcp_pret'),
                           ('idr_apres_rtp_s','premier_rtp'),
                           ('jpeg_apres_idr_s','premiere_idr')):
            current={'tls_apres_lecture_s':'mqtt_tls_connecte',
                     'offre_apres_tls_s':'offre_mqtt_envoyee',
                     'sdp_apres_offre_s':'reponse_sdp_recue',
                     'relais_apres_sdp_s':'relais_tcp_pret',
                     'rtp_apres_relais_s':'premier_rtp',
                     'idr_apres_rtp_s':'premiere_idr',
                     'jpeg_apres_idr_s':'premier_jpeg'}[k]
            a=self._phases.get(previous);b=self._phases.get(current)
            stages[k]=round(max(0.,b-a),2) if a is not None and b is not None else None
        if self._last_jpeg is not None:
            phase=('gel_image_pendant_session' if now-self._last_jpeg>=2
                   else 'images_produites')
        elif 'premier_rtp' not in self._phases:phase='attente_premier_rtp'
        elif 'premiere_idr' not in self._phases:phase='attente_premiere_idr'
        else:phase='attente_premier_jpeg'
        return {'diagnostic':'aosu_performance_b93',
                'duree_observation_s':round(max(0,now-self._start),1),
                'jalons_s_depuis_lecture':milestones,
                'etapes_demarrage_s':stages,
                'phase_observee':phase,
                'images_jpeg_total':self._frames,
                'fps_jpeg_10_derniere_secondes':fps,
                'pauses_jpeg_plus_500ms':self._gaps_05,
                'pauses_jpeg_2s_ou_plus':self._gaps_2,
                'plus_longue_pause_jpeg_s':round(self._max_gap,2),
                'derniere_pause_jpeg_s':round(self._last_gap,2) if self._last_gap is not None else None,
                'secondes_depuis_dernier_jpeg':round(now-self._last_jpeg,2) if self._last_jpeg is not None else None,
                'horloge_monotone_sans_date':True,
                'video_enregistree':False,
                'secrets_retournes':False}
