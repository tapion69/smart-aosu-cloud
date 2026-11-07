"""Read-only aggregates for MQTT messages on the EXISTING C5L video connection.

This does not open a second MQTT connection and never publishes any device DP.
Only count and fixed-label metadata may be exposed. Do not retain raw messages.
"""
from __future__ import annotations

from collections import Counter
import threading
import time


class PassiveMqttPtzObserver:
    """In-memory, thread-safe traffic aggregates; no payload or topic retention."""

    def __init__(self, *, clock=time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._start = clock()
        self._counts = Counter()
        self._protocols = Counter()
        self._types = Counter()
        self._baseline = None
        self._connected = False
        self._ended = False
        self._last_disconnect = None

    def monitoring(self, active: bool):
        with self._lock:
            self._connected = bool(active)
            if not active:
                self._ended = True

    def packet(self, *, own_topic: bool, protocol=None, header_type=None, decode_error=False,
               ptz_control=False, ptz_stop=False):
        with self._lock:
            self._counts['messages_mqtt_recus'] += 1
            if not own_topic:
                self._counts['messages_hors_topic_session'] += 1
                return
            self._counts['messages_sur_topic_session'] += 1
            if decode_error:
                self._counts['messages_chiffres_non_decodes'] += 1
                return
            self._counts['messages_dechiffres'] += 1
            # Deliberate allowlists only: no arbitrary server-provided text.
            if type(protocol) is int and protocol in (22, 302):
                self._protocols[f'protocole_{protocol}'] += 1
            else:
                self._protocols['autre_ou_inconnu'] += 1
            if header_type in ('offer', 'answer', 'candidate', 'disconnect'):
                self._types[header_type] += 1
            else:
                self._types['autre_ou_absent'] += 1
            if ptz_control:
                self._counts['marqueurs_ptz_control'] += 1
            if ptz_stop:
                self._counts['marqueurs_ptz_stop'] += 1

    def remote_disconnect(self, reason, local_reason):
        """Keep only bounded numeric close codes; never store the actual message."""
        def safe(value):
            return value if type(value) is int and 0 <= value <= 30 else None
        with self._lock:
            self._last_disconnect = {'close_reason':safe(reason),
                                     'close_reason_local':safe(local_reason)}

    def puback(self):
        with self._lock:
            self._counts['accuses_reception_mqtt'] += 1

    def failure(self):
        with self._lock:
            self._counts['erreurs_lecture_mqtt'] += 1

    def _safe_counts(self):
        return {key: int(self._counts[key]) for key in (
            'messages_mqtt_recus', 'messages_hors_topic_session',
            'messages_sur_topic_session', 'messages_chiffres_non_decodes',
            'messages_dechiffres', 'marqueurs_ptz_control',
            'marqueurs_ptz_stop', 'accuses_reception_mqtt',
            'erreurs_lecture_mqtt')}

    def mark(self):
        with self._lock:
            self._baseline = self._safe_counts()
            return self._report()

    def snapshot(self):
        with self._lock:
            return self._report()

    def _report(self):
        counts = self._safe_counts()
        return {
            'diagnostic': 'aosu_mqtt_ptz_direct_b42',
            'direct_mqtt_observe': self._connected or self._ended,
            'observation_en_cours': self._connected,
            'secondes_depuis_demarrage': int(max(0, self._clock() - self._start)),
            **counts,
            'protocoles_reconnus': dict(self._protocols),
            'types_messages': dict(self._types),
            'dernier_disconnect': dict(self._last_disconnect) if self._last_disconnect else None,
            'marque_comparaison_presente': self._baseline is not None,
            'depuis_marque': {k: counts[k] - self._baseline[k] for k in counts}
                             if self._baseline is not None else {},
            'commandes_ptz_envoyees': 0,
            'commandes_arret_envoyees': 0,
            'offres_mqtt_supplementaires': 0,
            'connexions_mqtt_supplementaires': 0,
            'commandes_directionnelles_autorisees': False,
            'arret_moteur_physiquement_verifie': False,
            'messages_bruts_conserves': False,
            'donnees_video_conservees': False,
            'identifiants_retournes': False,
            'secrets_retournes': False,
        }
