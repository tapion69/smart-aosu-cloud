"""Experimental manually-enabled in-memory P2P preview for C5L.

No video on disk, no automatic reconnect, no PTZ. Pause retains the active P2P link. Pipeline uses Home Assistant
FFmpeg binary and verified C5L HEVC/RTP depacketizer; release resources on stop.
"""
from __future__ import annotations

import queue
import shutil
import subprocess
import threading
import time
from typing import Any

from .tuya_hevc_rtp import C5LHevcDepacketizer, ANNEXB
from .tuya_video_metrics_b93 import VideoMetricsB93
from .tuya_stream_timing_b94 import StreamTimingB94
from .ptz_live_observer_b41 import PassivePtzChannelObserver
from .ptz_mqtt_observer_b42 import PassiveMqttPtzObserver

_MAX_IMAGE = 3 * 1024 * 1024
# Better display cadence than B85 (2 fps), without inventing missing source frames.
_DISPLAY_FPS = 6
# Stop, network EOF, or a 45-second idle timeout releases the session.
LIVE_SECONDS = None  # No artificial playback duration; user Stop or a stalled link ends the stream.

class LivePreview:
    """A manually-activated preview with no fixed duration and JPEG held in RAM."""

    def __init__(self, *, ffmpeg_path: str | None = None, on_frame=None):
        self._lock = threading.Lock()
        self._metrics_lock = threading.Lock()
        self._b93_metrics = VideoMetricsB93()
        self._b94_timing = StreamTimingB94()
        self._on_frame = on_frame
        self._stop = threading.Event()
        self._pause = threading.Event()
        self._jpeg: bytes | None = None
        self._jpeg_at = 0.0
        self._frames = 0
        self._rtp = 0
        self._decode_error = False
        self._status = 'pret'
        self._decoder = C5LHevcDepacketizer()
        self.ptz_control_observer = PassivePtzChannelObserver()
        self.ptz_mqtt_observer = PassiveMqttPtzObserver()
        self._queue: queue.Queue[bytes | None] = queue.Queue(maxsize=256)
        self._ffmpeg_path = ffmpeg_path if ffmpeg_path is not None else shutil.which('ffmpeg')
        self._process: subprocess.Popen | None = None
        self._threads: list[threading.Thread] = []
        self._opened = False
        self._fed_param: dict[int, bytes] = {}
        self._have_idr = False
        self._last_rtp_at = 0.0
        self._b87_control_sent = 0
        self._b87_decrypted_media = 0
        self._b87_kcp = {}
        self._b90_tcp = {}
        self._b92_keepalive = {}
        self._b96_control = {}
        # B88: keep only aggregate decoder data, never stderr lines or HEVC bytes.
        self._ffmpeg_written_bytes = 0
        self._ffmpeg_written_units = 0
        self._ffmpeg_write_error = False
        self._ffmpeg_error_classes: dict[str, int] = {}
        self._ffmpeg_error_lines = 0
        self._ffmpeg_exit_observed_before_stop: int | None = None
        self._first_jpeg_delay = None
        self._ffmpeg_started_at = 0.0
        self._ffmpeg_last_write_at = 0.0
        self._ffmpeg_last_output_at = 0.0
        self._jpeg_after_stop = 0
        self._stop_graceful = None
        self._stop_return_code = None

    def fluidite_b94(self) -> dict:
        """Only aggregate rates and intervals, read-only during live session."""
        with self._metrics_lock:
            return self._b94_timing.summary()

    def mark_phase_b93(self, phase: str) -> None:
        """Read-only timestamp, safe from the MQTT and decoder threads."""
        with self._metrics_lock:
            self._b93_metrics.mark(phase)

    def performance_b93(self) -> dict:
        with self._metrics_lock:
            result = self._b93_metrics.summary()
        result['session_terminee'] = self._stop.is_set()
        if self._stop.is_set():
            result['phase_observee'] = 'session_arretee'
        return result

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def start(self) -> bool:
        if self._opened or self._stop.is_set() or not self._ffmpeg_path:
            with self._lock:
                self._status = 'ffmpeg_indisponible' if not self._ffmpeg_path else 'demarrage_invalide'
            return False
        # Forced elementary HEVC: the default 5-second stream analysis can
        # buffer a short camera session without producing ANY JPEG while stdin
        # remains open. The bounded probe has been tested with synthetic HEVC.
        # Deliberately avoid -fflags +nobuffer: it dropped HEVC references.
        cmd = [self._ffmpeg_path, '-hide_banner', '-nostdin', '-loglevel', 'error',
               '-threads', '2', '-probesize', '32768', '-analyzeduration', '0',
               '-f', 'hevc', '-i', 'pipe:0', '-an', '-sn',
               '-vf', f'fps={_DISPLAY_FPS},scale=960:-2', '-q:v', '5', '-f', 'image2pipe',
               '-vcodec', 'mjpeg', 'pipe:1']
        try:
            self._process = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, bufsize=0)
        except OSError:
            with self._lock:
                self._status = 'echec_lancement_ffmpeg'
            return False
        self._opened = True
        self._ffmpeg_started_at = time.monotonic()
        self.mark_phase_b93('ffmpeg_demarre')
        with self._lock:
            self._status = 'attente_video'
        self._threads = [threading.Thread(target=self._writer, name='aosu-video-input', daemon=True),
                         threading.Thread(target=self._reader, name='aosu-jpeg-output', daemon=True),
                         threading.Thread(target=self._stderr_reader, name='aosu-ffmpeg-diagnostics', daemon=True)]
        for thread in self._threads: thread.start()
        return True

    def _writer(self) -> None:
        proc = self._process
        if proc is None or proc.stdin is None: return
        try:
            while True:
                try:
                    item = self._queue.get(timeout=.3)
                except queue.Empty:
                    if self._stop.is_set():
                        break
                    continue
                if item is None:
                    break
                # Popen has unbuffered binary pipes: each write reaches FFmpeg.
                n = proc.stdin.write(item)
                if n is None: n = 0
                self._ffmpeg_written_bytes += n
                self._ffmpeg_written_units += 1
                if n:
                    self._ffmpeg_last_write_at = time.monotonic()
                    self.mark_phase_b93('premiere_ecriture_ffmpeg')
                    with self._metrics_lock:
                        self._b94_timing.note('ffmpeg_ecriture')
        except (BrokenPipeError, OSError, ValueError):
            if not self._stop.is_set():
                self._decode_error = True
                self._ffmpeg_write_error = True
        finally:
            try:proc.stdin.close()
            except (OSError, ValueError):pass

    def _reader(self) -> None:
        proc = self._process
        if proc is None or proc.stdout is None:return
        buffer=bytearray()
        try:
            # Keep draining until EOF: FFmpeg may release delayed frames only
            # after stdin is closed. No post-STOP frames are sent to the UI.
            while True:
                piece=proc.stdout.read(8192)
                if not piece:break
                self._ffmpeg_last_output_at = time.monotonic()
                buffer.extend(piece)
                if len(buffer) > 2 * _MAX_IMAGE:
                    buffer.clear()
                    self._decode_error=True
                    continue
                while True:
                    start=buffer.find(b'\xff\xd8')
                    if start<0:
                        buffer.clear();break
                    if start:del buffer[:start]
                    end=buffer.find(b'\xff\xd9',2)
                    if end<0:break
                    jpeg=bytes(buffer[:end+2]);del buffer[:end+2]
                    if 1024 <= len(jpeg) <= _MAX_IMAGE:
                        if self._stop.is_set():
                            self._jpeg_after_stop += 1
                            continue
                        # Pause is a display-only hold: P2P and FFmpeg still run.
                        if self._pause.is_set():
                            continue
                        with self._lock:
                            self._jpeg=jpeg
                            self._jpeg_at=time.monotonic()
                            self._frames+=1
                            if self._frames == 1:
                                self._first_jpeg_delay = round(time.monotonic()-self._ffmpeg_started_at,2)
                            self._status='images_reçues'
                        with self._metrics_lock:
                            self._b93_metrics.jpeg()
                            self._b94_timing.note('jpeg')
                        if self._on_frame is not None:
                            try:self._on_frame()
                            except (RuntimeError, ValueError):pass
        except (OSError, ValueError):
            self._decode_error=True

    def _stderr_reader(self) -> None:
        """Drain FFmpeg stderr; only safe, fixed error classes are retained."""
        proc = self._process
        if proc is None or proc.stderr is None: return
        try:
            for line in proc.stderr:
                if not line: break
                self._ffmpeg_error_lines += 1
                # No raw strings, private paths, image bytes, or excerpts kept.
                line_lower = line[:2048].lower()
                if b'could not find ref' in line_lower or b'reference' in line_lower:
                    label = 'reference_hevc_absente'
                elif any(t in line_lower for t in (b'invalid data', b'error parsing', b'error while decoding')):
                    label = 'hevc_non_decodable'
                elif any(t in line_lower for t in (b'sps', b'pps', b'vps')):
                    label = 'parametres_hevc'
                elif b'buffer' in line_lower or b'queue' in line_lower:
                    label = 'tampon'
                else:
                    label = 'autre'
                self._ffmpeg_error_classes[label] = self._ffmpeg_error_classes.get(label, 0) + 1
        except (OSError, ValueError):
            pass

    def feed(self, decrypted_record: bytes) -> None:
        if self._stop.is_set() or not self._opened:return
        before=len(self._decoder.nals)
        old_rtp = self._decoder.packets
        self._decoder.feed(decrypted_record)
        self._rtp=self._decoder.packets
        if self._rtp > old_rtp:
            self._last_rtp_at=time.monotonic()
            self.mark_phase_b93('premier_rtp')
            with self._metrics_lock:
                self._b94_timing.note('rtp')
        added=self._decoder.nals[before:]
        # Avoid retaining full video in RAM while preserving sequence/FU state.
        del self._decoder.nals[:]
        self._decoder._size=0
        for nal in added:
            typ=(nal[0]>>1)&0x3f
            if typ in (32,33,34):
                self._fed_param[typ]=nal
                continue
            if typ in (19,20) and len(self._fed_param)==3:
                self.mark_phase_b93('premiere_idr')
            if typ in (19,20) and len(self._fed_param)==3 and not self._have_idr:
                self._have_idr=True
                for t in (32,33,34):
                    try:self._queue.put_nowait(ANNEXB+self._fed_param[t])
                    except queue.Full:self._decode_error=True;return
            if not self._have_idr:continue
            try:self._queue.put_nowait(ANNEXB+nal)
            except queue.Full:
                self._decode_error=True
                self._have_idr=False
                # Restart at next IDR; data gap could otherwise corrupt the next frames.

    def pause(self) -> bool:
        if not self._opened or self.stopped:
            return False
        self._pause.set()
        with self._lock:
            self._status = 'affichage_en_pause'
        return True

    def resume(self) -> bool:
        if not self._opened or self.stopped:
            return False
        self._pause.clear()
        with self._lock:
            self._status = 'reprise_attente_image'
        return True

    @property
    def paused(self) -> bool:
        return self._pause.is_set()

    def image(self, *, max_age: float=180.0) -> bytes | None:
        with self._lock:
            if self._jpeg and (self.paused or time.monotonic()-self._jpeg_at<max_age):
                return self._jpeg
            return None

    def summary(self) -> dict[str, Any]:
        """Expose only transport/codec counters, never payloads, keys or video."""
        types = dict(self._decoder.types)
        params = {32: types.get(32, 0), 33: types.get(33, 0), 34: types.get(34, 0)}
        idr = types.get(19, 0) + types.get(20, 0)
        valid_rtp = self._decoder.packets
        if valid_rtp == 0:
            diagnosis = 'aucun_paquet_rtp_valide'
        elif not types:
            diagnosis = 'fragments_rtp_sans_nal_complete'
        elif not all(params.values()):
            diagnosis = 'parametres_hevc_incomplets_vps_sps_pps'
        elif not idr:
            diagnosis = ('idr_fragmentee_incomplete' if any(self._decoder.fu_start.get(t,0) > self._decoder.fu_end.get(t,0) for t in (19,20))
                         else 'attente_image_cle_idr')
        elif not self._have_idr:
            diagnosis = 'attente_reinitialisation_decodeur_apres_perte'
        elif self._frames == 0:
            diagnosis = 'image_cle_presente_aucune_jpeg_ffmpeg'
        else:
            diagnosis = 'images_jpeg_produites'
        proc = self._process
        ffmpeg_exit = proc.poll() if proc is not None else None
        decoder_running = bool(proc is not None and ffmpeg_exit is None)
        if ffmpeg_exit is not None and self._opened and not self._stop.is_set():
            self._ffmpeg_exit_observed_before_stop = ffmpeg_exit
        now = time.monotonic()
        with self._lock:
            return {
                'etat': self._status,
                'affichage_en_pause': self.paused,
                'paquets_rtp': self._rtp,
                'images_jpeg_decodees': self._frames,
                'derniere_image_disponible': bool(self._jpeg and (self.paused or now-self._jpeg_at < 180)),
                'erreur_decodeur': self._decode_error,
                'flux_enregistre': False,
                'secret_retourne': False,
                'qualite_affichage_b86': {'limite_images_par_seconde': _DISPLAY_FPS, 'largeur_px': 960},
                'kcp_reception_b87': self._b87_kcp,
                'transport_tcp_b90': self._b90_tcp,
                'relais_keepalive_b92': self._b92_keepalive,
                'fiabilite_controle_b96': self._b96_control,
                'performance_b93': self.performance_b93(),
                'fluidite_b94': self.fluidite_b94(),
                'pipeline_ffmpeg_b88': {
                    'analyse_initiale_reduite': True,
                    'octets_annexb_ecrits': self._ffmpeg_written_bytes,
                    'unites_nal_ecrites': self._ffmpeg_written_units,
                    'erreur_ecriture': self._ffmpeg_write_error,
                    'lignes_erreur_ffmpeg': self._ffmpeg_error_lines,
                    'categories_erreurs': dict(self._ffmpeg_error_classes),
                    'code_sortie_avant_arret': self._ffmpeg_exit_observed_before_stop,
                    'delai_premiere_jpeg_s': self._first_jpeg_delay,
                    'processus_actif': decoder_running,
                    'secondes_depuis_derniere_ecriture': (round(now-self._ffmpeg_last_write_at,1) if self._ffmpeg_last_write_at else None),
                    'secondes_depuis_derniere_sortie': (round(now-self._ffmpeg_last_output_at,1) if self._ffmpeg_last_output_at else None),
                    'jpeg_produits_apres_stop': self._jpeg_after_stop,
                    'arret_propre_ffmpeg': self._stop_graceful,
                    'code_sortie_apres_stop': self._stop_return_code,
                    'donnees_privees_retournees': False,
                },
                'reconstruction_hevc_b86': {
                    'paquets_rtp_valides': valid_rtp,
                    'paquets_rejetes': self._decoder.discarded,
                    'ruptures_sequence_rtp': self._decoder.sequence_discontinuities,
                    'vps_recus': params[32], 'sps_recus': params[33], 'pps_recus': params[34],
                    'images_cles_idr_recues': idr,
                    'fragments_idr_debuts': sum(self._decoder.fu_start.get(t,0) for t in (19,20)),
                    'fragments_idr_fins': sum(self._decoder.fu_end.get(t,0) for t in (19,20)),
                    'fragment_type_en_cours': self._decoder.fu_in_progress_type,
                    'types_nal_complets': {str(k):v for k,v in sorted(types.items())},
                    'images_inter_recues': types.get(0, 0) + types.get(1, 0),
                    'image_cle_transmise_ffmpeg': self._have_idr,
                    'derniere_activite_rtp_secondes': (round(now-self._last_rtp_at, 1) if self._last_rtp_at else None),
                    'derniere_image_jpeg_secondes': (round(now-self._jpeg_at, 1) if self._jpeg_at else None),
                    'ffmpeg_actif': decoder_running,
                    'file_attente_ffmpeg': self._queue.qsize(),
                    'diagnostic': diagnosis,
                    'aucune_video_brute_retournee': True,
                },
            }

    def stop(self) -> None:
        """Bounded graceful decoder shutdown, then terminate as a fallback.

        The user-visible stream is stopped immediately. Late decoder frames are
        counted but never displayed, published, or written to disk.
        """
        self._stop.set()
        self._pause.clear()
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        writer = next((t for t in self._threads if t.name == 'aosu-video-input'), None)
        if writer is not None and writer is not threading.current_thread():
            writer.join(timeout=1.5)
        proc = self._process
        if proc is not None:
            if writer is not None and writer.is_alive():
                # A stalled stdin writer must not keep the decoder open forever.
                try:proc.terminate()
                except OSError:pass
            try:
                proc.wait(timeout=2)
                self._stop_graceful = (writer is None or not writer.is_alive())
            except subprocess.TimeoutExpired:
                self._stop_graceful = False
                try:proc.terminate();proc.wait(timeout=1)
                except (OSError,subprocess.TimeoutExpired):
                    try:proc.kill();proc.wait(timeout=1)
                    except (OSError,subprocess.TimeoutExpired):pass
            self._stop_return_code = proc.poll()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=1)
        with self._lock:
            self._status='arrete'
            # The last pre-STOP JPEG remains temporarily in RAM as before.


def readiness_live(client, *, diagnostic: bool = False) -> dict[str, Any]:
    """Read-only concurrency and conservative diagnostic limit status.

    Old 30min/5min/1h cooldowns remain for manual diagnostic probes only.
    The explicitly user-started stream uses a fresh RTC+MQTT negotiation,
    bounded by active-operation locks and LiveController retry backoff.
    """
    import math
    from . import tuya_rtc_inventory as inv
    from . import tuya_mqtt_offer as mqtt
    from .tuya_uid_gateway import TuyaAuthSession

    now = time.monotonic()
    key = id(client)
    session = getattr(client, '_tuya_oem_session', None)
    active = (isinstance(session, TuyaAuthSession)
              and 0 <= now - session.acquired_at < 1200)
    cache = getattr(client, '_tuya_oem_inventory_cache', None)
    can_use_cache = (active and isinstance(cache, dict)
                     and 0 <= now - cache.get('created', 0) < 600
                     and cache.get('session_uid') == session.uid
                     and isinstance(cache.get('devices'), dict))
    old_waits = {
        'inventaire': math.ceil(max(0, inv._LAST_RUN.get(key, 0) - now)) if not can_use_cache else 0,
        'authentification': math.ceil(max(0, inv._LAST_LOGIN.get(key, 0) - now)) if not active else 0,
        'rtc': math.ceil(max(0, inv._LAST_RTC.get(key, 0) - now)),
        'offre_mqtt': math.ceil(max(0, mqtt._OFFER_NEXT_ALLOWED.get(key, 0) - now)),
    }
    concurrent = inv._LOCK.locked() or mqtt._OFFER_LOCK.locked()
    waits = old_waits if diagnostic else {k: 0 for k in old_waits}
    delay = max(waits.values(), default=0)
    return {
        'etat': 'operation_en_cours' if concurrent else ('limitation_active' if delay else 'pret_cote_limites_locales'),
        'pret_cote_limites_locales': not concurrent and delay == 0,
        'delais_restants_secondes': waits,
        'delai_maximum_secondes': delay,
        'inventaire_cache_utilisable': bool(can_use_cache),
        'limites_diagnostics_non_applicables_au_direct': not diagnostic,
        'aucun_appel_reseau': True,
        'aucune_commande_camera': True,
        'note': ('Aucune attente artificielle pour Lecture; protection contre tentatives concurrentes et echecs reels.'
                 if not diagnostic else 'Delais conservateurs des audits manuels seulement.'),
    }


class LiveRetryGate:
    """Short bounded retries only after actual failures; no cloud access.

    No timer, no background request, no bypass of remote refusal. The retry
    gate never blocks Stop, Pause, or Play on an existing session.
    """
    def __init__(self, clock=None):
        self._clock = clock or time.monotonic
        self.failures = 0
        self.retry_at = 0.0
        self.last_reason = 'aucune'

    def remaining(self) -> int:
        import math
        return math.ceil(max(0.0, self.retry_at - self._clock()))

    def record(self, *, succeeded: bool, canceled: bool = False, reason: str = 'inconnu') -> None:
        if succeeded:
            self.failures = 0
            self.retry_at = 0.0
            self.last_reason = 'aucune'
        elif canceled:
            return
        else:
            self.failures = min(self.failures + 1, 6)
            # B95: A transient no-video/decoder failure is not an explicit
            # remote rejection. Bound its backoff at 30 s, without allowing a
            # tight request loop; retain conservative waits for remote refusal
            # and auth failures. No automatic retry is scheduled here.
            backoff = (300 if reason == 'auth_refusee' else
                       min(120, 10 * (2 ** (self.failures - 1)))
                       if reason == 'session_refusee' else
                       min(30, 10 * (2 ** (self.failures - 1))))
            self.retry_at = self._clock() + backoff
            # Only internally-authored status tokens, never an exception body.
            self.last_reason = reason if reason in (
                'aucune_video', 'aucune_image_jpeg', 'session_refusee', 'erreur_reseau',
                'erreur_decodeur', 'erreur_interne', 'auth_refusee') else 'erreur_session'


class LiveController:
    """Keep at most one user-triggered, time-limited preview for one config entry."""

    def __init__(self, hass, client):
        self.hass=hass
        self.client=client
        self.preview:LivePreview|None=None
        self._task=None
        self._status='inactif'
        self._last_result: dict[str, Any] = {}
        self._retry = LiveRetryGate()
        # Only safe status tokens and integers: no account/camera identifiers.
        self._start_refusal: dict[str, Any] | None = None
        self._start_refusal_count = 0
        self._starts_accepted = 0
        self._listeners=[]

    @property
    def running(self)->bool:
        return self._task is not None and not self._task.done()

    def subscribe(self, callback):
        self._listeners.append(callback)
        def remove():
            if callback in self._listeners:self._listeners.remove(callback)
        return remove

    def _notify(self):
        for callback in list(self._listeners):
            try:callback()
            except (RuntimeError,ValueError):pass

    def image(self)->bytes|None:
        return self.preview.image() if self.preview else None

    def _frame_ready(self):
        # Decoder calls this from a worker thread. Entity updates MUST run on
        # the Home Assistant event loop, not on the ffmpeg reader thread.
        try:
            self.hass.loop.call_soon_threadsafe(self._publish_frame)
        except (AttributeError, RuntimeError):
            pass

    def _publish_frame(self):
        if self._status in ('negociation_p2p', 'reprise_en_cours'):
            self._status = 'images_recues'
        self._notify()

    def status(self)->dict[str,Any]:
        value={'etat':self._status,'direct_actif':self.running,
               'session_max_secondes':LIVE_SECONDS,'donnees_enregistrees':False,
               'affichage_en_pause':bool(self.preview and self.preview.paused)}
        if self.preview:
            value['decodage']=self.preview.summary()
            value['canal_controle_ptz_b41']=self.preview.ptz_control_observer.snapshot()
            value['mqtt_ptz_b42']=self.preview.ptz_mqtt_observer.snapshot()
        if self._last_result:
            value['dernier_resultat']=self._last_result
        # The read-only readiness block is useful after an attempted preview;
        # never send an authenticated request from a status service.
        if self.client is not None:
            value['limites_demarrage'] = readiness_live(self.client)
        wait = self._retry.remaining()
        if wait and 'limites_demarrage' in value:
            value['limites_demarrage']['pret_cote_limites_locales'] = False
            value['limites_demarrage']['etat'] = 'reessai_apres_echec_reel'
            value['limites_demarrage']['delai_maximum_secondes'] = wait
        value['retry_apres_echec'] = {
            'secondes_restantes': self._retry.remaining(),
            'echecs_consecutifs': self._retry.failures,
            'cause': self._retry.last_reason,
            'aucune_tentative_automatique': True,
        }
        value['demarrage_b95'] = {
            'dernier_refus': dict(self._start_refusal) if self._start_refusal else None,
            'refus_depuis_dernier_demarrage': self._start_refusal_count,
            'demarrages_acceptes': self._starts_accepted,
            'arret_precedent_en_cours': bool(self.running and self.preview and self.preview.stopped),
            'nouvelle_tentative_automatique': False,
            'donnees_privees_retournees': False,
        }
        return value

    def _deny_start(self, etat: str, **fields: Any) -> dict[str, Any]:
        self._start_refusal_count += 1
        # Values supplied only by fixed local code paths; never copy errors.
        result = {'etat': etat, **fields}
        self._start_refusal = dict(result)
        self._start_refusal['refus_depuis_dernier_demarrage'] = self._start_refusal_count
        return result

    def start(self, *, password_confirmed:bool, candidate_confirmed:bool)->dict[str,Any]:
        if not password_confirmed or not candidate_confirmed:
            return self._deny_start('autorisations_expresse_requises')
        if self.running:
            # The previous worker may still be releasing the relay even after
            # STOP was clicked. Never claim that session is a fresh playable
            # direct or submit a second P2P offer in parallel.
            if self.preview is not None and self.preview.stopped:
                return self._deny_start('arret_precedent_en_cours',
                                        nouvelle_offre_mqtt=False)
            if self.preview is not None and self.preview.paused:
                if self.preview.resume():
                    self._status = 'reprise_en_cours'
                    self._notify()
                    return {'etat':'reprise_direct_existant', 'nouvelle_offre_mqtt':False,
                            'session_max_secondes':LIVE_SECONDS}
            return {'etat':'direct_deja_en_cours', 'nouvelle_offre_mqtt':False}
        # Only remote/decoder failures trigger a short bounded backoff.
        # Legacy development cooldowns do not apply to explicit user Play.
        retry_seconds = self._retry.remaining()
        if retry_seconds:
            return self._deny_start('demarrage_non_lance_reessai',
                                    secondes_restantes=retry_seconds,
                                    cause=self._retry.last_reason)
        readiness = readiness_live(self.client)
        if not readiness['pret_cote_limites_locales']:
            self._status = 'limitation_locale'
            self._last_result = {'etat_negociation': 'non_lance_limitation_locale',
                                 'commandes_video': 0, 'paquets_dechiffres': 0}
            self._notify()
            return self._deny_start('demarrage_non_lance_limitation',
                                    cause='operation_locale_en_cours',
                                    secondes_restantes=0,
                                    nouvelle_offre_mqtt=False)
        self.preview=LivePreview(on_frame=self._frame_ready)
        if not self.preview._ffmpeg_path:
            return self._deny_start('ffmpeg_absent')
        self._start_refusal = None
        self._start_refusal_count = 0
        self._starts_accepted += 1
        self._last_result={}
        self._status='demarrage'
        import asyncio
        self._task=asyncio.create_task(self._run(),name='aosu_c5l_live_preview')
        self._notify()
        return {'etat':'demarrage_demande','session_max_secondes':LIVE_SECONDS,
                'demarrage_automatique':False,'PTZ':False}

    async def _run(self):
        from functools import partial
        from .tuya_rtc_inventory import run_tuya_oem_inventory
        preview=self.preview
        try:
            if preview is None or not await self.hass.async_add_executor_job(preview.start):
                self._status='echec_decodeur'
                self._retry.record(succeeded=False, reason='erreur_decodeur')
                return
            self._status='negociation_p2p'
            # Reuse the verified P2P protocol with explicit active consent; the
            # interactive-only path bypasses development cooldowns, not remote refusals.
            report=await self.hass.async_add_executor_job(partial(
                run_tuya_oem_inventory,self.client,
                confirmation_envoi_mot_de_passe=True,tester_rtc=True,
                autoriser_candidat_unique=False,
                autoriser_correspondance_nom_unique=True,
                tester_mqtt=True,tester_offre_mqtt=True,
                confirmation_offre_mqtt=True,tester_relais_tcp=True,
                confirmation_relais_tcp=True,tester_kcp=True,
                confirmation_kcp=True,tester_media=True,
                confirmation_media=True,live_preview=preview,
                interactive_live=True))
            mqtt=report.get('signalisation_mqtt') or {}
            kcp=((mqtt.get('relais_tcp') or {}).get('kcp') or {})
            media=kcp.get('media_start') or {}
            frames_seen = (preview.summary().get('images_jpeg_decodees', 0)
                           if preview is not None else 0)
            ice_status = mqtt.get('negociation_ice_b85')
            disconnect_info = (preview.ptz_mqtt_observer.snapshot().get('dernier_disconnect')
                               if preview is not None else None)
            self._last_result={
                'images_jpeg_recues':frames_seen,
                'negociation_ice_b85':ice_status if isinstance(ice_status,dict) else None,
                'deconnexion_distante':disconnect_info,
                'etat_negociation':report.get('etat','non_disponible'),
                'etat_mqtt':mqtt.get('etat','non_disponible'),
                'signalisation_b89': mqtt.get('signalisation_b89'),
                'etat_relais':(mqtt.get('relais_tcp') or {}).get('etat','non_disponible'),
                'etat_media':media.get('etat','non_disponible'),
                'commandes_video':media.get('commandes_controle_envoyees',0) or (preview._b87_control_sent if preview else 0),
                'paquets_dechiffres':media.get('paquets_video_dechiffres',0) or (preview._b87_decrypted_media if preview else 0),
                'arret_sur_inactivite':bool(media.get('arret_inactivite_video')),
                'arret_sur_dechiffreur':bool(media.get('arret_dechiffreur')),
                'cause_fin_media_b85':media.get('cause_fin_session_b85','non_disponible'),
                'kcp_reception_b87':media.get('kcp_reception_b87',{}) or (preview._b87_kcp if preview else {}),
                'transport_tcp_b90':media.get('transport_tcp_b90',{}) or (preview._b90_tcp if preview else {}),
                'relais_keepalive_b92':media.get('relais_keepalive_b92',{}) or (preview._b92_keepalive if preview else {}),
                'fiabilite_controle_b96':media.get('fiabilite_controle_b96',{}) or (preview._b96_control if preview else {}),
            }
            reason = self._last_result['etat_negociation']
            self._retry.record(
                succeeded=bool(frames_seen),
                canceled=bool(preview is not None and preview.stopped),
                reason=('auth_refusee' if reason == 'login_UID_non_reussi'
                    else 'session_refusee' if (mqtt.get('refus_p2p_explicite')
                    or mqtt.get('etat') == 'deconnexion_camera_recue')
                    else 'aucune_image_jpeg' if self._last_result['paquets_dechiffres']
                    else 'aucune_video'))
            self._status = ('arret_utilisateur' if preview is not None and preview.stopped
                            else 'flux_inactif' if media.get('arret_inactivite_video')
                            else 'decodeur_interrompu' if media.get('arret_dechiffreur')
                            else 'fin_session_apres_images' if frames_seen
                            else 'hevc_recu_sans_jpeg' if self._last_result['paquets_dechiffres']
                            else 'limitation_locale' if reason in
                            ('limite_rtc_cinq_minutes', 'limite_inventaire_30_minutes',
                             'limite_login_une_heure') or
                            mqtt.get('etat') == 'limite_offre_trente_minutes'
                            else 'aucune_video')
        except Exception:
            self._status='erreur_session_sans_details'
            self._retry.record(succeeded=False,
                canceled=bool(preview is not None and preview.stopped),
                reason='erreur_interne')
        finally:
            if preview:
                await self.hass.async_add_executor_job(preview.stop)
            self._notify()

    def audit_ptz_channel(self, *, mark: bool = False) -> dict[str, Any]:
        """Audit the EXISTING video transport, without sending any command."""
        if not self.running or self.preview is None or self.preview.stopped:
            return {'diagnostic': 'aosu_canal_controle_direct_b41',
                    'etat': 'ouvrir_direct_c5l_avant_diagnostic',
                    'direct_actif': False, 'appels_reseau_supplementaires': 0,
                    'commandes_ptz_envoyees': 0, 'mouvement_autorise': False,
                    'secrets_retournes': False}
        obs = self.preview.ptz_control_observer
        data = obs.mark() if mark else obs.snapshot()
        return {**data, 'etat': 'observation_session_p2p_existante',
                'direct_actif': True, 'appels_reseau_supplementaires': 0,
                'marque_demandee': bool(mark)}

    def audit_ptz_mqtt(self, *, mark: bool = False) -> dict[str, Any]:
        """Read metadata from the MQTT connection already used by video."""
        if not self.running or self.preview is None or self.preview.stopped:
            return {'diagnostic': 'aosu_mqtt_ptz_direct_b42',
                    'etat': 'ouvrir_direct_c5l_avant_diagnostic',
                    'direct_actif': False, 'appels_reseau_supplementaires': 0,
                    'commandes_ptz_envoyees': 0, 'commandes_arret_envoyees': 0,
                    'secrets_retournes': False}
        obs = self.preview.ptz_mqtt_observer
        data = obs.mark() if mark else obs.snapshot()
        return {**data, 'etat': 'observation_mqtt_session_existante',
                'direct_actif': True, 'appels_reseau_supplementaires': 0,
                'marque_demandee': bool(mark)}

    def pause(self)->dict[str,Any]:
        if not self.running or self.preview is None or not self.preview.pause():
            return {'etat':'aucun_direct_actif'}
        self._status='affichage_en_pause'
        self._notify()
        return {'etat':'affichage_en_pause', 'connexion_p2p_maintenue':True,
                'nouvelle_offre_mqtt':False}

    def stop(self)->dict[str,Any]:
        if self.preview:self.preview._stop.set()
        self._status='arret_demande'
        self._notify()
        return {'etat': 'arret_demande' if self.running else 'aucun_direct_actif'}

    async def shutdown(self):
        self.stop()
        task=self._task
        if task:
            import asyncio
            try:await asyncio.wait_for(asyncio.shield(task),timeout=22)
            except (TimeoutError,asyncio.CancelledError):
                task.cancel()
                try:await task
                except asyncio.CancelledError:pass
        if self.preview:
            # On unload, do not retain private frames in RAM.
            with self.preview._lock:
                self.preview._jpeg=None
                self.preview._jpeg_at=0
