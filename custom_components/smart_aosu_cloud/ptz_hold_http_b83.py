"""B83: PTZ hold control for a C5L via physically-tested OEM HTTP route.

One movement at a time, from authenticated HA services, no Android/PC bridge.
The user no longer needs MJPEG, an 'arm' step, checkboxes or 5-minute test
cooldowns. This is still network control: real motor STOP is not observable.
A watchdog and unconditional STOP-on-exit remain as safety measures.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
import threading
import time
from typing import Any

from .ptz_direction_test_b82 import _session_and_camera
from .ptz_stop_alternate_api_b79 import publish_alternate_stop_once
from .ptz_right_test_b81 import _right_once
from .ptz_direction_test_b82 import _direction_once

DIRECTIONS = ('haut', 'bas', 'gauche', 'droite')
# Avoid repeating the old 0.75-second experiment; a real press/hold now works.
# Still bound a lost browser event. Physical STOP depends on network availability.
MAX_HOLD_SECONDS = 12.0
MIN_TAP_SECONDS = 0.30
GESTURE_PATTERN = re.compile(r'[A-Za-z0-9_-]{8,80}\Z')


@dataclass
class Gesture:
    identifier: str
    direction: str
    released: threading.Event = field(default_factory=threading.Event)
    cancelled: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    watchdog: threading.Thread | None = None
    started_at: float = field(default_factory=time.monotonic)


class C5LPtzHoldB83:
    """Per-coordinator controller, not one per Lovelace card/browser."""

    def __init__(self, coordinator: Any):
        self.coordinator = coordinator
        self._lock = threading.RLock()
        self._active: Gesture | None = None
        self._state = 'disponible'
        self._last_direction = None
        self._last_stop_accepted = None
        self._last_direction_accepted = None
        self._last_error = None
        self._closed = False
        self._stop_workers: set[threading.Thread] = set()

    def status(self):
        with self._lock:
            return self._snapshot()

    def _snapshot(self):
        return {
            'diagnostic': 'aosu_ptz_maintien_b83',
            'etat': self._state,
            'action_active': self._active is not None,
            'direction_active': self._active.direction if self._active else None,
            'derniere_direction': self._last_direction,
            'direction_acceptee_serveur': self._last_direction_accepted,
            'stop_accepte_serveur': self._last_stop_accepted,
            'erreur': self._last_error,
            'arret_physique_mesure': False,
            'api': 'thing.m.nb.device.dp.publish',
            'video_independante': True,
            'watchdog_secondes': MAX_HOLD_SECONDS,
        }

    def press(self, direction: str, gesture_id: str):
        if direction not in DIRECTIONS or not isinstance(gesture_id, str) or not GESTURE_PATTERN.fullmatch(gesture_id):
            return {'etat': 'parametres_invalides'}
        with self._lock:
            if self._closed:
                return {'etat': 'controle_arrete'}
            if self._active is not None:
                return {'etat': 'mouvement_deja_en_cours'}
            gesture = Gesture(gesture_id, direction)
            self._active = gesture
            self._last_direction = direction
            self._last_direction_accepted = None
            self._last_stop_accepted = None
            self._last_error = None
            self._state = 'preparation'
            worker = threading.Thread(target=self._run, args=(gesture,),
                                      daemon=True, name='smart-aosu-b83-ptz')
            gesture.thread = worker
            worker.start()
            # Separate best-effort watchdog: a stalled HTTP direction request
            # must not delay every attempt to send STOP until it returns.
            guard = threading.Thread(target=self._watchdog, args=(gesture,),
                                     daemon=True, name='smart-aosu-b83-watchdog')
            gesture.watchdog = guard
            guard.start()
            return {'etat': 'appui_recu', 'direction': direction, 'arret_sur_relachement': True}

    def release(self, gesture_id: str):
        if not isinstance(gesture_id, str) or not GESTURE_PATTERN.fullmatch(gesture_id):
            return {'etat': 'identifiant_invalide'}
        with self._lock:
            current = self._active
            if current is None:
                return {'etat': 'aucun_mouvement_actif'}
            if current.identifier != gesture_id:
                return {'etat': 'autre_appui_actif'}
            current.released.set()
            self._state = 'arret_demande'
            return {'etat': 'relachement_recu_stop_en_cours'}

    def stop(self):
        """STOP button is always available, even when no gesture is active.

        An independent STOP can overtake an outstanding direction HTTP request;
        therefore the gesture worker MUST send a final STOP after that request.
        """
        with self._lock:
            if self._active is not None:
                self._active.cancelled.set()
                self._active.released.set()
            self._state = 'arret_urgence_demande'
            worker = threading.Thread(target=self._send_emergency_stop, daemon=True,
                                      name='smart-aosu-b83-urgence')
            self._stop_workers.add(worker)
            worker.start()
            return {'etat': 'stop_urgence_demande', 'stop_physique_non_mesure': True}

    def _watchdog(self, gesture: Gesture):
        remaining = max(0.0, MAX_HOLD_SECONDS - (time.monotonic() - gesture.started_at))
        released = gesture.released.wait(remaining)
        if not released:
            gesture.cancelled.set()
            gesture.released.set()
        elif gesture.cancelled.is_set():
            return  # STOP button has already triggered its own emergency request.
        else:
            # Allow a normal ordered STOP a small head-start before launching
            # a secondary STOP over an independent HTTP call.
            if gesture.cancelled.wait(0.35):
                return
        with self._lock:
            pending = self._active is gesture
        if pending:
            self._send_emergency_stop()

    def close(self):
        with self._lock:
            self._closed = True
            current = self._active
            if current is not None:
                current.cancelled.set()
                current.released.set()
        if current is not None:
            self.stop()
            # Best effort to let the ordered STOP complete before HA unloads.
            if current.thread and threading.current_thread() is not current.thread:
                current.thread.join(timeout=2.0)

    def _params(self):
        """Refresh stale OEM inventory once, then use proven b79 credentials/selection.

        No video state constraint and no test cooldown. Authentication and
        camera identification stay server-side, never exposed to the card.
        """
        from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
        state = audit_ptz_readiness(self.coordinator, self.coordinator.client)
        if state.get('cache_oem_recent') is not True:
            refresh = refresh_ptz_inventory(self.coordinator, password_confirmed=True, allow_during_live=True)
            if refresh.get('etat') not in ('inventaire_oem_ptz_lu', 'cache_recent_reutilise'):
                raise ValueError('inventaire_oem_indisponible')
        return _session_and_camera(self.coordinator)

    def _publish_stop(self, params):
        identity, signer, session, dev_id, ttid, install_id, *_ = params
        res = publish_alternate_stop_once(identity, signer, session,
                     dev_id=dev_id, ttid=ttid, device_id=install_id)
        return res.get('publication_acceptee_par_serveur') is True

    def _send_emergency_stop(self):
        ok = False
        try:
            params = self._params()
            ok = self._publish_stop(params)
        except Exception:
            pass  # Never log credentials, IDs, or server content.
        finally:
            with self._lock:
                self._last_stop_accepted = ok
                # The motion worker may still need to send its ordered STOP.
                if self._active is None:
                    self._state = 'stop_accepte_serveur' if ok else 'stop_non_confirme_ouvrir_aosu'
                self._stop_workers.discard(threading.current_thread())

    def _run(self, gesture: Gesture):
        params = None
        direction_attempted = False
        stop_ok = False
        outcome = 'erreur_commande'
        try:
            params = self._params()
            # If the UI was closed or STOP pressed during slow authentication,
            # never start a late/unexpected movement.
            if (gesture.cancelled.is_set() or self._closed or
                time.monotonic() - gesture.started_at >= MAX_HOLD_SECONDS or
                (gesture.released.is_set() and time.monotonic() - gesture.started_at > 1.0)):
                # A very late authentication must never initiate a movement
                # after the user already released the control.
                outcome = 'annule_avant_direction'
                return
            identity, signer, session, dev_id, ttid, install_id, *_ = params
            direction_attempted = True  # a timed-out request may still reach camera
            with self._lock:
                self._state = 'direction_envoyee'
            if gesture.direction == 'droite':
                ok = _right_once(identity, signer, session, dev_id, ttid, install_id)
            else:
                ok = _direction_once(identity, signer, session, dev_id, ttid, install_id,
                                     direction=gesture.direction)
            with self._lock:
                self._last_direction_accepted = ok
                self._state = 'mouvement' if ok else 'direction_refusee'
            if ok and not gesture.cancelled.is_set():
                # Brief tap still gives a measurable pulse, then release stops.
                # Held button moves until release, with an independent watchdog.
                elapsed = time.monotonic() - gesture.started_at
                minimum = max(0.0, MIN_TAP_SECONDS - elapsed)
                if minimum:
                    gesture.cancelled.wait(minimum)
                if not gesture.cancelled.is_set():
                    gesture.released.wait(max(0.0, MAX_HOLD_SECONDS - (time.monotonic() - gesture.started_at)))
            outcome = 'mouvement_et_arret'
        except Exception:
            with self._lock:
                self._last_error = 'api_ou_session_indisponible'
            outcome = 'erreur_api'
        finally:
            # Always send STOP after any attempted direction, including a
            # timed-out call. This prevents an earlier emergency STOP from
            # being overtaken by an in-flight direction request.
            if params is not None and direction_attempted:
                for retry in range(2):
                    try:
                        stop_ok = self._publish_stop(params)
                        if stop_ok:
                            break
                    except Exception:
                        pass
                    if retry == 0:
                        gesture.cancelled.wait(0.25)
            with self._lock:
                self._last_stop_accepted = stop_ok if direction_attempted else self._last_stop_accepted
                if self._active is gesture:
                    self._active = None
                if direction_attempted and not stop_ok:
                    self._state = 'stop_non_confirme_ouvrir_aosu'
                elif outcome == 'annule_avant_direction':
                    self._state = 'annule_sans_mouvement'
                elif outcome == 'erreur_api':
                    self._state = 'erreur_api'
                else:
                    self._state = 'stop_accepte_serveur'
