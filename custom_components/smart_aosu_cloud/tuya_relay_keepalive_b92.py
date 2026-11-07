"""B92: outbound TCP relay keepalive every 1s, matching the Tuya P2P relay protocol.

The relay expects an independent F5 frame from the client even if the relay
continues sending its own F5 frames. No camera/PTZ commands, cloud requests,
or private media content are ever emitted here.
"""
from __future__ import annotations
import time
from typing import Callable, Any

KEEPALIVE = b"\xf5\x00\x00\x00"

class RelayKeepaliveB92:
    INTERVAL_SECONDS = 1.0

    def __init__(self, clock: Callable[[], float] | None = None):
        self._clock = clock or time.monotonic
        self._last_sent: float | None = None
        self._last_received: float | None = None
        self.sent = 0
        self.received = 0
        self.send_errors = 0

    def send_if_due(self, sock: Any) -> bool:
        """Transmit a single safe F5 relay keepalive once each interval."""
        now = self._clock()
        if self._last_sent is not None and now - self._last_sent < self.INTERVAL_SECONDS:
            return False
        try:
            sock.sendall(KEEPALIVE)
        except (OSError, ConnectionError, EOFError):
            self.send_errors += 1
            raise
        self._last_sent = self._clock()
        self.sent += 1
        return True

    def receive(self) -> None:
        """Log inbound relay F5; it does not replace the outbound heartbeat."""
        self.received += 1
        self._last_received = self._clock()

    def summary(self) -> dict[str, object]:
        now = self._clock()
        return {
            'intervalle_envoi_s': self.INTERVAL_SECONDS,
            'keepalives_envoyes': self.sent,
            'keepalives_recus': self.received,
            'erreurs_envoi': self.send_errors,
            'secondes_depuis_dernier_envoi': (round(max(0.0, now - self._last_sent), 1)
                                              if self._last_sent is not None else None),
            'secondes_depuis_derniere_reception': (round(max(0.0, now - self._last_received), 1)
                                                  if self._last_received is not None else None),
            'commandes_camera_envoyees': 0,
            'donnees_privees_retournees': False,
        }
