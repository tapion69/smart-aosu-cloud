"""B96: bounded reliable delivery of control KCP channel 0 startup pushes.

The relay signaling tunnel (conversation 0x010000F3) is deliberately excluded:
replaying an offer can terminate a video session. This class is only used
for seven existing startup packets on conversation 0. No new camera commands.
"""
from __future__ import annotations
import time
from typing import Callable, Any


class ControlDeliveryB96:
    RETRY_SECONDS = 1.5
    MAX_TRANSMISSIONS = 3  # including original push; bounded, not endless

    def __init__(self, clock: Callable[[], float] | None = None):
        self._clock = clock or time.monotonic
        self._pending: dict[int, tuple[bytes, float, int]] = {}
        self.initial = 0
        self.acked = 0
        self.acks_received = 0
        self.retransmissions = 0
        self.gave_up = 0
        self.errors = 0
        self._first_ack: float | None = None

    def sent(self, sequence: int, raw_frame: bytes) -> None:
        """Store only per-session KCP frames in RAM, never logs or reports."""
        if not (0 <= sequence < 7) or len(raw_frame) > 8192:
            raise ValueError('invalid control startup segment')
        self._pending[sequence] = (raw_frame, self._clock(), 1)
        self.initial += 1

    def input(self, *, cmd: int, sequence: int, una: int) -> None:
        """KCP ACK or peer cumulative UNA; valid only on conversation zero."""
        if cmd == 0x52:
            self.acks_received += 1
        # Invalid or contradictory cumulative values must not retire packets.
        acknowledged = {n for n in self._pending if 0 <= una <= 7 and n < una}
        if cmd == 0x52 and 0 <= sequence < 7:
            acknowledged.add(sequence)
        for n in acknowledged:
            self._pending.pop(n, None)
        if acknowledged:
            self.acked += len(acknowledged)
            if self._first_ack is None:
                self._first_ack = self._clock()

    def retransmit_if_due(self, sock: Any) -> int:
        """Resend only outstanding, identical channel-0 KCP frames, at most twice."""
        now = self._clock()
        sent = 0
        for sequence in sorted(tuple(self._pending)):
            raw, last, attempts = self._pending.get(sequence, (b'', now, 0))
            if not raw or now-last < self.RETRY_SECONDS:
                continue
            if attempts >= self.MAX_TRANSMISSIONS:
                del self._pending[sequence]
                self.gave_up += 1
                continue
            try:
                sock.sendall(raw)
            except (OSError, ConnectionError, EOFError):
                self.errors += 1
                raise
            self._pending[sequence] = (raw, self._clock(), attempts+1)
            self.retransmissions += 1
            sent += 1
        return sent

    def summary(self) -> dict[str, object]:
        return {
            'commandes_initiales_envoyees': self.initial,
            'commandes_kcp_acquittees': self.acked,
            'ack_kcp_recus': self.acks_received,
            'commandes_en_attente_ack': len(self._pending),
            'retransmissions_controle': self.retransmissions,
            'commandes_sans_ack_apres_limite': self.gave_up,
            'erreurs_retransmission': self.errors,
            'delai_retransmission_s': self.RETRY_SECONDS,
            'maximum_envois_par_commande': self.MAX_TRANSMISSIONS,
            'premier_ack_observe': self._first_ack is not None,
            'offre_mqtt_retransmise': False,
            'commandes_ptz_envoyees': 0,
            'secrets_retournes': False,
        }
