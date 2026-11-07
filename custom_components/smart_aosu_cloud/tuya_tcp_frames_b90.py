"""B90: Stateful TCP relay framing. Preserve partial frames across socket timeouts.

Unlike recv_exact-per-call, a timeout after a partial TCP read must not discard
those bytes. This module never logs, stores or exports the frame contents.
"""
from __future__ import annotations
import socket
import time

MAX_RELAY_PAYLOAD = 8192


class RelayFrameReaderB90:
    def __init__(self):
        self._buffer = bytearray()
        self.frames = 0
        self.partial_timeouts = 0
        self.empty_timeouts = 0
        self.partial_reads = 0
        self.invalid_length = 0
        self.max_buffered_bytes = 0
        self.closed_mid_frame = 0
        # B91: timing/length metadata only, never private network contents.
        self.total_bytes_received = 0
        self._last_byte_at = None
        self._partial_started_at = None
        self._consecutive_partial_timeouts = 0
        self.maximum_consecutive_partial_timeouts = 0

    def read(self, sock):
        """Return (kind, payload), or None on timeout; never lose partial data."""
        while True:
            if len(self._buffer) < 4:
                needed = 4 - len(self._buffer)
            else:
                length = int.from_bytes(self._buffer[2:4], "big")
                if length > MAX_RELAY_PAYLOAD:
                    self.invalid_length += 1
                    raise ValueError("relay_payload_too_long")
                needed = 4 + length - len(self._buffer)
                if needed == 0:
                    kind = self._buffer[0]
                    payload = bytes(self._buffer[4:])
                    self._buffer.clear()
                    self._partial_started_at = None
                    self._consecutive_partial_timeouts = 0
                    self.frames += 1
                    return kind, payload
            try:
                piece = sock.recv(needed)
            except (socket.timeout, TimeoutError):
                if self._buffer:
                    self.partial_timeouts += 1
                    self._consecutive_partial_timeouts += 1
                    self.maximum_consecutive_partial_timeouts = max(
                        self.maximum_consecutive_partial_timeouts, self._consecutive_partial_timeouts)
                else:
                    self.empty_timeouts += 1
                return None
            if not piece:
                if self._buffer:
                    self.closed_mid_frame += 1
                raise EOFError("relay_closed")
            if len(piece) < needed:
                self.partial_reads += 1
            if not self._buffer:
                self._partial_started_at = time.monotonic()
            self._last_byte_at = time.monotonic()
            self.total_bytes_received += len(piece)
            self._buffer.extend(piece)
            self.max_buffered_bytes = max(self.max_buffered_bytes, len(self._buffer))

    def summary(self):
        now = time.monotonic()
        have_header = len(self._buffer) >= 4
        expected = 4 + int.from_bytes(self._buffer[2:4], "big") if have_header else None
        remaining = max(0, expected - len(self._buffer)) if expected is not None else None
        return {
            "trames_completes": self.frames,
            "attentes_avec_trame_partielle": self.partial_timeouts,
            "attentes_sans_donnees": self.empty_timeouts,
            "lectures_partielles": self.partial_reads,
            "octets_en_attente": len(self._buffer),
            "octets_recus_total": self.total_bytes_received,
            "octets_requis_pour_trame": expected,
            "octets_manquants_pour_trame": remaining,
            "age_trame_partielle_s": (round(now-self._partial_started_at, 1)
                                      if self._buffer and self._partial_started_at is not None else None),
            "secondes_depuis_dernier_octet": (round(now-self._last_byte_at, 1)
                                               if self._last_byte_at is not None else None),
            "attentes_partielles_consecutives": self._consecutive_partial_timeouts,
            "maximum_attentes_partielles_consecutives": self.maximum_consecutive_partial_timeouts,
            "maximum_octets_tamponnes": self.max_buffered_bytes,
            "tailles_invalides": self.invalid_length,
            "connexions_fermees_trame_incomplete": self.closed_mid_frame,
            "contenu_prive_retourne": False,
        }
