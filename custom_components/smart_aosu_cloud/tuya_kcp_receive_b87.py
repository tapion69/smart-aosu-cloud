"""In-memory bounded KCP RX reordering for AOSU media; no network calls.

Window ACK/UNA advances only through contiguous sequence numbers.
Fragmented messages are assembled with a 2 MiB bound rather than the legacy
12-segment cutoff. No raw bytes or identifiers are returned by diagnostics.
"""
from __future__ import annotations

MAX_BUFFERED_SEGMENTS = 512
MAX_MESSAGE = 2 * 1024 * 1024


class KcpReceiveB87:
    def __init__(self):
        self.next_sequence = 0
        self.pending: dict[int, tuple[int, bytes]] = {}
        self.fragments: list[bytes] = []
        self.fragment_bytes = 0
        self.fragments_started = 0
        self.messages_completed = 0
        self.duplicates = 0
        self.out_of_order = 0
        self.outside_window = 0
        self.oversized = 0
        self.max_fragments_for_message = 0
        self._fragment_count = 0

    def accept(self, sequence: int, fragment: int, data: bytes) -> list[bytes]:
        """Return completed contiguous messages, in their original order."""
        if not isinstance(sequence, int) or not 0 <= sequence <= 0xffffffff:
            return []
        if not isinstance(fragment, int) or not 0 <= fragment <= 255 or not isinstance(data, bytes):
            return []
        if sequence < self.next_sequence or sequence in self.pending:
            self.duplicates += 1
            return []
        if sequence >= self.next_sequence + MAX_BUFFERED_SEGMENTS:
            self.outside_window += 1
            return []
        if sequence != self.next_sequence:
            self.out_of_order += 1
        self.pending[sequence] = fragment, data
        completed: list[bytes] = []
        while self.next_sequence in self.pending:
            frag, chunk = self.pending.pop(self.next_sequence)
            self.next_sequence += 1
            if not self.fragments:
                self.fragments_started += 1
            self._fragment_count += 1
            if self.fragment_bytes + len(chunk) > MAX_MESSAGE:
                self.fragments.clear()
                self.fragment_bytes = 0
                self._fragment_count = 0
                self.oversized += 1
                continue
            self.fragments.append(chunk)
            self.fragment_bytes += len(chunk)
            if frag == 0:
                completed.append(b''.join(self.fragments))
                self.max_fragments_for_message = max(self.max_fragments_for_message, self._fragment_count)
                self.fragments.clear()
                self.fragment_bytes = 0
                self._fragment_count = 0
                self.messages_completed += 1
        return completed

    def summary(self) -> dict:
        return {
            'segments_en_attente': len(self.pending),
            'fragments_message_en_cours': self._fragment_count,
            'messages_reconstitues': self.messages_completed,
            'doublons': self.duplicates,
            'hors_ordre': self.out_of_order,
            'hors_fenetre': self.outside_window,
            'depassements_taille': self.oversized,
            'max_fragments_par_message': self.max_fragments_for_message,
            'sequence_continue': self.next_sequence,
            'donnees_video_retournees': False,
        }
