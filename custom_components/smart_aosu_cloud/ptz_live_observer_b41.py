"""Passive, in-RAM metadata monitor for the C5L control channel of an ALREADY live session.

NEVER publishes a DP or a KCP control packet, stores payloads or user credentials,
logs frame contents, nor captures video. Inbound evidence in a P2P channel is not
proof that PTZ uses that channel (Tuya also has a dedicated DP SDK publisher).
"""
from __future__ import annotations
import threading
import time
from collections import Counter

_MAGIC = b"\x78\x56\x34\x12"
_TOKENS = (b"ptz_control", b"ptz_stop")


class PassivePtzChannelObserver:
    """Thread-safe aggregate counts ONLY; never retains the original bytes."""

    def __init__(self, *, clock=time.monotonic):
        self._lock = threading.Lock()
        self._clock = clock
        self._since = clock()
        self._segments = 0
        self._decryptions = 0
        self._decrypt_errors = 0
        self._header_formats = Counter()
        self._types = Counter()
        self._token_counts = Counter()
        self._baseline = None

    def segment(self):
        with self._lock:
            self._segments += 1

    def decrypt_error(self):
        with self._lock:
            self._decrypt_errors += 1

    def decrypted_control_record(self, plaintext: bytes):
        if not isinstance(plaintext, bytes):
            return
        # The original decrypted bytes are NEVER retained or exported.
        kind = 'format_non_identifie'
        header = None
        if len(plaintext) >= 20 and plaintext[:4] == _MAGIC:
            # Frame type/subtype from known, fixed-size control header.
            t = int.from_bytes(plaintext[4:8], 'little')
            sub = int.from_bytes(plaintext[12:16], 'little')
            declared = int.from_bytes(plaintext[16:20], 'little')
            if declared == len(plaintext) - 20:
                kind = 'entete_controle_structure_valide'
                header = f'{t:08x}:{sub:08x}'
            else:
                kind = 'entete_controle_longueur_incoherente'
        elif len(plaintext) >= 8 and plaintext[:4] == _MAGIC:
            kind = 'entete_auth_ou_binaire'
        with self._lock:
            self._decryptions += 1
            self._header_formats[kind] += 1
            if header is not None:
                self._types[header] += 1
            for token in _TOKENS:
                if token in plaintext:
                    self._token_counts[token.decode('ascii')] += 1

    def _counts(self):
        return {
            'segments_controle_recus': self._segments,
            'trames_controle_dechiffrees': self._decryptions,
            'dechiffrements_controle_impossibles': self._decrypt_errors,
            'marqueurs_ptz_control': self._token_counts['ptz_control'],
            'marqueurs_ptz_stop': self._token_counts['ptz_stop'],
        }

    def mark(self):
        """Mark a comparison window using numeric counters only."""
        with self._lock:
            self._baseline = self._counts()
            return self._snapshot_locked()

    def snapshot(self):
        with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self):
        counts = self._counts()
        # Whitelist-only aggregate output, no raw bytes, IDs, keys or frame text.
        return {
            'diagnostic': 'aosu_canal_controle_direct_b41',
            'observation_purement_passive': True,
            'commandes_ptz_envoyees': 0,
            'commandes_arret_envoyees': 0,
            'nouvelle_negociation_reseau': False,
            'capture_video': False,
            'donnees_brutes_conservees': False,
            'secrets_retournes': False,
            'duree_observation_secondes': int(max(0, self._clock()-self._since)),
            **counts,
            'types_entetes_controle': [
                {'type_subtype_hex': key, 'nombre': n}
                for key,n in self._types.most_common(12)
            ],
            'formats': dict(self._header_formats),
            'marque_comparaison_presente': self._baseline is not None,
            'depuis_marque': ({key: counts[key]-self._baseline[key]
                               for key in counts} if self._baseline is not None else {}),
            'conclusion_ptz': 'transport_non_identifie_pour_mouvement',
            'arret_moteur_verifie': False,
            'mouvement_autorise': False,
        }
