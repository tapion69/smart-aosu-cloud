"""Bounded in-memory JPEG chunk reassembly for standalone Tuya/AOSU C9C.

Input: *already authenticated & decrypted* video conversation 1 records,
as yielded by the existing channel-0 reader. This class has no network, no
camera commands, no disk writes, no frame or identifier logging.

A full JPEG requires contiguous bytes from offset 0 through a JPEG EOI.
Reject holes, inconsistent overlapping fragments and oversized buffers:
never turn zero-filled gaps into a convincing-but-fake picture.
"""
from __future__ import annotations

_MAX_JPEG = 3 * 1024 * 1024
_MIN_JPEG = 1024


class C9CJpegReassembler:
    def __init__(self) -> None:
        self._buffer = bytearray()
        self._active = False
        self._dropped = 0
        self._frames = 0

    def reset(self) -> None:
        self._buffer.clear()
        self._active = False

    def feed(self, offset: object, chunk: object) -> bytes | None:
        if (type(offset) is not int or not isinstance(chunk, bytes)
                or not chunk or len(chunk) > _MAX_JPEG):
            self._dropped += 1
            self.reset()
            return None
        if offset == 0:
            # A new JPEG SOI is the only permitted start/resynchronization.
            self.reset()
            if not chunk.startswith(b"\xff\xd8"):
                self._dropped += 1
                return None
            self._active = True
        if not self._active:
            return None
        end = offset + len(chunk)
        if offset < 0 or end > _MAX_JPEG or offset > len(self._buffer):
            self._dropped += 1
            self.reset()
            return None
        if offset < len(self._buffer):
            overlap = min(len(self._buffer) - offset, len(chunk))
            if self._buffer[offset:offset + overlap] != chunk[:overlap]:
                self._dropped += 1
                self.reset()
                return None
            self._buffer.extend(chunk[overlap:])
        else:
            self._buffer.extend(chunk)
        # Only emit completed JPEG frames with plausible length and markers.
        if len(self._buffer) < _MIN_JPEG or not self._buffer.endswith(b"\xff\xd9"):
            return None
        frame = bytes(self._buffer)
        self._frames += 1
        self.reset()
        return frame

    def summary(self) -> dict[str, object]:
        return {
            "diagnostic": "aosu_c9c_mjpeg_reassemblage_v1",
            "images_completes": min(self._frames, 1_000_000),
            "fragments_rejetes": min(self._dropped, 1_000_000),
            "fragment_en_cours": self._active,
            "octets_en_cours": min(len(self._buffer), _MAX_JPEG),
            "enregistrement": False,
            "appels_reseau": 0,
            "identifiants_retournes": False,
            "secrets_retournes": False,
        }
