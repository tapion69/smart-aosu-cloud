"""Generate a minimal local Android-like profile for an opt-in AOSU test.

Values are *unverified* substitutes for an Android phone. They may be
refused by the AOSU service. An existing user-supplied profile is never
changed. Do not serialize the profile into diagnostics, logs, or Git.
"""
from __future__ import annotations
import json
import os
import secrets
from pathlib import Path


def ensure_profile(path: Path) -> None:
    """Create once, with restrictive permissions; do not overwrite existing."""
    path = Path(path)
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # All values mimic the *shape* of AOSU 5.10.12 headers, not a real phone.
    profile = {
        "version": 1,
        "android_properties": {
            "Gz-OsVer": "35", "Gz-Brand": "generic",
            "Gz-Model": "Android", "Gz-FontSize": "1.0",
        },
        "additional_headers": {
            "Gz-Imei": secrets.token_hex(8),  # random local identifier, never a phone IMEI
            "Gz-Network": "{vpn=false, wifi=false/null, available=true}",
            "Gz-NotifyPermission": (
                "{filter=ALL, channels={}, channelGroups={}, enabled=true, "
                "paused=false, BubblesAllowed=false}"
            ),
        },
    }
    # The 'x' flag prevents replacement when another thread creates it first.
    # chmod is not relied on to protect an existing user-provided file.
    fd = None
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            fd = None
            json.dump(profile, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except BaseException:
        # On a partial first write, remove incomplete output rather than reuse.
        # Never remove a file if the OS did not let us create it.
        try:
            path.unlink(missing_ok=True)
        finally:
            raise
    finally:
        if fd is not None:
            os.close(fd)
