"""Select the existing cloud camera device for the experimental C5L preview.

Never create a synthetic/extra HA device.  This only selects a key from the
already-normalized, authenticated AOSU coordinator data.  An ambiguous
inventory is not attached to an arbitrary camera.
"""
from __future__ import annotations


def select_live_camera_key(coordinator):
    data = getattr(coordinator, "data", None) or {}
    cameras = [
        (key, row) for key, row in data.items()
        if isinstance(row, dict) and row.get("is_camera") is True
    ]
    if not cameras:
        return None

    def model_is_c5l(row):
        return "c5l" in str(row.get("model") or "").casefold()

    verified = [(key, row) for key, row in cameras if model_is_c5l(row)]
    # Select only an unambiguous C5L by model; never depend on an account-specific name.
    return verified[0][0] if len(verified) == 1 else None
