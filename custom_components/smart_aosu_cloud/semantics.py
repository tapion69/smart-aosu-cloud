"""Conservative interpretations of values seen in the AOSU getList response.

Only the raw 0 and 1 codes are mapped for the cloud-connection flag.
No battery percentage, signal strength unit or power mode is inferred.
"""
from __future__ import annotations

def cloud_online(value: object) -> bool | None:
    """Return cloud availability for the observed 0/1 status codes.

    Unknown status codes remain unknown instead of being treated as online.
    Reject booleans even though bool is a subclass of int.
    """
    if type(value) not in (int, float):
        return None
    if value == 1:
        return True
    if value == 0:
        return False
    return None


from datetime import datetime, timezone


def parse_cover_event_time(raw: object) -> datetime | None:
    """Convert a plausible AOSU coverInfo.eventTime to timezone-aware UTC.

    The real AOSU inventory observed on three cameras uses likely Unix
    milliseconds. Seconds are accepted for compatibility. This timestamp is
    *not* proof of a motion or person event, and not a camera video URL.
    Unknown/implausible timestamps become unavailable, never 1970.
    """
    if type(raw) not in (int, float) or raw != raw:  # disallow bool and NaN
        return None
    if 1_420_070_400 <= raw < 2_208_988_800:  # 2015-2040 in seconds
        seconds = raw
    elif 1_420_070_400_000 <= raw < 2_208_988_800_000:  # milliseconds
        seconds = raw / 1000.0
    else:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
