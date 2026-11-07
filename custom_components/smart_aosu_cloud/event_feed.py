"""Bounded, read-only AOSU recent-event feed.

Only /v1/event/getImageList, which has returned events on a real account,
is used. Never export event identifiers, SNs, private image URLs or IA payloads.
There is no live detection claim; event categories are interpreted conservatively.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone

import requests

from . import protocol_060 as proto
from .semantics import parse_cover_event_time

_API = 'https://api-eu.aosulife.com/v1/event/getImageList'
_MAX_BODY = 262144
_MAX_ROWS = 100
# Literal names convey their meaning; no numeric mapping is invented.
_CATEGORIES = {
    'motion': 'Mouvement', 'movement': 'Mouvement',
    'motion_detection': 'Mouvement',
    'person': 'Personne', 'human': 'Personne',
    'human_detection': 'Personne', 'person_detection': 'Personne',
    'vehicle': 'Véhicule', 'car': 'Véhicule',
    'animal': 'Animal', 'pet': 'Animal',
    # Exact lexical tokens in three-camera AOSU audit, verified by matching
    # SHA-256 prefixes against string constants in the owner's 5.10.12 APK.
    # Their French glosses are provisional. They are NOT equivalent to
    # 'Mouvement' or 'Personne' and must not trigger AI-category automations.
    'pass': 'Passage (AOSU)',
    'stay': 'Présence prolongée (AOSU)',
}
# Short event type codes, not arbitrary service messages or IDs.
_SAFE_CODE = re.compile(r'(?:[0-9]{1,5}|[a-zA-Z][a-zA-Z0-9_-]{0,23})\Z', re.ASCII)


def _category(v):
    return _CATEGORIES.get(v.strip().lower()) if isinstance(v, str) else None


def _event_code(v):
    if type(v) is int and 0 <= v <= 99999:
        return str(v)
    if isinstance(v, str):
        val = v.strip()
        if _SAFE_CODE.fullmatch(val):
            if val.isdecimal() or _category(val):
                return val
            # Unknown free-form eventType could accidentally contain an ID.
            # Use an irreversible reference to distinguish types, not content.
            return 'ref_' + hashlib.sha256(val.encode('utf-8')).hexdigest()[:10]
    return None


def summarize_event(item: object, *, now: datetime | None = None) -> dict | None:
    """Return only safe timestamp and type summary, never raw event payload."""
    if not isinstance(item, dict):
        return None
    event_time = parse_cover_event_time(item.get('eventTime'))
    if event_time is None:
        return None
    current = now or datetime.now(timezone.utc)
    if event_time > current + timedelta(days=2):
        return None
    raw = item.get('eventType')
    tokens = item.get('uniformType')
    # If several uniformType entries coexist, keep a directly confirmed
    # person/animal/vehicle/movement category ahead of the provisional
    # pass/stay labels. Never combine labels into an invented new AI event.
    categories = []
    if isinstance(tokens, list):
        for token in tokens[:8]:
            known = _category(token)
            if known:
                categories.append(known)
    raw_category = _category(raw)
    if raw_category:
        categories.append(raw_category)
    primary = [label for label in categories if not label.endswith('(AOSU)')]
    category = (primary or categories or [None])[0]
    # Raw code deliberately excludes the event id and user-defined AI metadata.
    if category:
        label = category
    else:
        # Event codes can be opaque IDs. Do not present a hashed technical
        # reference as a meaningful detection category in Home Assistant.
        # Privacy-safe hashed codes remain available in the manual audit.
        label = 'Type non identifié'
    return {'recent_event_time': event_time, 'recent_event_type': label,
            'recent_event_recognized': category is not None}


def parse_event_feed(body: object, camera_sns: list[str], *, now: datetime | None = None) -> dict[str, dict] | None:
    """Extract newest seen event per known camera using hashed device keys."""
    if not isinstance(body, dict) or type(body.get('errno')) is not int or body['errno'] != 0:
        return None
    data = body.get('data')
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = next((data[k] for k in ('list', 'records', 'events', 'items')
                     if isinstance(data.get(k), list)), None)
        if rows is None:
            lists = [v for v in data.values() if isinstance(v, list)]
            rows = lists[0] if len(lists) == 1 else None
    else:
        rows = None
    if rows is None:
        return None
    whitelist = {sn for sn in camera_sns if isinstance(sn, str) and 0 < len(sn) <= 256}
    result = {}
    for item in rows[:_MAX_ROWS]:
        if not isinstance(item, dict):
            continue
        sn = item.get('sn')
        if not isinstance(sn, str) or sn not in whitelist:
            continue
        info = summarize_event(item, now=now)
        if info is None:
            continue
        key = hashlib.sha256(('aosu-device:' + sn).encode()).hexdigest()[:32]
        previous = result.get(key)
        if previous is None or info['recent_event_time'] > previous['recent_event_time']:
            result[key] = info
    return result


def get_recent_event_feed(client, camera_sns: list[str]) -> dict[str, dict] | None:
    """One authenticated read per polling window; never add event URLs to HA."""
    if not camera_sns or not client._sid or not client._uid or not client._login_headers:
        return None
    params, headers = proto.build_device_list_request(
        client._suffix, client._login_headers, client._sid, client._uid
    )
    headers = dict(headers)
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    form = [('sn[]', sn) for sn in camera_sns[:10]] + [('count', '10')]
    try:
        response = client.session.post(
            _API, params=params, data=form, headers=headers,
            timeout=(8, 20), allow_redirects=False, verify=True,
        )
        if response.status_code != 200 or len(response.content) > _MAX_BODY:
            return None
        return parse_event_feed(response.json(), camera_sns)
    except (requests.RequestException, ValueError, TypeError):
        return None
