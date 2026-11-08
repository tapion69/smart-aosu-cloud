"""Bounded offline DEX literal audit of owner's known AOSU 5.10.12 APK.

No identifiers, extracted strings, SDK keys, images, network, or camera commands.
This is evidence of embedded strings, not of executed application behavior.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import struct
import threading
import time
import zipfile
from typing import Any

ORIGINAL_SIZE = 200265946
ORIGINAL_SHA = 'ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7'
LITE_SIZE = 1690990
LITE_SHA = '6a3692aa0dc2385f9d988ffbcf7a703249d426b022f78857d2b380748e790be1'
ORIGINAL_NAMES = ('Aosu_5.10.12_original.apks.apk',
                  'Aosu_5.10.12_21839_original.apks.apk',
                  'Aosu_5.10.12_21839.apks.apk')
_MAX_BASE = 230 * 1024 * 1024
_MAX_DEX = 32 * 1024 * 1024
_MAX_TOTAL_DEX = 256 * 1024 * 1024
_MAX_DEX_COUNT = 32
_LOCK = threading.Lock()
_ALLOWED: dict[int, float] = {}
_COOLDOWN = 900

# Only these fixed indicators escape the scanner, never matched raw strings.
_INDICATORS = {
    'jarvis_mqtt': (b'/api/jarvis/mqtt',),
    'jarvis_config': (b'/api/jarvis/config',),
    'ipc_config_api': (b'thing.m.ipc.config.get',),
    'rtc_v4_api': (b'm.ipc.v4.rtc.config.get',),
    'hub_access_config': (b'open-iot-hub/access/config',),
    'mqtt_session_msid': (b'msid', b'mSid'),
    'mqtt_mobile_domain': (b'mobileMqttsUrl',),
    'route_webrtc_in': (b'/av/u/',),
    'route_webrtc_out': (b'/av/moto/',),
    'sdk_mqtt_client': (b'MqttClient', b'MQTTClient', b'MqttManager'),
    'sdk_camera_tuya': (b'com/thingclips/smart/camera', b'com.thingclips.smart.android.camera'),
    'aosu_ty_controller': (b'com/glazero/mid/iot/ty', b'com.glazero.mid.iot.ty'),
}


def _dex_flags(data: bytes) -> dict[str, bool] | None:
    """Inspect DEX string_ids, avoiding incidental matches in arbitrary binary."""
    if len(data) < 112 or data[:4] != b'dex\n' or data[7] != 0:
        return None
    if struct.unpack_from('<I', data, 36)[0] != 112:
        return None
    count, offset = struct.unpack_from('<II', data, 56)
    if count > 1_000_000 or offset < 112 or offset + count * 4 > len(data):
        return None
    flags = {name: False for name in _INDICATORS}
    remaining = len(flags)
    for i in range(count):
        start = struct.unpack_from('<I', data, offset + 4 * i)[0]
        if start >= len(data):
            continue
        # Skip DEX's unsigned LEB128 UTF-16 code-point length (1..5 bytes).
        pos = start
        for _ in range(5):
            if pos >= len(data):
                break
            byte = data[pos]
            pos += 1
            if byte < 128:
                break
        else:
            continue
        end = data.find(b'\0', pos, min(len(data), pos + 256))
        if end < 0:
            continue
        value = data[pos:end]
        for key, markers in _INDICATORS.items():
            if not flags[key] and any(marker in value for marker in markers):
                flags[key] = True
                remaining -= 1
        if remaining == 0:
            break
    return flags


def _scan_base_apk(base: bytes) -> tuple[int, dict[str, bool]]:
    found = {key: False for key in _INDICATORS}
    processed = 0
    total_bytes = 0
    with zipfile.ZipFile(io.BytesIO(base)) as z:
        entries = [x for x in z.infolist() if x.filename.startswith('classes')
                   and x.filename.endswith('.dex') and '/' not in x.filename]
        if not entries or len(entries) > _MAX_DEX_COUNT:
            raise ValueError('dex_count_invalid')
        for entry in entries:
            if entry.file_size > _MAX_DEX or total_bytes + entry.file_size > _MAX_TOTAL_DEX:
                raise ValueError('dex_too_large')
            raw = z.read(entry)
            total_bytes += len(raw)
            flags = _dex_flags(raw)
            if flags is None:
                raise ValueError('dex_invalid')
            processed += 1
            for k, value in flags.items():
                found[k] |= value
    return processed, found


def _fingerprint(path: Path) -> tuple[int, str]:
    stat = path.stat()
    if stat.st_size not in (ORIGINAL_SIZE, LITE_SIZE):
        return stat.st_size, ''
    h = hashlib.sha256()
    with path.open('rb') as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b''):
            h.update(block)
    return stat.st_size, h.hexdigest()


def audit_apk_sdk_c9c(client: Any) -> dict[str, object]:
    """One explicit local-only scan of the configured APK or known full sibling."""
    result: dict[str, object] = {
        'diagnostic': 'aosu_c9c_sdk_mqtt_b25',
        'etat': 'non_lance', 'source': 'aucune', 'dex_scannes': 0,
        'apk_complet_valide': False, 'analyse_partielle': True,
        'methode_mqtt_identifiee': False,
        'indicateurs': {name: False for name in _INDICATORS},
        'appels_reseau': 0, 'publications_mqtt': 0, 'offres_envoyees': 0,
        'commandes_camera': 0, 'commandes_ptz': 0,
        'video_lancee': False, 'identifiants_retournes': False,
        'secrets_retournes': False, 'chaines_brutes_retournees': False,
        'fichiers_crees': 0,
    }
    if not _LOCK.acquire(blocking=False):
        return {**result, 'etat': 'analyse_deja_en_cours'}
    try:
        now = time.monotonic()
        key = id(client)
        if now < _ALLOWED.get(key, 0):
            return {**result, 'etat': 'limite_quart_heure'}
        source = getattr(client, 'apk_path', None)
        if not isinstance(source, (str, Path)):
            return {**result, 'etat': 'apk_non_configure'}
        configured = Path(source)
        if not configured.is_file():
            return {**result, 'etat': 'apk_introuvable'}
        try:
            size, digest = _fingerprint(configured)
        except (OSError, ValueError):
            return {**result, 'etat': 'apk_illisible'}
        if (size, digest) not in ((ORIGINAL_SIZE, ORIGINAL_SHA), (LITE_SIZE, LITE_SHA)):
            return {**result, 'etat': 'apk_non_reconnu'}
        selected = configured
        original = size == ORIGINAL_SIZE
        if not original:
            for filename in ORIGINAL_NAMES:
                sibling = configured.parent / filename
                if sibling == configured or not sibling.is_file():
                    continue
                try:
                    original_size, original_sha = _fingerprint(sibling)
                    if (original_size, original_sha) == (ORIGINAL_SIZE, ORIGINAL_SHA):
                        selected = sibling
                        original = True
                        break
                except (OSError, ValueError):
                    pass
        _ALLOWED[key] = now + _COOLDOWN
        result['source'] = 'original_verifie' if original else 'lite_verifie'
        result['apk_complet_valide'] = original
        try:
            with zipfile.ZipFile(selected) as outer:
                names = outer.namelist()
                if 'base.apk' in names:
                    info = outer.getinfo('base.apk')
                    if info.file_size > _MAX_BASE:
                        raise ValueError('apk_base_trop_grand')
                    base = outer.read(info)
                elif 'AndroidManifest.xml' in names:
                    if selected.stat().st_size > _MAX_BASE:
                        raise ValueError('apk_base_trop_grand')
                    base = selected.read_bytes()
                else:
                    raise ValueError('apk_base_absent')
            dex_count, flags = _scan_base_apk(base)
            result['dex_scannes'] = min(dex_count, _MAX_DEX_COUNT)
            result['indicateurs'] = flags
            result['analyse_partielle'] = not original
            result['etat'] = 'analyse_originale_terminee' if original else 'analyse_lite_partielle'
        except (OSError, ValueError, zipfile.BadZipFile, EOFError, MemoryError):
            result['etat'] = 'archive_invalide_ou_memoire_insuffisante'
        return result
    finally:
        _LOCK.release()
