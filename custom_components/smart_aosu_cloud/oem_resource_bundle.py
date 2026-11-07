"""Read-only vendor OEM resource sidecar for the owner's known AOSU 5.10.12.

These exact hashes pin original, unmodified resources from the owner's full APK.
No keys or proprietary asset bytes are included in the integration source.
Do not log, export or publish this confidential sidecar.
"""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from .oem_preflight_b7 import APKIdentity, parse_manifest_metadata
from .native_v2 import EXPECTED_BUILD_ID

RESOURCE_FILENAME = 'Aosu_5.10.12_OEM_resources.zip'
EXPECTED_SHA = {'AndroidManifest.xml': 'bdf13c6ae42ea6acde2749f07fb93be0d9988d7f883181f4dd25483ad6e2bbab', 't_s.bmp': '56b0e2032b6540400a56f8230a032fb9b927612a7865fa94601f1077faeabcdf', 'fixed_key.bmp': '536eeb953d9549e6e868f3c7c7c25fa0305141e6ffd55f59177f6837927741c0', 'certificate.der': '5d5117645482ccd8b79fac6382d0e8f0dce75538f4578beac8ebd0c09da6ef2e', 'libthing_security_algorithm.so': 'f842bdc9c575e8c5aeeb7c939ef7dfc8be5f1bc8e2aaec3d41d3facfc85c705a'}
MAX_SIZE = 1024 * 1024


def load_verified_oem_resources(folder: Path):
    """Validate all five bytestrings, before passing them to the OEM decoder."""
    path=Path(folder) / RESOURCE_FILENAME
    if not path.is_file():
        raise FileNotFoundError('oem_resources_not_found')
    if path.stat().st_size > MAX_SIZE:
        raise ValueError('oem_resources_too_large')
    with zipfile.ZipFile(path) as z:
        if len(z.infolist()) != 5 or set(z.namelist()) != set(EXPECTED_SHA):
            raise ValueError('oem_resources_invalid_structure')
        for entry in z.infolist():
            if entry.file_size > 100000 or entry.is_dir():
                raise ValueError('oem_resources_invalid_entry')
        raw={}
        for name, expected in EXPECTED_SHA.items():
            item=z.read(name)
            if hashlib.sha256(item).hexdigest() != expected:
                raise ValueError('oem_resources_invalid_hash')
            raw[name]=item
    meta=parse_manifest_metadata(raw['AndroidManifest.xml'])
    app_id=meta.get('THING_SMART_APPKEY','')
    app_secret=meta.get('THING_SMART_SECRET','')
    if meta.get('package') != 'com.glazero.android' or len(app_id)!=20 or len(app_secret)!=32:
        raise ValueError('oem_resources_invalid_identity')
    cert=raw['certificate.der']
    if not cert or cert[0] != 0x30:
        raise ValueError('oem_resources_invalid_certificate')
    so=raw['libthing_security_algorithm.so']
    if bytes.fromhex(EXPECTED_BUILD_ID) not in so[:0x800] or so[0x679c:0x67a0] != bytes.fromhex('ff8301d1'):
        raise ValueError('oem_resources_unexpected_native')
    return (APKIdentity(app_id,app_secret,hashlib.sha256(cert).hexdigest(),
                        meta['package'],raw['t_s.bmp'],raw['fixed_key.bmp']),so)
