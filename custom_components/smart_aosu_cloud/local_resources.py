"""Private, user-provided AOSU 5.10.12 resources for the HA config flow.

Never bundle, expose, upload to a third party, or log any vendor bytes.
The uploaded file identifiers are transient Home Assistant file_upload IDs.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile
import zipfile

from .const import APK_PATH
from .oem_resource_bundle import RESOURCE_FILENAME, load_verified_oem_resources
from . import protocol_060 as protocol

APK_FILENAME = APK_PATH.name
APK_MAX_BYTES = 10 * 1024 * 1024
OEM_MAX_BYTES = 1024 * 1024


class ResourceImportError(ValueError):
    """Known, translated import error. Do not expose low-level exception text."""


def _validate_apk(path: Path) -> None:
    if not path.is_file() or not (1024 <= path.stat().st_size <= APK_MAX_BYTES):
        raise ResourceImportError("invalid_apk")
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) != 2 or {m.filename for m in members} != {
                "base.apk", "split_config.arm64_v8a.apk"
            }:
                raise ResourceImportError("invalid_apk")
            # Our Lite bundle has two small nested APKs, not a full application.
            if any(m.is_dir() or m.file_size > 8 * 1024 * 1024 or m.compress_size == 0 for m in members):
                raise ResourceImportError("invalid_apk")
        native, dex = protocol.read_apk_parts(path)
        protocol.get_sign_suffix(dex)
        material = native[protocol.KEY_OFFSET:protocol.KEY_OFFSET + 16]
        if len(material) != 16 or protocol.check_vectors(material) != (4, 4):
            raise ResourceImportError("invalid_apk")
    except ResourceImportError:
        raise
    except (OSError, ValueError, RuntimeError, KeyError, IndexError, zipfile.BadZipFile) as err:
        raise ResourceImportError("invalid_apk") from err


def _validate_oem(path: Path) -> None:
    if not path.is_file() or not (1024 <= path.stat().st_size <= OEM_MAX_BYTES):
        raise ResourceImportError("invalid_oem")
    if path.name != RESOURCE_FILENAME:
        raise ResourceImportError("invalid_oem")
    try:
        load_verified_oem_resources(path.parent)
    except (OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile) as err:
        raise ResourceImportError("invalid_oem") from err


def resources_ready() -> bool:
    """Check existing files before showing the account form; no network calls."""
    try:
        _validate_apk(APK_PATH)
        _validate_oem(APK_PATH.parent / RESOURCE_FILENAME)
    except ResourceImportError:
        return False
    return True


def _copy_upload(src: Path, dst: Path, upper_bound: int) -> None:
    try:
        size = src.stat().st_size
    except OSError as err:
        raise ResourceImportError("missing_files") from err
    if size > upper_bound or size < 1024:
        raise ResourceImportError("invalid_apk" if upper_bound == APK_MAX_BYTES else "invalid_oem")
    with src.open("rb") as reader, dst.open("xb") as output:
        os.chmod(dst, 0o600)
        shutil.copyfileobj(reader, output, length=256 * 1024)
    if dst.stat().st_size != size:
        raise ResourceImportError("cannot_store")


def _install_from_paths(apk_upload: Path, oem_upload: Path) -> None:
    """Validate both in staging, then replace files with rollback on I/O errors."""
    target = APK_PATH.parent
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".smart_aosu_import_", dir=target.parent) as tmp:
        stage = Path(tmp)
        apk_stage = stage / APK_FILENAME
        oem_stage = stage / RESOURCE_FILENAME
        _copy_upload(apk_upload, apk_stage, APK_MAX_BYTES)
        _copy_upload(oem_upload, oem_stage, OEM_MAX_BYTES)
        _validate_apk(apk_stage)
        _validate_oem(oem_stage)
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        copies = {}
        installed = []
        try:
            for filename in (APK_FILENAME, RESOURCE_FILENAME):
                destination = target / filename
                if destination.exists():
                    backup = stage / (filename + ".backup")
                    shutil.copy2(destination, backup)
                    copies[filename] = backup
                else:
                    copies[filename] = None
            for filename in (APK_FILENAME, RESOURCE_FILENAME):
                os.replace(stage / filename, target / filename)
                installed.append(filename)
        except OSError as err:
            for filename in reversed(installed):
                destination = target / filename
                backup = copies[filename]
                if backup is not None:
                    os.replace(backup, destination)
                else:
                    destination.unlink(missing_ok=True)
            raise ResourceImportError("cannot_store") from err


def import_ha_uploads(hass, apk_id: str, oem_id: str) -> None:
    """Synchronous executor callback; consume HA temporary files exactly once."""
    if not isinstance(apk_id, str) or not isinstance(oem_id, str) or apk_id == oem_id:
        raise ResourceImportError("missing_files")
    from homeassistant.components.file_upload import process_uploaded_file
    try:
        with process_uploaded_file(hass, apk_id) as apk_upload:
            with process_uploaded_file(hass, oem_id) as oem_upload:
                # Paths are assigned by HA; never trust browser filenames or paths.
                _install_from_paths(apk_upload, oem_upload)
    except ResourceImportError:
        raise
    except (OSError, ValueError, KeyError) as err:
        raise ResourceImportError("missing_files") from err
