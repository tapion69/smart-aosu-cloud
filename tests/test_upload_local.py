"""Offline tests of a realistic HA FileSelector upload and atomic resource storage."""
from __future__ import annotations
import asyncio
from contextlib import contextmanager
import importlib
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT / 'custom_components/smart_aosu_cloud'
FIXTURE=Path('/mnt/data/files')
APK=FIXTURE/'Aosu_5.10.12_21839.apks(1).apk'
OEM=FIXTURE/'Aosu_5.10.12_OEM_resources.zip'

class UploadedResources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not APK.exists() or not OEM.exists():
            raise unittest.SkipTest('Local validation fixtures unavailable')
        pkg=types.ModuleType('smart_aosu_cloud')
        pkg.__path__=[str(COMP)]
        sys.modules['smart_aosu_cloud']=pkg
        cls.module=importlib.import_module('smart_aosu_cloud.local_resources')

    def test_reference_files_and_own_directory(self):
        imp=self.module
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'smart_aosu_cloud/aosu_vendor_app.apk'
            with patch.object(imp,'APK_PATH',path):
                self.assertFalse(imp.resources_ready())
                imp._install_from_paths(APK,OEM)
                self.assertTrue(imp.resources_ready())
                self.assertEqual(path.read_bytes(),APK.read_bytes())
                self.assertEqual((path.parent/'Aosu_5.10.12_OEM_resources.zip').read_bytes(),OEM.read_bytes())
                # Files stored with restricted permissions.
                self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_malformed_apk_keeps_old_files(self):
        imp=self.module
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'smart_aosu_cloud/aosu_vendor_app.apk'
            with patch.object(imp,'APK_PATH',path):
                imp._install_from_paths(APK,OEM)
                existing=path.read_bytes()
                other=path.parent/'Aosu_5.10.12_OEM_resources.zip'
                existing_oem=other.read_bytes()
                fake=Path(folder)/'bad.apk'
                fake.write_bytes(b'B'*1024)
                with self.assertRaises(imp.ResourceImportError) as info:
                    imp._install_from_paths(fake, OEM)
                self.assertEqual(str(info.exception),'invalid_apk')
                self.assertEqual(path.read_bytes(),existing)
                self.assertEqual(other.read_bytes(),existing_oem)

    def test_corrupted_oem_is_rejected(self):
        imp=self.module
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'smart_aosu_cloud/aosu_vendor_app.apk'
            bad=Path(folder)/'bad.zip'
            bad.write_bytes(b'B'*1024)
            with patch.object(imp,'APK_PATH',path), self.assertRaises(imp.ResourceImportError) as info:
                imp._install_from_paths(APK,bad)
            self.assertEqual(str(info.exception),'invalid_oem')
            self.assertFalse(path.exists())

    def test_ha_file_id_is_consumed_via_approved_api(self):
        imp=self.module
        @contextmanager
        def process_uploaded_file(hass,file_id):
            yield {'abcd1234': APK,'efgh1234':OEM}[file_id]
        fake=types.ModuleType('homeassistant')
        fake.__path__=[]
        components=types.ModuleType('homeassistant.components')
        components.__path__=[]
        upload=types.ModuleType('homeassistant.components.file_upload')
        upload.process_uploaded_file=process_uploaded_file
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'smart_aosu_cloud/aosu_vendor_app.apk'
            with patch.dict(sys.modules,{'homeassistant':fake,'homeassistant.components':components,'homeassistant.components.file_upload':upload}):
                with patch.object(imp,'APK_PATH',path):
                    imp.import_ha_uploads(object(),'abcd1234','efgh1234')
                    self.assertTrue(imp.resources_ready())
            # Security: duplicate file identifiers fail closed.
            with self.assertRaises(imp.ResourceImportError):
                imp.import_ha_uploads(None,'same','same')

if __name__=='__main__':unittest.main()
