"""No network, no Home Assistant, no APK/credentials: test new installer only."""
import ast
import json
import os
from pathlib import Path
import runpy
import tempfile
import types
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / 'custom_components/smart_aosu_cloud'

class InstallationTests(unittest.TestCase):
    def test_bootstrap_stable_without_leak(self):
        ensure = runpy.run_path(str(COMP/'profile_bootstrap.py'))['ensure_profile']
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'smart_aosu_cloud/profile.json'
            self.assertFalse(path.exists())
            ensure(path)
            original = path.read_bytes()
            obj=json.loads(original)
            self.assertEqual(obj['version'], 1)
            self.assertEqual(set(obj['android_properties']),{'Gz-OsVer','Gz-Brand','Gz-Model','Gz-FontSize'})
            self.assertEqual(set(obj['additional_headers']),{'Gz-Imei','Gz-Network','Gz-NotifyPermission'})
            self.assertEqual(len(obj['additional_headers']['Gz-Imei']),16)
            self.assertEqual(int(obj['additional_headers']['Gz-Imei'],16)>=0, True)
            self.assertNotIn('password',repr(obj).lower())
            self.assertEqual(os.stat(path).st_mode & 0o777,0o600)
            ensure(path)
            self.assertEqual(path.read_bytes(), original)

    def test_existing_user_profile_never_overwritten(self):
        ensure=runpy.run_path(str(COMP/'profile_bootstrap.py'))['ensure_profile']
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'profile.json'
            path.write_text('user_data')
            ensure(path)
            self.assertEqual(path.read_text(),'user_data')

    def test_rfc1918_only_and_optional(self):
        validate=runpy.run_path(str(COMP/'network_config.py'))['optional_station_ip']
        self.assertEqual(validate(''), '')
        self.assertEqual(validate(None), '')
        for v in ('10.0.0.2','172.31.6.40','192.168.2.150'):
            self.assertEqual(validate(v),v)
        for v in ('8.8.8.8','127.0.0.1','169.254.1.1','192.0.2.10','192.168.001.50','192.168.1.1 ','::1','invalid',123):
            with self.subTest(v=v),self.assertRaises(ValueError):validate(v)

    def test_service_ip_resolution(self):
        source=ast.parse((COMP/'__init__.py').read_text())
        setup=next(x for x in source.body if isinstance(x,ast.AsyncFunctionDef) and x.name=='async_setup')
        inner=next(x for x in setup.body if isinstance(x,ast.FunctionDef) and x.name=='_station_ip_for_call')
        code=compile(ast.fix_missing_locations(ast.Module(body=[inner],type_ignores=[])),'<isolated>','exec')
        validate=runpy.run_path(str(COMP/'network_config.py'))['optional_station_ip']
        data=types.SimpleNamespace(options={'station_ip':'192.168.10.33'},data={'station_ip':'192.168.20.11'})
        entries=[data]
        hass=types.SimpleNamespace(config_entries=types.SimpleNamespace(async_entries=lambda d: entries))
        ns={'hass':hass,'DOMAIN':'smart_aosu_cloud','CONF_STATION_IP':'station_ip','optional_station_ip':validate}
        exec(code,ns)
        f=ns['_station_ip_for_call']
        self.assertEqual(f(types.SimpleNamespace(data={})), '192.168.10.33')
        self.assertEqual(f(types.SimpleNamespace(data={'ip_station':'10.1.2.3'})), '10.1.2.3')
        entries.append(types.SimpleNamespace(options={},data={}))
        self.assertIsNone(f(types.SimpleNamespace(data={})))

if __name__=='__main__':unittest.main()
