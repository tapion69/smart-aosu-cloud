"""Offline, no Home Assistant/no networking. Run: python -m unittest discover -s tests -v."""
from __future__ import annotations
import ast
import asyncio
from functools import partial
import json
from pathlib import Path
import runpy
import unittest

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT/'custom_components/smart_aosu_cloud'

class TestsConfigurationSansReseau(unittest.TestCase):
    def test_manifest(self):
        d=json.loads((COMP/'manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(d['version'],'0.8.13-beta2')
        self.assertEqual(d['domain'],'smart_aosu_cloud')

    def test_python_syntax(self):
        for path in COMP.rglob('*.py'):
            with self.subTest(file=path.name):
                ast.parse(path.read_text(encoding='utf-8'),filename=str(path))

    def test_inventaire_sans_fichiers_prives(self):
        paths=list(ROOT.rglob('*'))
        forbidden={'profile.json','config_entries.json'}
        suffixes={'.pcap','.pcapng','.har','.log','.apk','.apks','.key','.pem','.p12','.pfx'}
        self.assertFalse([(p.name,p.suffix) for p in paths if p.is_file() and
                          (p.name in forbidden or p.suffix.casefold() in suffixes)])

    def test_c5l_selection_generic_fail_closed(self):
        from types import SimpleNamespace
        pick=runpy.run_path(str(COMP/'live_device.py'))['select_live_camera_key']
        cameras={
            'camera_a':{'is_camera':True,'model':'C9C3CA11','name':'Vue A'},
            'camera_b':{'is_camera':True,'model':'C5L','name':'Vue B'},
            'camera_c':{'is_camera':True,'model':'C9C3CA11','name':'Vue C'},
        }
        self.assertEqual(pick(SimpleNamespace(data=cameras)),'camera_b')
        # No matching model: do not silently target the first camera.
        self.assertIsNone(pick(SimpleNamespace(data={'camera_a':cameras['camera_a']})))
        # Two matching C5Ls: no arbitrary selection.
        cameras['camera_d']={'is_camera':True,'model':'C5L','name':'Vue D'}
        self.assertIsNone(pick(SimpleNamespace(data=cameras)))
        # Missing model: requires an explicit future selection, not a local name.
        self.assertIsNone(pick(SimpleNamespace(data={'camera_a':{'is_camera':True,'model':'AOSU'}})))

    def test_h1l_ip_rfc1918(self):
        validate=runpy.run_path(str(COMP/'h1l_local_probe_b103.py'))['_validate_target']
        for value in ('10.1.2.3','172.20.2.3','192.168.10.8'):
            self.assertEqual(validate(value),value)
        for value in ('8.8.8.8','203.0.113.10','127.0.0.1','999.2.3.4'):
            with self.subTest(address=value),self.assertRaises(ValueError):validate(value)

    def test_c9_station_ip_canonical_in_worker(self):
        s=(COMP/'c9_direct_controller_b141.py').read_text()
        # Both startup paths canonicalize once and pass that value to worker and PTZ.
        self.assertEqual(s.count('self.ip_station=station_ip'),2)
        self.assertEqual(s.count('ip_station=station_ip,'),2)
        self.assertEqual(s.count('try:station_ip=_validate_target(ip_station)'),2)

    def test_c9_counters_work_on_FIRST_failure(self):
        """Exercise actual _run method in isolation with no HA and no network."""
        src=ast.parse((COMP/'c9_direct_controller_b141.py').read_text())
        cls=next(n for n in src.body if isinstance(n,ast.ClassDef) and n.name=='C9DirectControllerB141')
        fn=next(n for n in cls.body if isinstance(n,ast.AsyncFunctionDef) and n.name=='_run')
        tree=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
        calls=[]
        response={'etat':'erreur_reseau_ou_timeout','offres_0x20_envoyees':0}
        def fake_worker(*args,**kwargs):
            calls.append(1)
            return dict(response)
        ns={'asyncio':asyncio,'partial':partial,'direct_sans_capture_b145':fake_worker,
            'direct_sans_capture_b144':fake_worker,'lancer_direct_c9_b141':fake_worker}
        exec(compile(tree,str(COMP/'c9_direct_controller_b141.py'),'exec'),ns)
        class Stop:
            def is_set(self):return len(calls)>=12
            def wait(self,*args):return False
        class Preview:
            def image(self):return None
            def stop(self):return None
        class Hass:
            async def async_add_executor_job(self,fn,*args):return fn(*args)
        class Probe:
            def __init__(self):
                self.hass=Hass();self._stop=Stop();self._last={};self._etat='';self.coordinator=None
            def _save_diagnostic_b150(self,*args):pass
            def _notify(self):pass
            def _progress_worker(self,*args):pass
        test=Probe()
        asyncio.run(ns['_run'](test,{},Preview(),captureless=True,diagnostic_b145=True))
        self.assertEqual(len(calls),2)
        self.assertEqual(test._etat,'echec_tcp_avant_offre_0x20')
        # First-attempt media timeout must also be bounded without UnboundLocalError.
        calls.clear()
        response={'etat':'pas_de_media','offres_0x20_envoyees':1,'commandes_video_envoyees':1,
                  'kcp_media_authenticated_passif':0}
        test=Probe()
        asyncio.run(ns['_run'](test,{},Preview(),captureless=True,diagnostic_b145=True))
        self.assertEqual(len(calls),2)
        self.assertEqual(test._etat,'echec_demarrage_video_sans_media')

if __name__=='__main__':unittest.main()
