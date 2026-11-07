"""Video C9C regression tests without Home Assistant, camera, or network."""
from pathlib import Path
import ast
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / 'custom_components/smart_aosu_cloud'
TOPO = runpy.run_path(str(COMP/'camera_topology.py'))


class C9CAutonomeTests(unittest.TestCase):
    def test_no_fake_h1l_for_standalone(self):
        c9 = {'is_camera':True, 'model':'C9C', 'name':'Vue exterieure', 'via_device':None}
        data = {'a':c9}
        self.assertFalse(TOPO['has_h1l_video_topology'](data))
        self.assertEqual(TOPO['select_standalone_c9c_key'](data),'a')
        for extra in [
            {'a':c9,'b':{'model':'H1L','is_camera':False}},
            {'a':c9,'b':{'model':'C5L','is_camera':True}},
            {'a':{'is_camera':True,'model':'C9C','via_device':'base'}}
        ]:
            self.assertIsNone(TOPO['select_standalone_c9c_key'](extra))
        self.assertIsNone(TOPO['select_standalone_c9c_key']({'a':{'model':'C9C3CA11','is_camera':True}}))
        self.assertIsNone(TOPO['select_standalone_c9c_key']({'a':{'model':'AOSU','is_camera':True}}))

    def test_legacy_h1l_still_present_with_station(self):
        data={'base':{'model':'H1L','is_camera':False},
              'a':{'model':'C9C3CA11','is_camera':True,'via_device':'base'},
              'b':{'model':'C9C3CA11','is_camera':True,'via_device':'base'}}
        self.assertTrue(TOPO['has_h1l_video_topology'](data))
        self.assertIsNone(TOPO['select_standalone_c9c_key'](data))
        camera=(COMP/'camera.py').read_text()
        self.assertIn('if has_h1l_video_topology(coordinator.data)',camera)
        self.assertIn('SmartAosuStandaloneC9CPreview',camera)

    def test_tuya_strong_identity_and_strict_fallback(self):
        choose=TOPO['select_tuya_standalone_target']
        matched={'a':{'devId':'dev_alpha','productBean':{'category':'sp'}},
                 'b':{'devId':'dev_beta','productBean':{'category':'ipc'}}}
        self.assertEqual(choose(matched,camera_sn=None,camera_coop='dev_beta'),
                         ('b','identite_exacte'))
        self.assertEqual(choose(matched,camera_sn=None,camera_coop='wrong')[0],None)
        self.assertEqual(choose({'a':{'productBean':{'category':'sp'}}},camera_sn=None,camera_coop=None),
                         ('a','camera_tuya_unique_non_confirmee'))
        self.assertIsNone(choose({'a':{'name':'unrelated'}},camera_sn=None,camera_coop=None)[0])
        # A single explicit IPC remains safe even with additional non-camera devices.
        devices={'a':{'productBean':{'category':'switch'}},
                 'b':{'productBean':{'category':'sp'}},
                 'c':{'category':'gw'}}
        self.assertEqual(choose(devices,camera_sn=None,camera_coop=None),
                         ('b','camera_tuya_unique_non_confirmee'))
        # Never silently select when multiple camera-category devices exist.
        both={'a':{'productBean':{'category':'sp'}},'b':{'category':'ipc'},'c':{'category':'gw'}}
        self.assertEqual(choose(both,camera_sn=None,camera_coop=None),
                         (None,'cameras_tuya_multiples_ambigues'))
        self.assertEqual(choose({'a':{'category':'gw'},'b':{'category':'switch'}},
                                camera_sn=None,camera_coop=None),
                         (None,'aucune_camera_tuya_identifiable'))
        self.assertIsNone(choose({'a':{'sn':'same'},'b':{'sn':'same'}},camera_sn='same',camera_coop=None)[0])


    def test_one_tuya_device_without_camera_category_for_manual_video(self):
        """Observed external install: one C9C, one Tuya device, no IPC category.

        The weak match cannot run without an AOSU camera SN or if the sole
        Tuya device self-identifies as a non-video device. It does not select
        anything when the Tuya account contains multiple unclassified devices.
        """
        choose=TOPO['select_tuya_standalone_target']
        alone={'opaque':{'devId':'opaque','localKey':'not-a-real-key'}}
        self.assertEqual(choose(alone,camera_sn='one-c9c-sn',camera_coop=None),
                         ('opaque','appareil_tuya_unique_sans_categorie_video'))
        self.assertEqual(choose({'opaque':{'category':'new-camera-category'}},
                         camera_sn='one-c9c-sn',camera_coop=None),
                         ('opaque','appareil_tuya_unique_sans_categorie_video'))
        self.assertEqual(choose(alone,camera_sn=None,camera_coop=None),
                         (None,'aucune_camera_tuya_identifiable'))
        self.assertEqual(choose({'x':{'localKey':'x'},'y':{'localKey':'y'}},
                         camera_sn='one-c9c-sn',camera_coop=None),
                         (None,'aucune_camera_tuya_identifiable'))
        for non_video in ('gw','gateway','hub','switch','socket','sensor','light','cz','kg','dj'):
            self.assertEqual(choose({'x':{'productBean':{'category':non_video}}},
                             camera_sn='one-c9c-sn',camera_coop=None),
                             (None,'appareil_tuya_unique_categorie_non_video'))
        self.assertEqual(choose({'a':None},camera_sn='one-c9c-sn',camera_coop=None),
                         (None,'appareil_tuya_unique_invalide'))
        self.assertEqual(choose({'a':{'category':'gw','deviceId':'exact-coop'}},
                         camera_sn='one-c9c-sn',camera_coop='exact-coop'),
                         ('a','identite_exacte'))

    def test_manual_video_only_path_and_no_ptz_card(self):
        init=(COMP/'__init__.py').read_text()
        service_name='demarrer_video_c9c_autonome_beta'
        self.assertIn(service_name,init)
        self.assertIn('confirmation_camera_c9c_autonome',init)
        self.assertIn('confirmation_envoi_mot_de_passe',init)
        js=(COMP/'frontend/c9c-autonome-b1.js').read_text()
        self.assertIn(service_name,js)
        self.assertNotIn('ptz_maintien',js)
        self.assertNotIn('data-dir',js)
        stream=(COMP/'tuya_live_preview.py').read_text()
        self.assertIn('standalone_c9c_video_test=self._standalone_video_test_mode',stream)
        route=(COMP/'tuya_rtc_inventory.py').read_text()
        self.assertIn('select_tuya_standalone_target',route)
        # Only the explicit start method may choose a standalone candidate.
        self.assertIn('if standalone_c9c_video_test:',route)
        self.assertIn('if standalone_c9c_video_test and not interactive_live:',route)
        self.assertIn("out['cameras_tuya_categorie_video']",route)
        self.assertIn("'methode_selection_rtc':report.get",stream)
        self.assertIn('cameras_tuya_categorie_video',js)

    def test_grammar_and_safety(self):
        for p in COMP.glob('*.py'):
            with self.subTest(p=p.name):
                ast.parse(p.read_text(encoding='utf-8'))
        text=(COMP/'__init__.py').read_text()
        self.assertNotIn("self._c5l_sn = self._standalone_c9c_sn",text)


if __name__=='__main__': unittest.main()
