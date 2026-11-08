"""Offline tests of privacy-preserving C9C moto_id resolution and routing."""
import ast
import runpy
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'custom_components'/'smart_aosu_cloud'
NS=runpy.run_path(str(BASE/'c9c_moto_signal.py'))
resolve=NS['resolve_rtc_moto_id']

class MotoIdSafetyTests(unittest.TestCase):
    def test_unique_moto_in_trusted_rtc_path(self):
        rtc={'data':{'p2pConfig':{'session':{'moto_id':'SECRET_MOTO'}}}}
        value,source=resolve(rtc)
        self.assertEqual(value,'SECRET_MOTO')
        self.assertEqual(source,'p2p_session')
        self.assertNotIn('SECRET_MOTO',source)

    def test_multiple_values_fail_closed(self):
        rtc={'data':{'moto_id':'SECRET_ONE',
                       'p2pConfig':{'session':{'motoId':'SECRET_TWO'}}}}
        self.assertEqual(resolve(rtc),('','valeurs_ambigues'))

    def test_no_generic_walk_and_no_unsafe_values(self):
        self.assertEqual(resolve({'data':{'unknown':{'motoId':'SECRET'}}}),
                         ('','champ_non_resolu'))
        self.assertEqual(resolve({'moto_id':'\nBAD'}),('','champ_non_resolu'))
        self.assertEqual(resolve({'moto_id':'A'*129}),('','champ_non_resolu'))

    def test_manual_only_no_change_to_c5l_h1l(self):
        src=(BASE/'tuya_rtc_inventory.py').read_text(encoding='utf-8')
        offer=(BASE/'tuya_mqtt_offer.py').read_text(encoding='utf-8')
        self.assertIn('if standalone_c9c_video_test:',src)
        self.assertIn('use_standalone_c9c_moto_id=(standalone_c9c_video_test is True)',src)
        self.assertIn('use_moto_id=(interactive_live and use_standalone_c9c_moto_id is True)',offer)
        self.assertIn("moto_id=offer['header']['moto_id']",offer)
        self.assertNotIn('ptz_maintien', (BASE/'frontend/c9c-autonome-b1.js').read_text())
        for f in ('tuya_mqtt_offer.py','tuya_rtc_inventory.py','tuya_media_bootstrap.py'):
            ast.parse((BASE/f).read_text(encoding='utf-8'))

if __name__=='__main__':
    unittest.main()
