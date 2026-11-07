"""Offline C9C AOSU routing report — no Home Assistant or network."""
from pathlib import Path
from types import SimpleNamespace
import runpy
import unittest

ROOT=Path(__file__).resolve().parents[1]
MOD=runpy.run_path(str(ROOT/'custom_components/smart_aosu_cloud/c9c_identity_diagnostic.py'))
inspect=MOD['inspect_c9c_identity_cache']

class C9CRoutingReadOnlyTests(unittest.TestCase):
    def test_metadata_and_no_secret_leak(self):
        sn='PrivateSN99'
        row={'model':'C9C','is_camera':True,'ptz_iot_platform':'Gz',
             'ptz_tuya_reference_status':'absent'}
        client=SimpleNamespace(_standalone_c9c_sn=sn,
          _standalone_c9c_coop_id=None,
          _provider_snapshot={'appareils':[{'sdk_provider_declare_nom':'TUTK',
                                            'p2p_type_declare':2}]})
        cache={'created':1e100,'devices':{sn:{'name':'PrivateCamera',
                                                  'localKey':'PrivateLocalKey'}}}
        out=inspect(data={'a':row},client=client,cache=cache,
          select_standalone=lambda _: 'a',
          select_tuya=lambda devices,**kw:(sn,'appareil_tuya_unique_sans_categorie_video'))
        self.assertEqual(out['aosu_routage_declare']['fournisseur_p2p'],'TUTK')
        self.assertEqual(out['aosu_routage_declare']['branche_ptz'],'Gz')
        self.assertEqual(out['correspondance']['serie_egale_id_tuya_nombre'],1)
        self.assertFalse(out['correspondance']['identite_exacte_confirmee'])
        for v in (sn,'PrivateCamera','PrivateLocalKey'):
            self.assertNotIn(v,str(out))
    def test_unknown_values_not_leaked(self):
        row={'is_camera':True,'model':'C9C','ptz_iot_platform':'PRIVATE',
             'ptz_tuya_reference_status':'PRIVATE_REF'}
        client=SimpleNamespace(_standalone_c9c_sn='something',
          _standalone_c9c_coop_id=None,
          _provider_snapshot={'appareils':[{'sdk_provider_declare_nom':'PRIVATE',
                                            'p2p_type_declare':'99'}]})
        out=inspect(data={'a':row},client=client,
          cache={'devices':{'other':{'category':'gw'}}},
          select_standalone=lambda _: 'a',
          select_tuya=lambda devices,**kw:(None,'aucune_camera_tuya_identifiable'))
        self.assertEqual(out['aosu_routage_declare']['fournisseur_p2p'],'INDETERMINE')
        self.assertEqual(out['aosu_routage_declare']['p2p_type'],'absent')
        self.assertEqual(out['aosu_routage_declare']['branche_ptz'],'indeterminee')
        self.assertNotIn('PRIVATE_REF',str(out))
    def test_no_network_when_cache_absent(self):
        client=SimpleNamespace(_standalone_c9c_sn='a',_standalone_c9c_coop_id=None)
        out=inspect(data={'a':{'is_camera':True,'model':'C9C'}},
          client=client,cache=None,
          select_standalone=lambda _: 'a',select_tuya=lambda *a,**k: (None,'none'))
        self.assertEqual(out['appels_reseau'],0)
        self.assertEqual(out['commandes_camera'],0)

if __name__=='__main__':unittest.main()
