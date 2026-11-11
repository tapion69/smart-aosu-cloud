"""Offline tests of B37 SDK prerequisite report and fail-closed guard."""
import ast
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'custom_components'/'smart_aosu_cloud'
SRC=(BASE/'c9c_sdk_preflight_b37.py').read_text(encoding='utf8')
TREE=ast.parse(SRC)
FUNCS=[n for n in TREE.body if isinstance(n,ast.FunctionDef)]
N={'Any':object}
exec(compile(ast.Module(body=FUNCS,type_ignores=[]),'<offline>','exec'),N)
AUDIT=N['summarize_native_prerequisites_b37']
TARGET='FAKE_TUYA_ID'
DETAIL={'data':{'devId':TARGET,'skills':{'p2pType':4},'localKey':'PRIVATE_KEY'}}
INVENTORY={'devId':TARGET,'skills':{'p2pType':4}}
RTC={'data':{'p2pConfig':{'session':{'sessionId':'PRIVATE_SESSION',
                                   'aesKey':'PRIVATE_AES'}},
             'sessionTid':'PRIVATE_TRACE','p2pPolicy':'PRIVATE_POLICY',
             'p2pId':'PRIVATE_P2P_ID'}}

class TestNativeSDKPreflightB37(unittest.TestCase):
    def report(self,device=INVENTORY,detail=DETAIL,rtc=RTC,
               accepted_detail=True,accepted_rtc=True):
        return AUDIT(tuya_device=device,tuya_detail=detail,rtc_response=rtc,
                     expected_tuya_id=TARGET,detail_accepted=accepted_detail,
                     rtc_accepted=accepted_rtc)

    def test_exact_thing_sdk_metadata_without_claiming_camera_or_video(self):
        r=self.report()
        self.assertEqual(r['etat'],'lectures_obtenues')
        self.assertTrue(r['fiche_tuya_memes_identifiants'])
        self.assertTrue(r['type_p2p_thing4_present'])
        self.assertTrue(r['cle_locale_presente'])
        self.assertTrue(r['p2p_config_structure_presente'])
        self.assertTrue(r['p2p_policy_champ_present'])
        self.assertTrue(r['session_tid_champ_present'])
        self.assertTrue(r['p2p_id_champ_present'])
        for key in ('android_devicebean_reproduit','native_sdk_initialized',
                    'parite_binaire_validee','liaison_aosu_tuya_prouvee',
                    'video_autorisee','identifiants_retournes','secrets_retournes'):
            self.assertFalse(r[key])
        self.assertEqual(r['offres_mqtt_envoyees'],0)
        self.assertEqual(r['commandes_camera'],0)
        self.assertEqual(r['commandes_ptz'],0)
        for secret in ('PRIVATE_KEY','PRIVATE_SESSION','PRIVATE_AES',
                       'PRIVATE_TRACE','PRIVATE_POLICY','PRIVATE_P2P_ID',TARGET):
            self.assertNotIn(secret,json.dumps(r))

    def test_missing_sdk_account_metadata_visible_but_never_synthesized(self):
        r=self.report(device={'devId':TARGET},
                      detail={'data':{'devId':TARGET,'skills':{'p2pType':4}}},
                      rtc={'data':{'session':{'iceUfrag':'PRIVATE'}}})
        self.assertTrue(r['type_p2p_thing4_present'])
        self.assertFalse(r['cle_locale_presente'])
        self.assertFalse(r['product_bean_present'])
        self.assertFalse(r['categorie_camera_sp_presente'])
        self.assertFalse(r['p2p_config_structure_presente'])
        self.assertFalse(r['session_tid_champ_present'])
        self.assertFalse(r['video_autorisee'])

    def test_wrong_target_or_refused_api_never_forges_device_proof(self):
        r=self.report(detail={'data':{'devId':'OTHER_DEVICE',
                                      'skills':{'p2pType':4}}},
                      accepted_rtc=False)
        self.assertEqual(r['etat'],'lectures_partielles')
        self.assertFalse(r['fiche_tuya_memes_identifiants'])
        self.assertFalse(r['rtc_ipc_v4_accepte'])
        self.assertFalse(r['p2p_config_structure_presente'])
        self.assertFalse(r['liaison_aosu_tuya_prouvee'])

    def test_integration_read_only_manual_gate(self):
        path=(BASE/'tuya_rtc_inventory.py').read_text(encoding='utf8')
        self.assertIn('if standalone_c9c_sdk_b37_audit and (',path)
        self.assertIn('or tester_mqtt or tester_offre_mqtt',path)
        self.assertIn('read(\'thing.m.device.get\',',path)
        self.assertIn('read(\'m.ipc.v4.rtc.config.get\',',path)
        self.assertIn("'sdk_b37_lecture_seule_uniquement'",path)
        self.assertNotIn('print(',SRC)


if __name__=='__main__':unittest.main()
