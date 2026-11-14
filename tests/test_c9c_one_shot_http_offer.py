"""Synthetic tests for the ONE C9C native HTTP offer, no HA, APK or network."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
source=ROOT/"custom_components"/"smart_aosu_cloud"/"c9c_thing4_http_once.py"
spec=importlib.util.spec_from_file_location("c9c_thing4_http_once_test",source)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TARGET="tuya_single_cam_001"
SERIAL="AOSU_C9C_SN_001"
UID="private_uid_001"
SDP="v=0\r\nm=application 9 imm 6001\r\na=rtpmap:6001 AES/KCP 330\r\n"


def device(**kwargs):
    return {TARGET:{"devId":TARGET,"uuid":"anonymous-test",**kwargs}}


def offer():
    return {
        "header":{"type":"offer","from":UID,"to":TARGET,
                  "sessionid":"rtc_session_001","moto_id":"","path":"mqtt",
                  "trace_id":"trace_001","is_pre":0,
                  "p2p_skill":1635,"security_level":3},
        "msg":{"sdp":SDP,"token":[{"url":"synthetic_stun"}],
               "tcp_token":{"sessionId":"synthetic_tcp"},
               "log":{},"preconnect":True}
    }


class OneShotHttpTests(unittest.TestCase):
    def test_manual_unique_target_requires_explicit_permission(self):
        got,reason=module.manual_target_gate(
            device(),aosu_sn=SERIAL,typed_target=TARGET,
            typed_selection="appareil_tuya_unique_sans_categorie_video",
            allow_one_unproven=False)
        self.assertIsNone(got)
        self.assertEqual(reason,"liaison_aosu_tuya_non_prouvee")
        got,reason=module.manual_target_gate(
            device(),aosu_sn=SERIAL,typed_target=TARGET,
            typed_selection="appareil_tuya_unique_sans_categorie_video",
            allow_one_unproven=True)
        self.assertEqual(got,TARGET)
        self.assertEqual(reason,"candidat_unique_autorise_manuellement")

    def test_manual_rejects_multiple_or_conflicting_targets(self):
        multi=device()
        multi["another_tuya_002"]={"devId":"another_tuya_002"}
        self.assertIsNone(module.manual_target_gate(
            multi,aosu_sn=SERIAL,typed_target=TARGET,
            typed_selection="appareil_tuya_unique_sans_categorie_video",
            allow_one_unproven=True)[0])
        self.assertIsNone(module.manual_target_gate(
            device(deviceId="OTHER_001"),aosu_sn=SERIAL,typed_target=TARGET,
            typed_selection="not_exact",allow_one_unproven=True)[0])

    def test_manual_rejects_non_video_and_missing_aosu_sn(self):
        self.assertIsNone(module.manual_target_gate(
            device(category="socket"),aosu_sn=SERIAL,typed_target=TARGET,
            typed_selection="not_exact",allow_one_unproven=True)[0])
        self.assertIsNone(module.manual_target_gate(
            device(),aosu_sn=None,typed_target=TARGET,
            typed_selection="not_exact",allow_one_unproven=True)[0])

    def test_exact_typed_identity_does_not_require_weak_fallback(self):
        target,proof=module.manual_target_gate(
            device(),aosu_sn=SERIAL,typed_target=TARGET,
            typed_selection="identite_exacte_ty_cp_uuid",
            allow_one_unproven=False)
        self.assertEqual(target,TARGET)
        self.assertEqual(proof,"identite_typée")

    def test_type4_requires_exact_device_id_in_same_camera_info(self):
        rtc={"data":{"result":{"id":TARGET,"p2pSpecifiedType":4,
                               "p2pConfig":{"session":{"sessionId":"test"}}}}}
        self.assertTrue(module.validate_type4_rtc(rtc,TARGET))
        rtc["data"]["result"]["id"]="wrong_device_002"
        self.assertFalse(module.validate_type4_rtc(rtc,TARGET))
        rtc["data"]["result"]["id"]=TARGET
        rtc["data"]["result"]["p2pSpecifiedType"]=2
        self.assertFalse(module.validate_type4_rtc(rtc,TARGET))

    def test_type4_does_not_accept_nested_relay_id_as_camera_id(self):
        rtc={"data":{"p2pSpecifiedType":4,
                     "p2pConfig":{"session":{"id":TARGET}}}}
        self.assertFalse(module.validate_type4_rtc(rtc,TARGET))

    def test_http_json_matches_native_inner_post_data_only(self):
        body=module.native_http_form(offer(),target=TARGET)
        self.assertEqual(set(body),{"header","msg"})
        self.assertEqual(body["header"]["to"],TARGET)
        self.assertNotIn("devId",body)
        self.assertNotIn("path",body["header"])
        self.assertNotIn("security_level",body["header"])
        self.assertEqual(set(body["header"]), {
            "from", "to", "sessionid", "moto_id", "type",
            "trace_id", "is_pre", "p2p_skill",
        })
        self.assertNotIn("preconnect",body["msg"])
        self.assertNotIn("udp_token",body["msg"])
        self.assertEqual(body["msg"]["sdp"],SDP)
        self.assertEqual(module._HTTP_ACTION,"thing.m.rtc.session.offer")
        self.assertEqual(module._HTTP_VERSION,"1.0")

    def test_http_rejects_wrong_target_or_skill(self):
        with self.assertRaises(ValueError):
            module.native_http_form(offer(),target="wrong_target_002")
        altered=offer();altered["header"]["p2p_skill"]=5
        with self.assertRaises(ValueError):
            module.native_http_form(altered,target=TARGET)

    def test_http_rejects_no_sdp_or_transport(self):
        altered=offer();altered["msg"]["sdp"]="garbage"
        with self.assertRaises(ValueError):
            module.native_http_form(altered,target=TARGET)
        altered=offer();del altered["msg"]["tcp_token"]
        with self.assertRaises(ValueError):
            module.native_http_form(altered,target=TARGET)

    def test_http_result_never_exports_identity_or_secrets(self):
        result=module.safe_http_result({
            "serveur_accepte":True,"rejet_explicite":False,
            "devId":TARGET,"raw_sdp":SDP,"access_key":"secret"})
        self.assertTrue(result["serveur_accepte"])
        self.assertTrue(result["requete_http_effectuee"])
        self.assertFalse(result["video_lancee"])
        self.assertFalse(result["identifiants_retournes"])
        self.assertNotIn(TARGET,json.dumps(result))
        self.assertNotIn('"access_key"',json.dumps(result))

    def test_http_refusal_is_fixed_category_not_raw_remote_text(self):
        remote="PRIVATE_ERROR_HAS_SECRET_AND_USER_IDENTIFIERS"
        result=module.safe_http_result({
            "serveur_accepte":False,"rejet_explicite":True,
            "categorie_refus":"parametres",
            "code_erreur_present":True,"raw_response":remote})
        self.assertEqual(result["categorie_refus"],"parametres")
        self.assertTrue(result["code_erreur_present"])
        self.assertNotIn(remote,str(result))
        result=module.safe_http_result({
            "rejet_explicite":True,"categorie_refus":remote})
        self.assertEqual(result["categorie_refus"],"non_applicable")

    def test_http_explicit_rejection_precedes_acceptance(self):
        result=module.safe_http_result({
            "serveur_accepte":True,"rejet_explicite":True})
        self.assertEqual(result["etat"],"offre_http_refusee")
        self.assertFalse(result["serveur_accepte"])


if __name__=="__main__":
    unittest.main()
