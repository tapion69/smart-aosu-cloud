"""No-network C9C media proof regression: actual relay ≠ native P2P ≠ JPEG."""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "custom_components" / "smart_aosu_cloud"
P = BASE / "c9c_thing4_mqtt_evidence.py"
spec = importlib.util.spec_from_file_location("c9c_media_proofs_offline",P)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)

CAM="PRIVATE_DEVICE_FOR_TESTS"
USER="PRIVATE_USER_FOR_TESTS"
SID="PRIVATE_SESSION_FOR_TESTS"
SDP=("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n"
     "m=application 9 imm 6001\r\na=rtpmap:6001 AES/KCP 330\r\n"
     "a=ice-ufrag:fake\r\na=ice-pwd:fake\r\n")


def monitor(answer=True):
    monitor = m.C9CMqttSessionEvidence(CAM,USER,SID)
    monitor.mark_offer_sent()
    if answer:
        response = monitor.classify(302, {
            "type":"answer","from":CAM,"to":USER,"sessionid":SID
        },{"sdp":SDP})
        assert response=="reponse_sdp_liee_a_notre_session"
    return monitor


def relay(*,signed=True, video=True, encrypted=2,decrypted=2,
          complete_jpeg=False):
    return {
      "relais_signature_verifiee":signed,
      "relais_handshake_termine":signed,
      "kcp":{
         "conversation_video_detectee":video,
         "media_start":{
             "conversation_video_detectee":video,
             "paquets_video_chiffres_recus":encrypted,
             "paquets_video_dechiffres":decrypted,
             "image_jpeg_complete_detectee":complete_jpeg
         }
      }
    }


class TestC9CMediaProofs(unittest.TestCase):
    def test_absent_media_stays_signaling_only(self):
        status=monitor().summarize_existing_relay(None)
        self.assertEqual(status["phase_observee"],"reponse_sdp_validee")
        self.assertFalse(status["relais_tcp_authentifie"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_relay_handshake_is_not_camera_p2p(self):
        status=monitor().summarize_existing_relay(relay(video=False,encrypted=0,decrypted=0))
        self.assertEqual(status["phase_observee"],"relais_tcp_authentifie")
        self.assertTrue(status["relais_tcp_authentifie"])
        self.assertFalse(status["connexion_native_thing4_authentifiee"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_kcp_video_channel_is_not_media(self):
        status=monitor().summarize_existing_relay(relay(encrypted=0,decrypted=0))
        self.assertEqual(status["phase_observee"],"canal_kcp_video_observe")
        self.assertTrue(status["canal_video_kcp_observe"])
        self.assertFalse(status["paquets_video_dechiffres_observes"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_media_decrypted_is_not_jpeg_decoded(self):
        status=monitor().summarize_existing_relay(relay(),decoded_jpeg_delta=0)
        self.assertEqual(status["phase_observee"],"video_dechiffree_sans_image")
        self.assertTrue(status["paquets_video_dechiffres_observes"])
        self.assertFalse(status["nouvelle_image_preview_decodee"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_jpeg_complete_from_media_is_not_preview_frame(self):
        status=monitor().summarize_existing_relay(relay(complete_jpeg=True))
        self.assertTrue(status["jpeg_complet_en_memoire_detecte"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_newly_decoded_preview_image_is_positive_only_with_full_evidence(self):
        status=monitor().summarize_existing_relay(relay(complete_jpeg=True),
                                                   decoded_jpeg_delta=1)
        self.assertEqual(status["phase_observee"],"image_preview_decodee")
        self.assertTrue(status["video_visible_confirmee"])
        self.assertFalse(status["connexion_native_thing4_authentifiee"])
        self.assertTrue(status["nouvelle_image_preview_decodee"])

    def test_wrong_old_session_sdp_does_not_prove_video(self):
        status=monitor(answer=False).summarize_existing_relay(relay(),
                                                               decoded_jpeg_delta=5)
        self.assertFalse(status["nouvelle_image_preview_decodee"])
        self.assertFalse(status["video_visible_confirmee"])
        self.assertFalse(status["reponse_sdp_origine_verifiee"])

    def test_relay_signature_alone_does_not_prove_media(self):
        status=monitor().summarize_existing_relay(
            relay(signed=False),decoded_jpeg_delta=20)
        self.assertFalse(status["relais_tcp_authentifie"])
        self.assertFalse(status["paquets_video_dechiffres_observes"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_no_encrypted_media_means_no_decrypted_evidence(self):
        status=monitor().summarize_existing_relay(
            relay(encrypted=0,decrypted=5),decoded_jpeg_delta=2)
        self.assertFalse(status["paquets_video_dechiffres_observes"])
        self.assertFalse(status["video_visible_confirmee"])

    def test_wrong_types_cannot_inflate_image_or_packet_counts(self):
        for bogus in (True,"100",None,-1,0,1e9):
            with self.subTest(type=type(bogus).__name__):
                status=monitor().summarize_existing_relay(
                    relay(),decoded_jpeg_delta=bogus)
                self.assertFalse(status["video_visible_confirmee"])
        status=monitor().summarize_existing_relay(
            relay(encrypted=True,decrypted=True),decoded_jpeg_delta=5)
        self.assertFalse(status["video_visible_confirmee"])

    def test_no_identifier_or_secret_leak_even_with_private_values(self):
        status=monitor().summarize_existing_relay({
            **relay(), "raw":"SECRET_PRIVATE_TOKEN",
            "uuid":"PRIVATE_UUID", "session_id":SID,
        },decoded_jpeg_delta=2)
        report=json.dumps(status)
        for private in (CAM,USER,SID,"SECRET_PRIVATE_TOKEN","PRIVATE_UUID","AES/KCP"):
            self.assertNotIn(private,report)
        self.assertFalse(status["secrets_retournes"])
        self.assertFalse(status["identifiants_retournes"])

    def test_real_probe_wires_existing_relay_and_preview_frame_delta(self):
        source=(BASE/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
        ast.parse(source)
        self.assertIn("preview_jpeg_baseline",source)
        self.assertIn("current-preview_jpeg_baseline",source)
        self.assertIn("current >= preview_jpeg_baseline",source)
        self.assertIn("if use_moto_id:",source)
        self.assertIn("c9c_evidence.summarize_existing_relay(",source)
        self.assertIn("result.get('relais_tcp')",source)
        self.assertIn("result['preuves_media_c9c']",source)
        self.assertIn("return finish_probe()",source)

    def test_independent_legacy_relay_path_is_unchanged(self):
        source=(BASE/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
        self.assertIn("if c9c_evidence is not None:",source)
        self.assertIn("use_moto_id=(interactive_live and use_standalone_c9c_moto_id is True)",source)
        self.assertIn("if use_moto_id:",source)
        self.assertIn("sequence_start,source=1,secrets.token_bytes(4)",source)


if __name__=="__main__":
    unittest.main()
