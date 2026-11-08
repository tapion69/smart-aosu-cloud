"""Offline C9C wake+offer same MQTT session regression; no HA/network."""
import ast
import unittest
from pathlib import Path

COMP=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
OFFER=(COMP/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
WAKE=(COMP/"c9c_wake_probe.py").read_text(encoding="utf-8")
RTC=(COMP/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
LIVE=(COMP/"tuya_live_preview.py").read_text(encoding="utf-8")

class TestSharedMQTTBeta21(unittest.TestCase):
    def test_single_socket_between_wake_and_offer(self):
        start=OFFER.index("diag['abonnement_confirme']=True")
        end=OFFER.index("sent_offer=True",start)
        block=OFFER[start:end]
        self.assertIn("try_wake_c9c_on_open_socket(",block)
        self.assertIn("if not awake:",block)
        self.assertIn("'reveil_non_confirme_offre_non_envoyee'",block)
        self.assertLess(block.index("try_wake_c9c_on_open_socket("),
                        block.index("_send_once(sock,key,pubtopic,source,sequence_start+1,11,302,offer)"))
        self.assertNotIn("socket.create_connection",block)
        self.assertIn("sock.sendall(_mqtt_publish(topic, payload, 2))",WAKE)
        self.assertIn("_COOLDOWN_S = 600",WAKE)
        self.assertIn("result['reveil_et_video']['puback_offre']=True",OFFER)
    def test_only_opt_in_c9c(self):
        self.assertIn("wake_before_offer=standalone_c9c_wake_then_video",RTC)
        self.assertIn("standalone_c9c_video_test is not True",RTC)
        self.assertIn("wake_before_offer and not (interactive_live",OFFER)
        self.assertIn("standalone_c9c_wake_then_video=self._standalone_wake_then_video",LIVE)
        for source in (OFFER,WAKE,RTC):
            ast.parse(source)


    def test_beta22_no_premature_wake_result_access(self):
        """Executes the real offer branch offline to guard against beta21 KeyError."""
        tree=ast.parse(RTC)
        branch=next(node for node in ast.walk(tree)
            if isinstance(node,ast.If)
            and isinstance(node.test,ast.BoolOp)
            and "tester_offre_mqtt is True and private is not None"
                in ast.get_source_segment(RTC,node.test))
        calls=[]
        def offer_stub(*args,**kwargs):
            calls.append(kwargs)
            return {"etat":"offre_envoyee_sans_reponse_sdp",
                    "reveil_et_video":{"etat":"observation_terminee",
                                       "wake_envoye":True,"puback_wake":True,
                                       "dp149_vrai":1,"offre_effectuee":True},
                    "relais_tcp":{}}
        ns={
            "out": {}, "tester_offre_mqtt":True,
            "standalone_c9c_wake_then_video":True,
            "standalone_c9c_video_test":True,
            "private":object(), "client":object(),
            "identity":object(), "signer":object(), "session":object(),
            "install_id":"offline-test", "tester_relais_tcp":True,
            "tester_kcp":True, "tester_media":True,
            "capturer_media_localement":False,"repertoire_capture_locale":None,
            "live_preview":object(), "interactive_live":True,
            "run_tuya_mqtt_offer":offer_stub,
        }
        code=compile(ast.fix_missing_locations(
            ast.Module(body=[branch],type_ignores=[])), "<rtc-mqtt-branch>", "exec")
        exec(code,ns)
        self.assertEqual(len(calls),1)
        self.assertTrue(calls[0]["wake_before_offer"])
        self.assertEqual(ns["out"]["reveil_et_video"]["dp149_vrai"],1)
        self.assertTrue(ns["out"]["reveil_et_video"]["offre_effectuee"])
        self.assertEqual(ns["out"]["signalisation_mqtt"]["etat"],
                         "offre_envoyee_sans_reponse_sdp")

if __name__=="__main__":unittest.main()
