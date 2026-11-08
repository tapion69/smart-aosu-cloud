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
                        block.index("_send_once(sock,key,pubtopic,source,2,11,302,offer)"))
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

if __name__=="__main__":unittest.main()
