"""C9C passive MQTT regression tests. No broker, HA or personal data."""
import ast
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/"custom_components"/"smart_aosu_cloud"
SRC=(BASE/"c9c_mqtt_passive.py").read_text(encoding="utf-8")
class PassiveMQTTTests(unittest.TestCase):
    def test_syntax_and_strict_topic_scope(self):
        ast.parse(SRC)
        self.assertIn('("appareil",auth.topic)', SRC)
        self.assertIn('("moto","/av/u/"+uid)',SRC)
        self.assertIn('("sortant","smart/mb/out/"+device_id)',SRC)
        self.assertNotIn('send302',SRC)
        self.assertNotIn('_send_once',SRC)
        self.assertNotIn('_mqtt_publish',SRC)
        self.assertNotIn('ptz_maintien',SRC)
    def test_sensitive_output_not_reused(self):
        self.assertIn('"payloads_conserves":False',SRC)
        self.assertIn('base["messages_appareil"]+=1',SRC)
        self.assertIn('base["messages_moto"]+=1',SRC)
        self.assertIn('_DURATION=20',SRC)
        self.assertIn('now+600',SRC)
        js=(BASE/"frontend"/"c9c-autonome-b1.js").read_text(encoding="utf-8")
        self.assertIn("observer_mqtt_c9c_autonome",js)
    def test_only_manual_c9c_mode(self):
        r=(BASE/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
        self.assertIn('if standalone_c9c_mqtt_watch and (',r)
        init=(BASE/"__init__.py").read_text(encoding="utf-8")
        self.assertIn('if runtime.live_controller.running:',init)
        self.assertIn("tester_rtc=True, tester_mqtt=True,",init)
        self.assertIn("tester_offre_mqtt=False, tester_relais_tcp=False,",init)

if __name__=="__main__":unittest.main()
