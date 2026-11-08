"""Privacy and read-only DP149 detection for standalone C9C."""
import ast
import runpy
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
NS=runpy.run_path(str(ROOT/"c9c_mqtt_classify.py"))
inspect=NS["inspect_sleep_dp149"]
classify=NS["classify_observed_signal"]

class SleepDp149Tests(unittest.TestCase):
    def test_bool_dp149_in_decrypted_mqtt(self):
        payload={"dps":{"149":True,"145":87},
                 "extra":{"password":"SECRET_PASSWORD"}}
        result=classify(b"2.2"+b"x"*30,key=b"1"*16,
            device_id="SECRET_DEVICE",uid="SECRET_UID",
            decoder=lambda *_:(5,payload))
        self.assertTrue(result["decoded"])
        self.assertTrue(result["dp149_present"])
        self.assertTrue(result["dp149_true"])
        self.assertFalse(result["dp149_false"])
        self.assertNotIn("SECRET",str(result))

    def test_false_and_list_form(self):
        state=inspect({"data":{"status":[{"code":"wireless_awake",
              "value":False},{"dpId":145,"value":90}]}},inventory=False)
        self.assertTrue(state["dp149_present"])
        self.assertTrue(state["dp149_false"])
        self.assertFalse(state["dp149_true"])
        self.assertNotIn("90",str(state))

    def test_inventory_lowpower_is_unknown_without_explicit_flag(self):
        state=inspect({"dpCodes":{"wireless_awake":{"id":149}},
                       "localKey":"SECRET_KEY"},inventory=True)
        self.assertTrue(state["dp149_present"])
        self.assertEqual(state["low_power_hint"],"inconnu")
        self.assertNotIn("SECRET",str(state))
        yes=inspect({"isLowPower":True,"dps":{"149":False}},inventory=True)
        self.assertEqual(yes["low_power_hint"],"oui")
        self.assertTrue(yes["dp149_false"])

    def test_reject_untrusted_types_and_do_not_infer_from_absence(self):
        false=inspect({"dps":{"149":"SECRET_TOKEN"}},inventory=False)
        self.assertTrue(false["dp149_non_bool"])
        self.assertFalse(false["dp149_true"])
        self.assertEqual(inspect({"deviceId":"SECRET"},inventory=False)
                         ["dp149_present"],False)

    def test_only_passive_observer_changed(self):
        observer=(ROOT/"c9c_mqtt_passive.py").read_text(encoding="utf-8")
        inventory=(ROOT/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
        self.assertIn('if result["decoded"] and not (t & 0x01):',observer)
        self.assertIn("if standalone_c9c_mqtt_watch:",inventory)
        self.assertNotIn("_mqtt_publish",observer)
        self.assertNotIn("_send_once",observer)
        ast.parse(observer)
        ast.parse(inventory)

if __name__=="__main__":unittest.main()
