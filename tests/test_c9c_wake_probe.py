"""Offline safety and wake CRC32 tests. No network or Home Assistant."""
import ast
from pathlib import Path
import struct
import unittest
import zlib

BASE=Path(__file__).resolve().parents[1]/"custom_components/smart_aosu_cloud"
SRC=(BASE/"c9c_wake_probe.py").read_text(encoding="utf-8")
TREE=ast.parse(SRC)
FUNC=next(n for n in TREE.body if isinstance(n,ast.FunctionDef)
          and n.name=="build_wake_packet")
NS={"zlib":zlib,"struct":struct}
exec(compile(ast.Module(body=[FUNC],type_ignores=[]),"<wake>","exec"),NS)
build=NS["build_wake_packet"]

class C9CWakeTests(unittest.TestCase):
    def test_topic_and_crc32_big_endian(self):
        topic,packet=build("test-device", "1234567890123456")
        self.assertEqual(topic,"m/w/test-device")
        self.assertEqual(len(packet),4)
        self.assertEqual(packet,struct.pack(">I",zlib.crc32(b"1234567890123456")&0xffffffff))

    def test_reject_invalid_device_and_key(self):
        for dev in ("bad/id","bad#id","A"*129,"x"):
            with self.subTest(dev=dev[:15]), self.assertRaises(ValueError):
                build(dev,"1234567890123456")
        with self.assertRaises(ValueError):
            build("valid-device","short")

    def test_only_manual_wake_one_publish(self):
        inv=(BASE/"tuya_rtc_inventory.py").read_text(encoding="utf-8")
        init=(BASE/"__init__.py").read_text(encoding="utf-8")
        self.assertIn("standalone_c9c_wake_only:bool=False",inv)
        self.assertIn("if standalone_c9c_wake_only and (",inv)
        self.assertIn("if standalone_c9c_wake_only:",inv)
        self.assertIn("tester_offre_mqtt=False,tester_relais_tcp=False",init)
        self.assertIn("if runtime.live_controller.running:",init)
        self.assertIn("_COOLDOWN_S = 600",SRC)
        self.assertEqual(SRC.count("conn.sendall(_mqtt_publish(topic, payload, 2))"),1)
        self.assertNotIn("ptz_maintien",SRC)
        self.assertNotIn("run_tuya_mqtt_offer",SRC)
        ast.parse(inv)
        ast.parse(init)

if __name__=="__main__":
    unittest.main()
