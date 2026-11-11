"""Offline C9C MQTT AES/CRC reference vectors (MIT public upstream examples).
No camera, credentials, network or proprietary native library required.
"""
import ast
import json
import struct
import types
import unittest
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

ROOT=Path(__file__).resolve().parents[1]
path=ROOT/"custom_components"/"smart_aosu_cloud"/"tuya_mqtt_offer.py"
tree=ast.parse(path.read_text(encoding="utf-8"))
needed={"_pkcs7","_encrypt","_signal_frame"}
functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in needed]
assert {x.name for x in functions}==needed
ns={"json":json,"struct":struct,"zlib":zlib,"Cipher":Cipher,
    "algorithms":algorithms,"modes":modes,
    "time":types.SimpleNamespace(time=lambda:1700000000)}
exec(compile(ast.Module(body=functions,type_ignores=[]),str(path),"exec"),ns)
KEY=b"0123456789abcdef"
SOURCE=bytes.fromhex("00000001")
# Known public upstream frame fixture (test_signaling_envelope_vector).
UPSTREAM=(
 "322e322841b2050000000400000001ea755a246e67a8cc3e61dbdaf73c5ff5"
 "d16b70eb9fdecab88f58ebe333fd3bc99b0b853bab143cbd29db21f1dcb1ba"
 "ccbe454130944da5bb3dac257dab4987acf038d9e2020dd6a986d7561eef5e"
 "9de31e60787eb6d61f55b35238f5cee5f7c7"
)
ASCII=(
 "322e329e2ad94400000004000000016d91e50bf1cc7865a74577284a9ee9a3"
 "f4993974c362d1c591e4417eee97165a1a71c49dc8f34542b9bd0e302338"
 "9bff1c09914a3928fc1cef54b0d88a0d4ab61f720078de6e4e8de85f351"
 "ee9508384"
)
def frame(plain):
    tail=struct.pack("!I",4)+SOURCE+ns["_encrypt"](KEY,plain)
    return b"2.2"+struct.pack("!I",zlib.crc32(tail))+tail
class TestVectors(unittest.TestCase):
    def test_known_public_upstream_framing(self):
        plain=b'{"protocol":302,"pv":"2.2","t":1700000000,"data":{"header":{"type":"offer"},"msg":{}}}'
        self.assertEqual(frame(plain).hex(),UPSTREAM)
    def test_actual_python_encoder_ascii_packet(self):
        data={"header":{"type":"offer"},"msg":{}}
        self.assertEqual(ns["_signal_frame"](KEY,4,SOURCE,302,data).hex(),ASCII)
    def test_json_unicode_difference_from_upstream(self):
        data={"header":{"type":"offer"},"msg":{"note":"café"}}
        actual=ns["_signal_frame"](KEY,4,SOURCE,302,data)
        raw=json.dumps({"data":data,"protocol":302,"t":1700000000},
                       separators=(",",":")).encode("utf-8")
        expected=frame(raw)
        self.assertNotEqual(actual,expected)
        # CRC differs when the plaintext JSON encoding differs, while
        # the plaintext-independent sequence and 4-byte source stay identical.
        self.assertEqual(actual[7:15],expected[7:15])
    def test_crc_detects_mutation(self):
        broken=bytearray(ns["_signal_frame"](KEY,4,SOURCE,302,{"header":{},"msg":{}}))
        broken[-1]^=1
        self.assertNotEqual(zlib.crc32(broken[7:]),int.from_bytes(broken[3:7],"big"))
if __name__=="__main__":unittest.main()
