"""Offline C9C-only SDK MQTT SandO counter regression.

No APK, Home Assistant instance, account, internet or camera needed.
"""
from __future__ import annotations
import ast
import json
import struct
import unittest
import zlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

ROOT=Path(__file__).resolve().parents[1]
OFFER=(ROOT/"custom_components/smart_aosu_cloud/tuya_mqtt_offer.py").read_text(encoding="utf-8")
SHARED=(ROOT/"tests/test_c9c_shared_mqtt_beta21.py").read_text(encoding="utf-8")

class FakeSecrets:
    value=0
    calls=0
    def randbelow(self,n):
        assert n==1_000_000
        self.calls+=1
        return self.value

def sdk_counter():
    tree=ast.parse(OFFER)
    node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)
              and n.name=="_c9c_sdk_counters_b26")
    ns={"secrets":FakeSecrets(),"struct":struct}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],
                type_ignores=[])),"<counter>","exec"),ns)
    return ns["_c9c_sdk_counters_b26"],ns["secrets"]

class TestC9CSdkCountersB26(unittest.TestCase):
    def test_inclusive_range_and_first_sequence(self):
        fun,rng=sdk_counter()
        for v in (0,1,999999):
            rng.value=v
            first,source=fun()
            self.assertEqual(first,3)
            self.assertEqual(len(source),4)
            self.assertEqual(struct.unpack("!I",source)[0],1000+v)
        self.assertEqual(rng.calls,3)

    def test_single_O_and_incrementing_S(self):
        start,source=sdk_counter()[0]()
        self.assertEqual([start,start+1,start+2,start+3],[3,4,5,6])
        self.assertEqual(len(source),4)
        self.assertIn("sequence_start,source=_c9c_sdk_counters_b26()",OFFER)
        self.assertIn("sequence_start,source=1,secrets.token_bytes(4)",OFFER)
        self.assertIn("_send_once(sock,key,pubtopic,source,sequence_start,10,22",OFFER)
        self.assertIn("_send_once(sock,key,pubtopic,source,sequence_start+1,11,302,offer)",OFFER)
        self.assertIn("_send_once(sock,key,pubtopic,source,sequence_start+2,12,302,candidate_msg)",OFFER)
        self.assertIn("sequence_start+(3 if ice_candidate else 2)",OFFER)
        self.assertIn("if use_moto_id:",OFFER)
        self.assertIn("sequencement_sdk_c9c_b26",OFFER)

    def test_pv22_synthetic_envelope_and_crc(self):
        # Independent raw-AES reference. No vendor/private bytecode distributed.
        key=b"0123456789abcdef"
        data={"reqType":"sigQry"}
        raw=json.dumps({"data":data,"protocol":22,"t":1700000000},
                       ensure_ascii=False,separators=(",",":")).encode()
        n=16-len(raw)%16
        cipher=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
        encrypted=cipher.update(raw+bytes([n])*n)+cipher.finalize()
        source=struct.pack("!I",1000)
        tail=struct.pack("!I",3)+source+encrypted
        frame=b"2.2"+struct.pack("!I",zlib.crc32(tail))+tail
        self.assertEqual(frame[:3],b"2.2")
        self.assertEqual(zlib.crc32(frame[7:]),
                         struct.unpack("!I",frame[3:7])[0])
        self.assertEqual(struct.unpack("!II",frame[7:15]),(3,1000))
        self.assertEqual(len(encrypted)%16,0)
        self.assertNotIn(b'"s":',raw)
        self.assertTrue(any(b>127 for b in encrypted))

    def test_legacy_behavior_preserved(self):
        ast.parse(OFFER)
        self.assertIn("else:\n        sequence_start,source=1,secrets.token_bytes(4)",OFFER)
        self.assertIn("use_moto_id=(interactive_live and use_standalone_c9c_moto_id is True)",OFFER)
        self.assertNotIn("Base64",OFFER)
        self.assertIn("modes.ECB()",OFFER)

if __name__=="__main__":unittest.main()
