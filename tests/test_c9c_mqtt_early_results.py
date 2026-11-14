"""Exercise early MQTT returns entirely offline using isolated _probe AST."""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import sys
import types
import unittest

BASE=Path(__file__).resolve().parents[1]/"custom_components"/"smart_aosu_cloud"
OFFER=(BASE/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
TREE=ast.parse(OFFER)
PROBE=next(n for n in TREE.body if isinstance(n,ast.FunctionDef)
           and n.name=="_probe")
mod=ast.Module(body=[ast.ImportFrom(module="__future__",
               names=[ast.alias(name="annotations")],level=0),PROBE],
               type_ignores=[])
ast.fix_missing_locations(mod)
P=BASE/"c9c_thing4_mqtt_evidence.py"
spec=importlib.util.spec_from_file_location("c9c_mqtt_early_status",P)
evidence=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=evidence
spec.loader.exec_module(evidence)
DEV="PRIVATE_TUYA_DEVICE_12345"
SID="PRIVATE_SESSION_ABCDE123"
UID="PRIVATE_USER_123456"
class FakeSocket:
    def __init__(self):
        self.sent=[]
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def settimeout(self,_):pass
    def sendall(self,v):self.sent.append(v)

class FakeCtx:
    def __init__(self,socket_):
        self.socket_=socket_
        self.verify_mode=None
        self.check_hostname=None
    def wrap_socket(self,*args,**kwargs):return self.socket_

class FakeSSL:
    Purpose=types.SimpleNamespace(SERVER_AUTH=1)
    CERT_REQUIRED=ssl.CERT_REQUIRED
    SSLCertVerificationError=ssl.SSLCertVerificationError
    SSLError=ssl.SSLError
    def __init__(self,sock):self.sock=sock
    def create_default_context(self,_):return FakeCtx(self.sock)


def compile_probe(*, messages, media_error=False):
    sock=FakeSocket()
    answers=iter(messages)
    def payload(*a,**k):
        if media_error:raise ValueError("PRIVATE_BAD_CREDENTIALS")
        return b"0"*16, {"header":{"moto_id":"PRIVATE_MOTO"}}
    namespace={
        "ssl":FakeSSL(sock),
        "socket":types.SimpleNamespace(
            create_connection=lambda *args,**kwargs:sock,
            timeout=socket.timeout),
        "secrets":types.SimpleNamespace(token_bytes=lambda n:b"x"*n),
        "_BROKER":"fake.local","_PORT":8883,
        "_media_payload":payload,
        "C9CMqttSessionEvidence":evidence.C9CMqttSessionEvidence,
        "_c9c_sdk_counters_b26":lambda:(3,b"abcd"),
        "_mqtt_connect_packet":lambda a:b"CONNECT",
        "_mqtt_subscribe_packet":lambda a:b"SUB",
        "_mqtt_read":lambda sock:next(answers),
        "_WAIT_ANSWER_SECONDS":9,
        "_WAIT_ANSWER_LIVE_SECONDS":20,
    }
    exec(compile(mod,str(BASE/"tuya_mqtt_offer.py"),"exec"),namespace)
    media=types.SimpleNamespace(device_id=DEV,session_id=SID,
                                 ice_password="PRIVATE_ICE")
    auth=types.SimpleNamespace(topic="PRIVATE_TOPIC")
    return namespace["_probe"],auth,media,sock


class TestC9CEarlyMQTTStatus(unittest.TestCase):
    def test_invalid_rtc_has_safe_c9c_status_before_connect(self):
        p,a,m,sock=compile_probe(messages=[],media_error=True)
        result=p(a,UID,m,use_moto_id=True)
        self.assertEqual(result["etat"],"rtc_ou_cle_locale_incompatible")
        status=result["observation_session_c9c"]
        self.assertEqual(status["etat"],"non_initialisee")
        self.assertFalse(status["reponse_sdp_origine_verifiee"])
        self.assertFalse(status["video_confirmee"])
        self.assertFalse(sock.sent)

    def test_connack_refusal_returns_safe_status(self):
        p,a,m,sock=compile_probe(messages=[(0x20,bytes([0,5]))])
        result=p(a,UID,m,use_moto_id=True)
        self.assertEqual(result["etat"],"connack_non_accepte")
        self.assertFalse(result["observation_session_c9c"]["offre_emise"])
        self.assertFalse(result["observation_session_c9c"]["video_confirmee"])
        # CONNECT and best-effort MQTT DISCONNECT from the existing finally.
        self.assertEqual(len(sock.sent),2)

    def test_suback_refusal_returns_safe_status(self):
        p,a,m,sock=compile_probe(messages=[
            (0x20,bytes([0,0])),
            (0x90,bytes([0,1,0x80]))])
        result=p(a,UID,m,use_moto_id=True)
        self.assertEqual(result["etat"],"abonnement_non_accepte")
        self.assertTrue(result["connack_accepte"])
        status=result["observation_session_c9c"]
        self.assertFalse(status["offre_emise"])
        self.assertFalse(status["reponse_sdp_origine_verifiee"])
        self.assertFalse(status["video_confirmee"])
        # CONNECT, SUBSCRIBE, then best-effort MQTT DISCONNECT.
        self.assertEqual(len(sock.sent),3)

    def test_legacy_c5l_has_no_c9c_observation(self):
        p,a,m,sock=compile_probe(messages=[(0x20,bytes([0,5]))])
        result=p(a,UID,m,use_moto_id=False)
        self.assertEqual(result["etat"],"connack_non_accepte")
        self.assertNotIn("observation_session_c9c",result)

    def test_never_exposes_private_data_on_early_errors(self):
        p,a,m,sock=compile_probe(messages=[(0x20,bytes([0,5]))])
        result=p(a,UID,m,use_moto_id=True)
        payload=json.dumps(result)
        for value in (DEV,SID,UID,"PRIVATE_MOTO","PRIVATE_ICE","PRIVATE_TOPIC"):
            self.assertNotIn(value,payload)

    def test_all_returns_use_single_safe_finisher(self):
        s=ast.get_source_segment(OFFER,PROBE)
        self.assertEqual(s.count("return finish_probe()"),5)
        self.assertEqual(s.count("return result"),1)
        self.assertIn("c9c_evidence = None",s)
        self.assertIn("def finish_probe()",s)


if __name__=="__main__":unittest.main()
