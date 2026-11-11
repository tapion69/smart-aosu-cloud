"""Synthetic C9C ICE readiness tests: zero actual network/camera calls.

Exercise _probe's real AST function against a fake TLS/MQTT socket to
guarantee that a missing host candidate cannot publish an SDP or wake
a standalone C9C. The C5L path is not modified by this experimental patch.
"""
from __future__ import annotations

import ast
import socket as socket_module
import ssl as ssl_module
import threading
import time
import types
import unittest
from pathlib import Path
from typing import Any

COMP=Path(__file__).resolve().parents[1]/"custom_components"/"smart_aosu_cloud"
SOURCE=(COMP/"tuya_mqtt_offer.py").read_text(encoding="utf-8")
FUNCTIONS=[n for n in ast.parse(SOURCE).body
           if isinstance(n,ast.FunctionDef) and n.name=="_probe"]
if len(FUNCTIONS)!=1:raise AssertionError("Missing _probe")

class DummyMedia:
    ice_password="password"
    device_id="synthetic-device"
    session_id="synthetic-session"

class DummyPreview:
    def __init__(self):
        self._stop=threading.Event()
        self._stop.set()  # Do not enter the answer-await loop.
    def mark_phase_b93(self, _):pass

class FakeSocket:
    def __init__(self,events):self.events=events
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def settimeout(self,*_):pass
    def sendall(self,data):self.events.append("mqtt_data")
    def recv(self,size):raise AssertionError("No direct recv permitted")

class FakeSSLContext:
    def __init__(self,sock):self.sock=sock
    def wrap_socket(self,*_,**__):return self.sock

class FakeIce:
    candidate=None
    def __init__(self,_password,events):self.events=events;self.closed=False
    def start(self):
        self.events.append("ice_start")
        return self.candidate
    def snapshot(self):
        return {"etat":"pret" if self.candidate else "indisponible",
                "adresse_ip_retournee":False,"secret_retourne":False}
    def close(self):
        self.closed=True
        self.events.append("ice_close")

def make_namespace(events,candidate):
    sock=FakeSocket(events)
    context=FakeSSLContext(sock)
    readings=iter([(0x20,b"\x00\x00"),(0x90,b"\x00\x01\x01")])
    ice_instances=[]
    class Ice(FakeIce):
        def __init__(self,passwd):
            super().__init__(passwd,events)
            self.candidate=candidate
            ice_instances.append(self)
    def send_once(*args):
        events.append("send_protocol_"+str(args[6]))
    def mqtt_read(_):
        return next(readings)
    ns={
        "Any":Any, "PrivateMediaBootstrap":DummyMedia,
        "ssl":types.SimpleNamespace(Purpose=ssl_module.Purpose,
                                   CERT_REQUIRED=ssl_module.CERT_REQUIRED,
                                   SSLError=ssl_module.SSLError,
                                   SSLCertVerificationError=ssl_module.SSLCertVerificationError,
                                   create_default_context=lambda _purpose:context),
        "socket":types.SimpleNamespace(create_connection=lambda *_args,**_kw:sock,
                                      timeout=socket_module.timeout),
        "secrets":types.SimpleNamespace(token_bytes=lambda n:b"\0"*n),
        "time":time,
        "_BROKER":"mock.invalid","_PORT":8883,
        "_c9c_sdk_counters_b26":lambda:(3,b"\0\0\0\1"),
        "_media_payload":lambda _media,_uid,**_kw:
           (b"0123456789abcdef",
            {"header":{"moto_id":"synthetic"},"msg":{}}),
        "_mqtt_connect_packet":lambda *_:b"mock-connect",
        "_mqtt_subscribe_packet":lambda *_:b"mock-subscribe",
        "_mqtt_read":mqtt_read,
        "_send_once":send_once,
        "ControlledIceB85":Ice,
        "_disconnect":lambda *_args,**_kw:{"header":{"type":"disconnect"}},
        "_WAIT_ANSWER_LIVE_SECONDS":20,
        "_WAIT_ANSWER_SECONDS":9,
    }
    exec(compile(ast.Module(body=FUNCTIONS,type_ignores=[]),
                 "<source _probe>","exec"),ns)
    return ns["_probe"],ice_instances

def call(probe, *,c9c=True):
    return probe(types.SimpleNamespace(topic="mock/in"),"synthetic-user",
                 DummyMedia(),tester_relais_tcp=True,tester_kcp=True,
                 tester_media=True,live_preview=DummyPreview(),
                 use_moto_id=c9c,wake_before_offer=False)

class TestC9CIcePreflight(unittest.TestCase):
    def test_no_host_candidate_means_zero_camera_publishes(self):
        events=[]
        probe,ices=make_namespace(events,None)
        report=call(probe)
        self.assertEqual(report["etat"],"ice_local_indisponible_offre_non_envoyee")
        self.assertFalse(report["offre_sdp_envoyee"])
        self.assertEqual(report["mqtt_messages_publies"],0)
        self.assertEqual(report["commande_ptz"],0)
        self.assertEqual(len(ices),1)
        self.assertTrue(ices[0].closed)
        self.assertIn("ice_start",events)
        self.assertNotIn("send_protocol_22",events)
        self.assertNotIn("send_protocol_302",events)
        self.assertTrue(report["negociation_ice_b85"]["secret_retourne"] is False)
    def test_valid_candidate_precedes_sigqry_offer_and_candidate(self):
        events=[]
        candidate="a=candidate:123 1 udp 2130706431 192.0.2.1 40001 typ host\r\n"
        probe,ices=make_namespace(events,candidate)
        report=call(probe)
        self.assertEqual(report["signalisation_b89"]["ice_pret_avant_offre"],True)
        self.assertTrue(report["offre_sdp_envoyee"])
        self.assertTrue(report["candidat_ice_b85_publie"])
        self.assertTrue(ices[0].closed)
        pos=events.index("ice_start")
        self.assertLess(pos,events.index("send_protocol_22"))
        self.assertLess(events.index("send_protocol_22"),events.index("send_protocol_302"))
    def test_existing_legacy_path_does_not_fail_closed_before_offer(self):
        events=[]
        probe,ices=make_namespace(events,None)
        report=call(probe,c9c=False)
        self.assertNotEqual(report["etat"],"ice_local_indisponible_offre_non_envoyee")
        self.assertTrue(report["offre_sdp_envoyee"])
        self.assertIn("send_protocol_22",events)
        self.assertTrue(ices[0].closed)

if __name__=="__main__":
    unittest.main()
