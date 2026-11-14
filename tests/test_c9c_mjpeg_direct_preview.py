"""Standalone C9C MJPEG path end-to-end synthetic proof, no network/HA/ffmpeg."""
from __future__ import annotations

import ast
import importlib.util
import json
from pathlib import Path
import struct
import sys
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
COMP=ROOT/"custom_components"/"smart_aosu_cloud"
P=COMP/"c9c_mjpeg_reassembly.py"
SPEC=importlib.util.spec_from_file_location("c9c_mjpeg_test_module",P)
mod=importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name]=mod
SPEC.loader.exec_module(mod)
Reassembler=mod.C9CJpegReassembler

CHANNEL=(COMP/"tuya_channel0_probe.py").read_text(encoding="utf-8")
PREVIEW=(COMP/"tuya_live_preview.py").read_text(encoding="utf-8")
media_tree=ast.parse(CHANNEL)
chunk_fn=next(n for n in media_tree.body if isinstance(n,ast.FunctionDef)
              and n.name=="_maybe_jpeg_chunks")
chunk_namespace={"_MEDIA_MARKER":b"\x00\xff\x50\x3c",
                 "_MAX_FRAME":4*1024*1024}
exec(compile(ast.Module(body=[chunk_fn],type_ignores=[]),"<chunks>","exec"),
     chunk_namespace)
decode_chunks=chunk_namespace["_maybe_jpeg_chunks"]

preview_tree=ast.parse(PREVIEW)
preview_class=next(n for n in preview_tree.body if isinstance(n,ast.ClassDef)
                   and n.name=="LivePreview")
preview_fn=next(n for n in preview_class.body if isinstance(n,ast.FunctionDef)
                and n.name=="feed_jpeg")
preview_namespace={"_MAX_IMAGE":3*1024*1024,"time":time}
exec(compile(ast.Module(body=[preview_fn],type_ignores=[]),"<preview>","exec"),
     preview_namespace)
feed_jpeg=preview_namespace["feed_jpeg"]


def sample_jpeg():
    return b"\xff\xd8" + b"DATA"*400 + b"\xff\xd9"


def record(offset,part):
    header=bytearray(20)
    header[12:16]=offset.to_bytes(4,"big")
    header[16:20]=b"\x00\xff\x50\x3c"
    # The native envelope reports 20 bytes of header preceding chunk.
    return (20+len(part)).to_bytes(4,"little")+bytes(header)+part


class FakeMetric:
    def __init__(self):
        self.jpeg_count=0
        self.timing=[]
    def jpeg(self):self.jpeg_count+=1
    def note(self,kind):self.timing.append(kind)


class FakePreview:
    feed_jpeg=feed_jpeg
    def __init__(self):
        self._opened=True
        self._stop=threading.Event()
        self._pause=threading.Event()
        self._lock=threading.Lock()
        self._metrics_lock=threading.Lock()
        self._jpeg=None
        self._jpeg_at=0
        self._frames=0
        self._first_jpeg_delay=None
        self._ffmpeg_started_at=time.monotonic()-1
        self._status="attente_video"
        self._b93_metrics=FakeMetric()
        self._b94_timing=FakeMetric()
        self.called=0
        self._on_frame=lambda:setattr(self,"called",self.called+1)


class TestC9CMjpegReassembly(unittest.TestCase):
    def test_three_decrypted_records_reassemble_one_jpeg(self):
        f=sample_jpeg();a=Reassembler()
        parts=[f[:400],f[400:900],f[900:]]
        results=[]
        offset=0
        for part in parts:
            found=decode_chunks(record(offset,part))
            self.assertEqual(len(found),1)
            results.extend(a.feed(off,fragment) for off,fragment in found)
            offset+=len(part)
        self.assertEqual(results,[None,None,f])
        self.assertEqual(a.summary()["images_completes"],1)
        self.assertEqual(a.summary()["octets_en_cours"],0)

    def test_contiguous_jpeg_to_live_preview_without_ffmpeg(self):
        data=sample_jpeg()
        a=Reassembler();preview=FakePreview()
        pos=0
        for part in (data[:300],data[300:900],data[900:]):
            for off,chunk in decode_chunks(record(pos,part)):
                frame=a.feed(off,chunk)
                if frame is not None:
                    self.assertTrue(preview.feed_jpeg(frame))
            pos+=len(part)
        self.assertEqual(preview._jpeg,data)
        self.assertEqual(preview._frames,1)
        self.assertEqual(preview.called,1)
        self.assertEqual(preview._b93_metrics.jpeg_count,1)

    def test_no_holes_filled_with_zero_bytes(self):
        a=Reassembler();data=sample_jpeg()
        self.assertIsNone(a.feed(0,data[:200]))
        self.assertIsNone(a.feed(450,data[450:]))
        self.assertEqual(a.summary()["fragments_rejetes"],1)
        self.assertFalse(a.summary()["fragment_en_cours"])

    def test_conflicting_overlap_does_not_construct_fake_jpeg(self):
        a=Reassembler();data=sample_jpeg()
        a.feed(0,data[:500])
        self.assertIsNone(a.feed(200,b"wrong-data"))
        self.assertEqual(a.summary()["fragments_rejetes"],1)
        self.assertEqual(a.summary()["images_completes"],0)

    def test_identical_overlap_is_accepted(self):
        data=sample_jpeg();a=Reassembler()
        a.feed(0,data[:500])
        self.assertEqual(a.feed(300,data[300:]),data)

    def test_next_frame_resets_last_one(self):
        data=sample_jpeg();a=Reassembler()
        self.assertEqual(a.feed(0,data),data)
        self.assertEqual(a.feed(0,data),data)
        self.assertEqual(a.summary()["images_completes"],2)

    def test_short_or_oversized_frames_are_not_emitted(self):
        a=Reassembler()
        self.assertIsNone(a.feed(0,b"\xff\xd8"+b"a"*50+b"\xff\xd9"))
        self.assertIsNone(a.feed(0,b"\xff\xd8"+b"x"*(3*1024*1024)))
        self.assertEqual(a.summary()["images_completes"],0)

    def test_pause_stop_or_wrong_marker_blocks_preview(self):
        jpeg=sample_jpeg();preview=FakePreview()
        preview._pause.set()
        self.assertFalse(preview.feed_jpeg(jpeg))
        preview._pause.clear()
        preview._stop.set()
        self.assertFalse(preview.feed_jpeg(jpeg))
        preview._stop.clear()
        self.assertFalse(preview.feed_jpeg(b"FAKE"+jpeg))
        self.assertEqual(preview._frames,0)
        self.assertEqual(preview.called,0)

    def test_c9c_routing_only_in_existing_authenticated_media_path(self):
        self.assertIn("if standalone_c9c is True else None",CHANNEL)
        self.assertIn("c9c_jpeg_assembler.feed(offset,chunk)",CHANNEL)
        self.assertIn("live_preview.feed_jpeg(complete)",CHANNEL)
        self.assertIn("live_preview.feed(plain)",CHANNEL)
        self.assertIn("out['mjpeg_c9c']=c9c_jpeg_assembler.summary()",CHANNEL)
        relay=(COMP/"tuya_relay_handshake.py").read_text()
        kcp=(COMP/"tuya_kcp_probe.py").read_text()
        mqtt=(COMP/"tuya_mqtt_offer.py").read_text()
        self.assertIn("standalone_c9c=standalone_c9c",relay)
        self.assertIn("standalone_c9c=standalone_c9c",kcp)
        self.assertIn("standalone_c9c=(c9c_evidence is not None)",mqtt)
        self.assertIn("if use_moto_id else None",mqtt)
        for src in (CHANNEL,PREVIEW,relay,kcp,mqtt):
            ast.parse(src)

    def test_safe_summary_does_not_expose_jpeg_data(self):
        data=sample_jpeg()
        a=Reassembler();a.feed(0,data)
        report=json.dumps(a.summary())
        self.assertNotIn("DATA",report)
        self.assertFalse(a.summary()["enregistrement"])
        self.assertEqual(a.summary()["appels_reseau"],0)


if __name__=="__main__":
    unittest.main()
