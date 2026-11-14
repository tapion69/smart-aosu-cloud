"""No-network C9C lazy JPEG preview with optional HEVC fallback.

Test actual preview methods via AST without Home Assistant, FFmpeg, network,
OEM SDK, camera frames, or credentials.
"""
from __future__ import annotations

import ast
from pathlib import Path
import threading
import time
import unittest

SOURCE=Path(__file__).resolve().parents[1]/"custom_components"/"smart_aosu_cloud"/"tuya_live_preview.py"
RAW=SOURCE.read_text(encoding="utf-8")
TREE=ast.parse(RAW)
PREVIEW=next(n for n in TREE.body if isinstance(n,ast.ClassDef)
             and n.name=="LivePreview")
FUNCS=[n for n in PREVIEW.body if isinstance(n,ast.FunctionDef)
       and n.name in ("start","_start_hevc_decoder","feed","feed_jpeg")]
assert len(FUNCS)==4
NS={"time":time,"_MAX_IMAGE":3*1024*1024}
module=ast.Module(body=[ast.ImportFrom(module="__future__",
                                      names=[ast.alias(name="annotations")],level=0),
                        *FUNCS],type_ignores=[])
ast.fix_missing_locations(module)
exec(compile(module,str(SOURCE),"exec"),NS)


class Metrics:
    def __init__(self):
        self.frames=0
        self.rtp=[]
    def jpeg(self):self.frames+=1
    def note(self,v):self.rtp.append(v)


class SyntheticRTP:
    def __init__(self):
        self.nals=[]
        self.packets=0
        self._size=0
        self.next_nals=[]
    def feed(self,raw):
        self.packets+=1
        self.nals.extend(self.next_nals)
        self.next_nals=[]


class PreviewStub:
    start=NS["start"]
    feed=NS["feed"]
    feed_jpeg=NS["feed_jpeg"]
    _start_hevc_decoder=NS["_start_hevc_decoder"]

    def __init__(self,lazy=True):
        self._opened=False
        self._stop=threading.Event()
        self._pause=threading.Event()
        self._ffmpeg_path=None
        self._lazy_hevc=lazy
        self._process=None
        self._lock=threading.Lock()
        self._metrics_lock=threading.Lock()
        self._frames=0
        self._rtp=0
        self._decoder=SyntheticRTP()
        self._fed_param={}
        self._have_idr=False
        self._ffmpeg_started_at=0.0
        self._last_rtp_at=0.0
        self._first_jpeg_delay=None
        self._b93_metrics=Metrics()
        self._b94_timing=Metrics()
        self._on_frame=self.on_frame
        self.events=[]
        self._status="pret"
        self._jpeg=None
        self._jpeg_at=0.0
        self._decode_error=False
        self._queue=None
        self.hevc_starts=0
    def on_frame(self):self.events.append("image")
    def mark_phase_b93(self,phase):self.events.append(phase)


class TestC9CLazyPreview(unittest.TestCase):
    def test_standalone_c9c_can_start_without_ffmpeg(self):
        preview=PreviewStub(lazy=True)
        self.assertTrue(preview.start())
        self.assertTrue(preview._opened)
        self.assertIsNone(preview._process)
        self.assertEqual(preview._status,"attente_video")
        self.assertIn("preview_jpeg_pret",preview.events)

    def test_jpeg_goes_to_ha_callback_without_ffmpeg(self):
        preview=PreviewStub(lazy=True)
        self.assertTrue(preview.start())
        frame=b"\xff\xd8"+b"PRIVATE_FAKE_PAYLOAD"*100+b"\xff\xd9"
        self.assertTrue(preview.feed_jpeg(frame))
        self.assertEqual(preview._frames,1)
        self.assertEqual(preview._jpeg,frame)
        self.assertIn("image",preview.events)
        self.assertEqual(preview._b93_metrics.frames,1)
        self.assertIsNone(preview._process)

    def test_legacy_c5l_still_requires_ffmpeg(self):
        preview=PreviewStub(lazy=False)
        self.assertFalse(preview.start())
        self.assertFalse(preview._opened)
        self.assertEqual(preview._status,"ffmpeg_indisponible")

    def test_c9c_does_not_start_decoder_for_non_hevc_records(self):
        preview=PreviewStub(lazy=True)
        self.assertTrue(preview.start())
        starts=[]
        def start_decoder():
            starts.append(1)
            return True
        preview._start_hevc_decoder=start_decoder
        preview.feed(b"RANDOM_NON_HEVC_CHUNK")
        self.assertEqual(starts,[])
        self.assertIsNone(preview._process)

    def test_real_hevc_nal_triggers_late_decoder(self):
        preview=PreviewStub(lazy=True)
        self.assertTrue(preview.start())
        starts=[]
        def start_decoder():
            starts.append(1)
            preview._process=object()
            return True
        preview._start_hevc_decoder=start_decoder
        # HEVC VPS: NAL type 32, identified only after actual RTP parse.
        preview._decoder.next_nals=[bytes((32<<1,1,2,3))]
        preview.feed(b"FAKE_RTP_WITH_NAL")
        self.assertEqual(starts,[1])
        self.assertEqual(preview._fed_param[32],bytes((64,1,2,3)))

    def test_no_decoder_when_c9c_ffmpeg_is_absent_even_if_hevc(self):
        preview=PreviewStub(lazy=True)
        self.assertTrue(preview.start())
        preview._decoder.next_nals=[bytes((64,1,2,3))]
        preview.feed(b"FAKE_RTP_WITH_NAL")
        self.assertIsNone(preview._process)
        self.assertTrue(preview._opened)
        self.assertEqual(preview._status,"attente_video")

    def test_stopped_or_paused_preview_refuses_jpeg(self):
        jpeg=b"\xff\xd8"+b"x"*1024+b"\xff\xd9"
        preview=PreviewStub(lazy=True)
        preview.start()
        preview._pause.set()
        self.assertFalse(preview.feed_jpeg(jpeg))
        preview._pause.clear()
        preview._stop.set()
        self.assertFalse(preview.feed_jpeg(jpeg))
        self.assertEqual(preview._frames,0)

    def test_runtime_controller_enablement_is_c9c_only(self):
        self.assertIn("lazy_hevc=(standalone_c9c_video_test is True)",RAW)
        self.assertIn(
            "if not self.preview._ffmpeg_path and standalone_c9c_video_test is not True:",
            RAW)
        self.assertIn("images_jpeg_directes",RAW)
        self.assertIn("if self._lazy_hevc and self._process is None:",RAW)
        # Legacy FFmpeg invocation is retained unchanged.
        for flag in ("'-f', 'hevc'","'-vcodec', 'mjpeg'"):
            self.assertIn(flag,RAW)


if __name__=="__main__":
    unittest.main()
