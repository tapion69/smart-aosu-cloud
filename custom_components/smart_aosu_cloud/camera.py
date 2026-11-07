"""C5L P2P Home Assistant camera: event-driven in-memory MJPEG preview.

Video decoding and connection are owned by LiveController. This module only
serves JPEG snapshots and MJPEG to authenticated Home Assistant camera routes.
Neither opening the camera nor requesting its image starts Tuya/RTC/MQTT.
"""
from __future__ import annotations

import asyncio
import time
from aiohttp import web
from homeassistant.components.camera import Camera
from homeassistant.core import callback
from .device import info_for_device
from .live_device import select_live_camera_key
from .camera_topology import has_h1l_video_topology, select_standalone_c9c_key

# A long negotiation (OEM login / RTC / MQTT) may precede the first JPEG.
_FIRST_FRAME_TIMEOUT = 45.0
_FRAME_WAIT = 12.0
_BOUNDARY = "aosu-frame"


def _mjpeg_part(jpeg: bytes) -> bytes:
    """One well-framed JPEG; do not expose tokens or raw HEVC."""
    return (f"--{_BOUNDARY}\r\nContent-Type: image/jpeg\r\n"
            f"Content-Length: {len(jpeg)}\r\n\r\n".encode("ascii")
            + jpeg + b"\r\n")


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    registered = False
    standalone_registered = False

    @callback
    def add_when_available():
        nonlocal registered, standalone_registered
        key = select_live_camera_key(coordinator)
        if not registered and key is not None:
            registered = True
            async_add_entities([SmartAosuC5LPreview(coordinator, entry.entry_id, key)])
        standalone_key = select_standalone_c9c_key(coordinator.data)
        if standalone_key is not None and not standalone_registered:
            standalone_registered = True
            async_add_entities([SmartAosuStandaloneC9CPreview(
                coordinator, entry.entry_id, standalone_key)])

    add_when_available()
    entry.async_on_unload(coordinator.async_add_listener(add_when_available))
    if has_h1l_video_topology(coordinator.data) and getattr(coordinator,'c9_live_b141',None) is not None:
        async_add_entities([SmartAosuC9H1LPreviewB141(coordinator,entry.entry_id,n)
                            for n in (1,2)])
    elif has_h1l_video_topology(coordinator.data) and getattr(coordinator,'c9_live_b139',None) is not None:
        async_add_entities([SmartAosuC9H1LPreview(coordinator,entry.entry_id)])


class SmartAosuC5LPreview(Camera):
    _attr_has_entity_name = True
    _attr_name = "C5L Direct"
    _attr_should_poll = False
    _attr_brand = "AOSU"
    _attr_model = "C5L - P2P MJPEG"
    # Deliberately no CameraEntityFeature.STREAM: the source isn't RTSP/HLS.
    # HA's camera_proxy_stream instead calls handle_async_mjpeg_stream below.
    frame_interval = 0.5

    def __init__(self, coordinator, entry_id, device_key):
        super().__init__()
        self._controller = coordinator.live_controller
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._device_key = device_key
        self._attr_unique_id = f"smart_aosu_{entry_id}_c5l_p2p_preview"
        self.content_type = "image/jpeg"
        self._unsub = None
        self._snapshot_requests = 0
        self._mjpeg_connections = 0
        self._mjpeg_frames_sent = 0
        self._last_served_at = 0.0

    @property
    def device_info(self):
        return info_for_device(self._coordinator, self._entry_id, self._device_key)

    @property
    def is_streaming(self):
        # The state reflects actual P2P activity, not HLS support.
        return self._controller.running

    @property
    def extra_state_attributes(self):
        s = self._controller.status()
        d = s.get("decodage") or {}
        return {
            "etape": s.get("etat"),
            "images_decodees": d.get("images_jpeg_decodees", 0),
            "image_disponible": d.get("derniere_image_disponible", False),
            "video_enregistree": False,
            "sortie_mjpeg": "camera_proxy_stream",
            "clients_mjpeg": self._mjpeg_connections,
            "images_mjpeg_envoyees": self._mjpeg_frames_sent,
            "requetes_instantane": self._snapshot_requests,
            "direct_limite_secondes": None,
            "arret_automatique_apres_inactivite_secondes": 45,
            "affichage_en_pause": s.get("affichage_en_pause", False),
        }

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        self._unsub = self._controller.subscribe(self._state_changed)

    async def async_will_remove_from_hass(self):
        if self._unsub:
            self._unsub()
            self._unsub = None
        await super().async_will_remove_from_hass()

    @callback
    def _state_changed(self):
        self.async_write_ha_state()

    async def _wait_for_jpeg(self, seconds: float) -> bytes | None:
        """Wait without blocking HA; do not start the camera or poll Tuya."""
        image = self._controller.image()
        if image:
            return image
        if not self._controller.running:
            return None
        event = asyncio.Event()

        def notify():
            event.set()

        remove = self._controller.subscribe(notify)
        try:
            # Subscribe-then-recheck closes the lost-wakeup window.
            image = self._controller.image()
            if image:
                return image
            try:
                await asyncio.wait_for(event.wait(), timeout=seconds)
            except TimeoutError:
                pass
            return self._controller.image()
        finally:
            remove()

    async def async_camera_image(self, width=None, height=None):
        self._snapshot_requests += 1
        # HA's still-image HTTP route has its own short timeout. Avoid returning
        # None just because negotiation has not produced the first image yet.
        return await self._wait_for_jpeg(6.0)

    async def handle_async_mjpeg_stream(self, request: web.Request) -> web.StreamResponse:
        """Serve the authenticated HA camera_proxy_stream endpoint directly.

        The first request waits for the first real JPEG; no placeholder or
        synthetic video is emitted. Subsequent frames are pushed on decoder
        notifications, without opening extra P2P sessions per browser tab.
        """
        self._mjpeg_connections += 1
        event = asyncio.Event()

        def notify():
            event.set()

        remove = self._controller.subscribe(notify)
        response: web.StreamResponse | None = None
        last_jpeg: bytes | None = None
        last_write = 0.0
        start = time.monotonic()
        try:
            response = web.StreamResponse(
                status=200,
                headers={
                    "Content-Type": f"multipart/x-mixed-replace; boundary={_BOUNDARY}",
                    "Cache-Control": "no-store, no-cache, max-age=0",
                    "Pragma": "no-cache",
                    "X-Accel-Buffering": "no",
                },
            )
            await response.prepare(request)
            while True:
                image = self._controller.image()
                now = time.monotonic()
                if image and (image is not last_jpeg or now - last_write > 10):
                    await response.write(_mjpeg_part(image))
                    last_jpeg = image
                    last_write = now
                    self._mjpeg_frames_sent += 1
                if not self._controller.running:
                    break
                if image is None and now-start > _FIRST_FRAME_TIMEOUT:
                    break
                event.clear()
                # Recheck after clearing to reduce risk of missed frames.
                new_image = self._controller.image()
                if new_image is not None and new_image is not last_jpeg:
                    continue
                try:
                    await asyncio.wait_for(event.wait(), timeout=_FRAME_WAIT)
                except TimeoutError:
                    pass
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
            # A closed browser tab is ordinary; do not stop the shared P2P stream.
            pass
        finally:
            remove()
            self._mjpeg_connections -= 1
            if response is not None:
                try:
                    await response.write_eof()
                except (ConnectionResetError, ConnectionAbortedError, OSError):
                    pass
        # If the user has not pressed Play, HA shows a blank preview; the
        # Play button alone starts P2P. Do not auto-connect from a GET request.
        return response



class SmartAosuStandaloneC9CPreview(SmartAosuC5LPreview):
    """Opt-in, video-only experiment with the C5L P2P pipeline on standalone C9C.

    This is NOT a verified video-capable camera, and exposes no PTZ services.
    """
    _attr_name = 'C9C autonome - vidéo expérimentale'
    _attr_model = 'C9C - essai P2P (sans PTZ)'

    def __init__(self, coordinator, entry_id, device_key):
        super().__init__(coordinator, entry_id, device_key)
        self._attr_unique_id = f'smart_aosu_{entry_id}_c9c_standalone_video_beta'

    @property
    def extra_state_attributes(self):
        result = dict(super().extra_state_attributes)
        result['mode_video'] = 'essai_c5l_p2p_sur_c9c_autonome'
        result['ptz_active'] = False
        result['compatibilite_confirmee'] = False
        return result

class SmartAosuC9H1LPreview(SmartAosuC5LPreview):
    """Manual-only C9 video via the verified C5L HEVC/JPEG decoder."""
    _attr_name="C9 H1L Direct (experimental B139)"
    _attr_model="C9 H1L - LAN MJPEG B139"

    def __init__(self,coordinator,entry_id):
        # No automatic session starts when the entity is created/opened.
        super().__init__(coordinator,entry_id,None)
        self._controller=coordinator.c9_live_b139
        self._attr_unique_id=f"smart_aosu_{entry_id}_c9_h1l_preview_b139"

    @property
    def device_info(self):
        # Avoid falsely associating this camera with the selected C5L.
        return None


class SmartAosuC9H1LPreviewB141(SmartAosuC9H1LPreview):
    """Two independent C9 entities; preserve C9 #2 B139 unique ID."""
    def __init__(self,coordinator,entry_id,number):
        super().__init__(coordinator,entry_id)
        self._camera_numero=number
        self._controller=coordinator.c9_live_b141[number]
        self._attr_name=f'C9 H1L Direct {number}'
        if number==1:
            self._attr_unique_id=f'smart_aosu_{entry_id}_c9_h1l_preview_b141_1'

    def _aosu_name(self):
        """Read the current AOSU display name, never an unverified cloud label."""
        try:
            from .c9_rtc_candidate_b101 import _candidate
            from .c9_h1l_identity_structure_b99 import _match_name
            data=getattr(self._coordinator,'data',None)
            client=getattr(self._coordinator,'client',None)
            if not isinstance(data,dict) or client is None:return None
            did,_=_candidate(data,client,self._camera_numero)
            cache=getattr(client,'_tuya_oem_inventory_cache',{})
            devices=cache.get('devices',{}) if isinstance(cache,dict) else {}
            dev=devices.get(did) if isinstance(devices,dict) else None
            if not isinstance(dev,dict):return None
            matched=[row.get('name') for row in data.values() if isinstance(row,dict)
               and row.get('model')=='C9C3CA11' and row.get('is_camera') is True
               and isinstance(row.get('name'),str) and _match_name(dev,row['name'])]
            return matched[0].strip() if len(matched)==1 and matched[0].strip() else None
        except (ValueError,TypeError,KeyError,AttributeError):return None

    @property
    def extra_state_attributes(self):
        result=dict(super().extra_state_attributes)
        result['camera_numero']=self._camera_numero
        result['session_max_secondes']=None
        name=self._aosu_name()
        if name:result['nom_aosu']=name
        return result
