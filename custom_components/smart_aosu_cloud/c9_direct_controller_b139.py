"""B139: opt-in C9 H1L preview controller. No automatic session start.

Uses independent C5L LivePreview decoder, FFmpeg and authenticated HA camera.
No disk writes; one bounded session (75 seconds media, 100 seconds total).
"""
from __future__ import annotations
import asyncio
import threading
from functools import partial
from .tuya_live_preview import LivePreview
from .c9_kcp_direct_b139 import lancer_direct_c9_b139

class C9DirectControllerB139:
    def __init__(self,hass,coordinator):
        self.hass=hass
        self.coordinator=coordinator
        self.preview=None
        self._task=None
        self._stop=threading.Event()
        self._listeners=[]
        self._etat='inactif'
        self._last={}

    @property
    def running(self):
        return self._task is not None and not self._task.done()

    def subscribe(self,fn):
        self._listeners.append(fn)
        def remove():
            if fn in self._listeners:self._listeners.remove(fn)
        return remove

    def _notify(self):
        for cb in list(self._listeners):
            try:cb()
            except (RuntimeError,ValueError):pass

    def _frame_thread(self):
        try:self.hass.loop.call_soon_threadsafe(self._frame_ready)
        except (AttributeError,RuntimeError):pass

    def _frame_ready(self):
        self._etat='images_recues'
        self._notify()

    def image(self):
        return self.preview.image() if self.preview else None

    def status(self):
        return {'etat':self._etat,'direct_actif':self.running,
          'decodage':self.preview.summary() if self.preview else {},
          'dernier_resultat':dict(self._last),
          'session_max_secondes':100,
          'video_enregistree':False,'secrets_retournes':False}

    def start(self,*,config_dir,nom_capture,ip_station,camera_numero,
      confirmation_capture_personnelle,confirmation_camera_candidate,
      autoriser_reconstitution_oem,confirmation_envoi_mot_de_passe,
      autoriser_configuration_rtc,autoriser_offre_lan_active,
      autoriser_test_ice_actif,autoriser_test_kcp_actif,
      autoriser_auth_kcp_active,autoriser_essai_cle_station_b134,
      autoriser_commandes_video_c9_b137,autoriser_direct_c9_b139):
        if self.running:return {'etat':'direct_c9_deja_en_cours'}
        if self.coordinator.live_controller.running:
            return {'etat':'direct_c5l_en_cours'}
        if not all(x is True for x in (confirmation_capture_personnelle,confirmation_camera_candidate,
            autoriser_configuration_rtc,autoriser_offre_lan_active,autoriser_test_ice_actif,
            autoriser_test_kcp_actif,autoriser_auth_kcp_active,autoriser_essai_cle_station_b134,
            autoriser_commandes_video_c9_b137,autoriser_direct_c9_b139)):
            return {'etat':'autorisations_actives_completes_requises'}
        if (type(camera_numero) is not int or camera_numero!=2 or
            nom_capture!='c9_camera_2_reference.pcap'):
            return {'etat':'camera_c9_numero_2_requise'}
        self._stop=threading.Event()
        preview=LivePreview(on_frame=self._frame_thread)
        if not preview.start():
            return {'etat':'ffmpeg_indisponible_ou_echec'}
        self.preview=preview
        self._etat='negociation_c9'
        args=dict(config_dir=config_dir,nom_capture=nom_capture,ip_station=ip_station,
            camera_numero=camera_numero,confirmation_capture_personnelle=True,
            confirmation_camera_candidate=True,
            autoriser_reconstitution_oem=autoriser_reconstitution_oem,
            confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
            autoriser_configuration_rtc=True,autoriser_offre_lan_active=True,
            autoriser_test_ice_actif=True,autoriser_test_kcp_actif=True,
            autoriser_auth_kcp_active=True,autoriser_essai_cle_station_b134=True,
            autoriser_commandes_video_c9_b137=True,autoriser_direct_c9_b139=True,
            preview=preview,stop_event=self._stop)
        self._task=self.hass.async_create_task(self._run(args,preview))
        self._notify()
        return {'etat':'demarrage_direct_c9_lance','camera':'C9 H1L Direct B139',
            'duree_max_secondes':100,'aucune_video_enregistree':True}

    async def _run(self,args,preview):
        try:
            self._last=await self.hass.async_add_executor_job(partial(
                lancer_direct_c9_b139,self.coordinator,**args))
            self._etat=('images_decodees' if preview.image() else self._last.get('etat','termine'))
        except Exception:
            self._last={'etat':'erreur_interne_masquee'}
            self._etat='erreur_interne_masquee'
        finally:
            await self.hass.async_add_executor_job(preview.stop)
            self._notify()

    async def stop(self):
        self._stop.set()
        self._etat='arret_demande'
        self._notify()
        if self._task is not None and not self._task.done():
            try:await asyncio.wait_for(asyncio.shield(self._task),timeout=20)
            except (TimeoutError,asyncio.CancelledError):pass
        return {'etat':'direct_c9_arrete' if not self.running else 'arret_c9_en_cours',
                'aucune_video_enregistree':True}

    async def shutdown(self):
        return await self.stop()
