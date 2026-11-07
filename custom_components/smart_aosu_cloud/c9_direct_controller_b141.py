"""B141: opt-in persistent, per-camera H1L preview using the C5L decoder.
No automatic initial start, no video disk writes, clean STOP and bounded retry rate.
"""
from __future__ import annotations
import asyncio
import threading
from functools import partial
from .tuya_live_preview import LivePreview
from .c9_kcp_direct_b141 import lancer_direct_c9_b141
from .c9_captureless_b144 import direct_sans_capture_b144
from .c9_captureless_b145 import direct_sans_capture_b145
from .c9_context_b141 import CAPTURES
from .c9_attempt_history_b150 import sanitized_attempt, best_control_attempt

class C9DirectControllerB141:
    def __init__(self,hass,coordinator,camera_numero):
        if camera_numero not in CAPTURES:raise ValueError('numero_camera_invalide')
        self.camera_numero=camera_numero
        self.ip_station=None
        self.hass=hass
        self.coordinator=coordinator
        self.preview=None
        self._task=None
        self._stop=threading.Event()
        self._listeners=[]
        self._etat='inactif'
        self._last={}
        self._progress={}
        self._attempts_b150=[]
        self._best_control_b150=None
        self._attempt_no_b150=0

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
          'historique_essais_b150':list(self._attempts_b150),
          'dernier_diagnostic_kcp_exploitable_b150':(dict(self._best_control_b150)
              if self._best_control_b150 is not None else None),
          'progression':dict(self._progress),
          'derniere_cause':str(self._last.get('etat','aucune'))[:90],
          'camera_numero':self.camera_numero,'session_max_secondes':None,
          'limite_temps_direct':False,
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
        # B139 legacy service should not race a B141 live.
        if getattr(getattr(self.coordinator,'c9_live_b139',None),'running',False):
            return {'etat':'direct_c9_legacy_en_cours'}
        if not all(x is True for x in (confirmation_capture_personnelle,confirmation_camera_candidate,
            autoriser_configuration_rtc,autoriser_offre_lan_active,autoriser_test_ice_actif,
            autoriser_test_kcp_actif,autoriser_auth_kcp_active,autoriser_essai_cle_station_b134,
            autoriser_commandes_video_c9_b137,autoriser_direct_c9_b139)):
            return {'etat':'autorisations_actives_completes_requises'}
        if type(camera_numero) is not int or camera_numero!=self.camera_numero or nom_capture!=CAPTURES[camera_numero]:
            return {'etat':'camera_c9_capture_incoherente'}
        from .h1l_local_probe_b103 import _validate_target
        try:station_ip=_validate_target(ip_station)
        except (TypeError,ValueError):return {'etat':'adresse_h1l_invalide'}
        self.ip_station=station_ip
        self._stop=threading.Event()
        preview=LivePreview(on_frame=self._frame_thread)
        if not preview.start():
            return {'etat':'ffmpeg_indisponible_ou_echec'}
        self.preview=preview
        self._etat='negociation_c9'
        args=dict(config_dir=config_dir,nom_capture=nom_capture,ip_station=station_ip,
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
        return {'etat':'demarrage_direct_c9_lance','camera':f'C9 H1L Direct {self.camera_numero}',
            'duree_max_secondes':None,'aucune_video_enregistree':True}

    def start_sans_capture(self,*,ip_station,camera_numero,
            autoriser_reconstitution_oem,confirmation_envoi_mot_de_passe,
            autoriser_direct_c9_b144,diagnostic_b145=False):
        """New B144 direct — same camera entity, NO PCAP path or implied consent."""
        if self.running:return {'etat':'direct_c9_deja_en_cours'}
        if getattr(getattr(self.coordinator,'live_controller',None),'running',False):
            return {'etat':'direct_c5l_en_cours'}
        if getattr(getattr(self.coordinator,'c9_live_b139',None),'running',False):
            return {'etat':'direct_c9_legacy_en_cours'}
        if autoriser_direct_c9_b144 is not True or confirmation_envoi_mot_de_passe is not True:
            return {'etat':'autorisation_direct_b144_requise'}
        if type(camera_numero) is not int or camera_numero!=self.camera_numero:
            return {'etat':'numero_camera_invalide'}
        from .h1l_local_probe_b103 import _validate_target
        try:station_ip=_validate_target(ip_station)
        except (ValueError,TypeError):return {'etat':'adresse_h1l_invalide'}
        self.ip_station=station_ip
        self._stop=threading.Event()
        preview=LivePreview(on_frame=self._frame_thread)
        if not preview.start():return {'etat':'ffmpeg_indisponible_ou_echec'}
        self.preview=preview
        self._etat='negociation_sans_capture_b145' if diagnostic_b145 else 'negociation_sans_capture_b144'
        self._last={}
        self._attempts_b150=[]
        self._best_control_b150=None
        self._attempt_no_b150=0
        self._progress={'etape':'preparation_autorisations'}
        args=dict(camera_numero=camera_numero,ip_station=station_ip,
                  autoriser_reconstitution_oem=autoriser_reconstitution_oem,
                  confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
                  autoriser_direct_c9_b144=True,preview=preview,stop_event=self._stop)
        self._task=self.hass.async_create_task(self._run(args,preview,captureless=True,
            diagnostic_b145=diagnostic_b145))
        self._notify()
        return {'etat':'demarrage_direct_c9_lance','aucun_pcap_necessaire':True,
                'camera_numero':camera_numero,'duree_max_secondes':None}

    def _progress_worker(self,stage,counters):
        self._progress={'etape':stage,**{k:v for k,v in counters.items()
                         if isinstance(v,(int,bool)) or v is None}}
        try:self.hass.loop.call_soon_threadsafe(self._notify)
        except (RuntimeError,AttributeError):pass

    def _save_diagnostic_b150(self, result):
        """Keep ONLY whitelisted structural counters, never private protocol bytes."""
        self._attempt_no_b150+=1
        item=sanitized_attempt(result,self._attempt_no_b150)
        self._attempts_b150=(self._attempts_b150+[item])[-5:]
        useful=best_control_attempt(result,self._attempt_no_b150)
        if useful is not None:
            self._best_control_b150=useful

    async def _run(self,args,preview,captureless=False,diagnostic_b145=False):
        # The user explicitly requested a persistent live. Only an actual
        # disconnect triggers a fresh session, with bounded retry frequency.
        attempts=0
        early_failures=0
        video_start_failures=0
        try:
            while not self._stop.is_set():
                try:
                    job=(direct_sans_capture_b145 if diagnostic_b145 else
                         direct_sans_capture_b144 if captureless else lancer_direct_c9_b141)
                    job_args={**args,'on_progress':self._progress_worker} if diagnostic_b145 else args
                    self._last=await self.hass.async_add_executor_job(partial(
                        job,self.coordinator,**job_args))
                except Exception:
                    self._last={'etat':'erreur_interne_masquee'}
                self._save_diagnostic_b150(self._last)
                if self._stop.is_set():break
                result=self._last.get('etat','termine')
                self._etat='images_decodees' if preview.image() else result
                self._notify()
                # A missing capture, credentials or FFmpeg cannot be corrected
                # by repeatedly hammering the OEM API.
                # Profile and identity failures are configuration problems,
                # NOT network disconnects: never hammer OEM with retries.
                fatal={'autorisations_manquantes','capture_c9_incoherente',
                    'profil_c9_non_reconstructible','profil_demarrage_c9_non_reconstructible',
                    'identite_camera_capture_non_concordante','inventaire_camera_invalide',
                    'inventaire_oem_indisponible','inventaire_absent','station_ambigue',
                    'decodeur_non_prepare','auth_rtc_password_absent',
                    'auth_rtc_cle_station_absente','auth_capture_invalide',
                    'capture_absente','commande_c9_entete_inattendu',
                    'commande_c9_flag_inattendu','commande_c9_parametre_non_reconstructible',
                    'commande_c9_extension_2','reference_camera_non_conforme',
                    'profil_capture_non_reproductible','cle_offre_capture_absente',
                    'auth_schema_identites_non_conforme','inventaire_camera_modifie',
                    'reference_oem_c9_20_octets_ambigue','deux_c9_h1l_introuvables',
                    'correspondance_oem_c9_ambigue','cle_station_h1l_absente',
                    'auth_rtc_password_absent','rtc_jetons_non_remplaces',
                    'nom_aosu_c9_absent','identifiant_station_format_invalide',
                    'cle_locale_c9_specifique_non_prise_en_charge'}
                if diagnostic_b145 and result=='erreur_reseau_ou_timeout' and not self._last.get('offres_0x20_envoyees'):
                    early_failures+=1
                    if early_failures>=2:
                        self._etat='echec_tcp_avant_offre_0x20'
                        self._notify()
                        break
                else:
                    early_failures=0
                if result in fatal:
                    self._etat=result
                    self._notify()
                    break
                # B150: only failed INITIAL media startups are bounded. Once
                # a live stream receives media, it remains unlimited and can
                # recover from genuine subsequent disconnections normally.
                if diagnostic_b145 and not preview.image() and (
                    self._last.get('commandes_video_envoyees',0)>0 and
                    self._last.get('kcp_media_authenticated_passif',0)==0):
                    video_start_failures+=1
                    if video_start_failures>=2:
                        self._etat='echec_demarrage_video_sans_media'
                        self._notify()
                        break
                else:
                    video_start_failures=0
                attempts+=1
                backoff=min(60,max(10,attempts*10))
                self._etat='reconnexion_c9'
                self._notify()
                await self.hass.async_add_executor_job(self._stop.wait,backoff)
        finally:
            await self.hass.async_add_executor_job(preview.stop)
            if self._stop.is_set():self._etat='arret_c9'
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
