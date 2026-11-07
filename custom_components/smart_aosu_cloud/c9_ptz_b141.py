"""C9/H1L PTZ: verified B158 per-camera routing and guarded opt-in.

Preserve B159's short-trial entrypoint for backwards compatibility. The stable
release adds a *per-device* persistent opt-in only after the operator confirms
that direction AND physical STOP have been tested. Only a one-way fingerprint
of the selected camera is stored by Home Assistant; no raw OEM IDs or secrets.
A changed/ambiguous selection disables PTZ. The B83 physical release STOP,
final STOP and independent 12-second watchdog remain untouched.
"""
from __future__ import annotations
import time
import hashlib
import hmac
import re
from .ptz_hold_http_b83 import C5LPtzHoldB83
from .ptz_readiness import _ptz_flags
from .c9_captureless_b144 import _snapshot
from .h1l_local_status_b108 import _cache_state
from .uid_token_probe import _ready_identity, _apk_preflight
from .tuya_uid_gateway import TuyaAuthSession, do_uid_login_request

_TRIAL_SECONDS=120.0
_STOP_FALLBACK_SECONDS=300.0


class C9PtzHoldB141(C5LPtzHoldB83):
    def __init__(self, coordinator, number):
        if type(number) is not int or number not in (1, 2):
            raise ValueError('numero_camera_invalide')
        super().__init__(coordinator)
        self.camera_numero=number
        self._trial_until=0.0
        self._trial_did=None
        self._stable_binding=None
        self._stop_until=0.0
        self._stop_did=None

    def _selection(self):
        """Fail closed unless the *B158 video selector* identifies this C9.

        B141 previously used _candidate() and the old private PCAP. That gate
        diverged from the already working no-PCAP C9 video selection. Only
        return the OEM ID inside the process; never expose it in status.
        """
        client=getattr(self.coordinator,'client',None)
        if _cache_state(client,time.monotonic())!='cache_utilisable':
            return None,None
        station_ip=self._station_ip()
        if station_ip is None:
            return None,None
        try:
            _sid,did,devices,_meta=_snapshot(self.coordinator,self.camera_numero,station_ip)
            row=devices.get(did)
            if not isinstance(did,str) or not isinstance(row,dict):
                return None,None
            return did,row
        except (TypeError, ValueError, KeyError, AttributeError):
            return None,None

    def _station_ip(self):
        controllers=getattr(self.coordinator,'c9_live_b141',{})
        direct=controllers.get(self.camera_numero) if isinstance(controllers,dict) else None
        value=getattr(direct,'ip_station',None)
        if not isinstance(value,str) or not value:
            return None
        try:
            from .h1l_local_probe_b103 import _validate_target
            return _validate_target(value)
        except (TypeError,ValueError):
            return None

    def _confirmed_video(self):
        controllers=getattr(self.coordinator,'c9_live_b141',{})
        live=controllers.get(self.camera_numero) if isinstance(controllers,dict) else None
        if live is None or not getattr(live,'running',False):
            return False
        preview=getattr(live,'preview',None)
        if preview is None:return False
        try:
            return preview.image() is not None
        except Exception:
            return False

    def _trial_valid(self,did,now=None):
        now=time.monotonic() if now is None else now
        return (isinstance(did,str) and did==self._trial_did and 0<=now<self._trial_until)

    def _fingerprint(self,did):
        """Return non-reversible, camera-specific binding; NEVER return the DID."""
        if not isinstance(did,str) or not did:
            return None
        station_ip=self._station_ip()
        if station_ip is None:
            return None
        material=f'smart-aosu-ptz-v1\0{station_ip}\0{self.camera_numero}\0{did}'
        return hashlib.sha256(material.encode('utf-8')).hexdigest()

    def set_stable_binding(self,fingerprint):
        """Only caller can persist grants; status checks active OEM identity."""
        if fingerprint is not None and (not isinstance(fingerprint,str) or
            re.fullmatch(r'[0-9a-f]{64}',fingerprint) is None):
            raise ValueError('empreinte_ptz_invalide')
        with self._lock:
            self._stable_binding=fingerprint

    def stable_binding(self):
        with self._lock:
            return self._stable_binding

    def _stable_valid(self,did):
        current=self._fingerprint(did)
        with self._lock:
            binding=self._stable_binding
        return bool(current and binding and hmac.compare_digest(current,binding))

    def preparer_autorisation_stable(self,*,confirmation_camera_correcte=False,
                                    confirmation_deplacement_et_stop=False):
        """Read-only preflight; no PTZ command and no mutation until HA save."""
        report={'diagnostic':'aosu_c9_ptz_stable_089',
                'camera_numero':self.camera_numero,
                'commandes_envoyees':0,'deplacement_demarre':False,
                'identifiants_retournes':False,'secrets_retournes':False}
        if confirmation_camera_correcte is not True or confirmation_deplacement_et_stop is not True:
            return {**report,'etat':'confirmations_necessaires'},None
        did,row=self._selection()
        if did is None or row is None:
            return {**report,'etat':'identite_c9_non_confirmee'},None
        if not self._confirmed_video():
            return {**report,'etat':'direct_video_c9_requis'},None
        with self._lock:
            if self._closed or self._active is not None:
                return {**report,'etat':'ptz_deja_actif_ou_arrete'},None
        return {**report,'etat':'pret_a_enregistrer'},self._fingerprint(did)

    def status(self):
        result=super().status()
        did,row=self._selection()
        caps=_ptz_flags(row if row is not None else {})
        has_both=bool(caps.get('code_direction_repere') and caps.get('code_arret_repere'))
        active_trial=bool(did and self._trial_valid(did))
        stable_grant=bool(did and self._stable_valid(did))
        video=self._confirmed_video()
        ready=bool(did and (has_both or ((active_trial or stable_grant) and video)))
        result.update({'camera_numero':self.camera_numero,
            'liaison_c9_h1l_confirmee':did is not None,
            'identification_sans_pcap_b158':did is not None,
            'code_direction_oem_present':bool(caps.get('code_direction_repere')),
            'code_arret_oem_present':bool(caps.get('code_arret_repere')),
            'schema_oem_ptz_c9_complet':has_both,
            'essai_ptz_b159_arme':active_trial,
            'autorisation_ptz_stable_active':stable_grant,
            'autorisation_ptz_stable_requiert_video':True,
            'direct_video_confirme':video,
            'secondes_essai_restantes':max(0,int(self._trial_until-time.monotonic())) if active_trial else 0,
            'commandes_ptz_autorisees':ready,
            'transport_ptz_c9_verifie_physiquement':False,
            'confirmation_utilisateur_arret_ptz':stable_grant,
            'arret_physique_mesure':False,
            'schema_ptz_c9_valide_physiquement':False})
        return result

    def autoriser_essai(self,*,confirmation_deplacement=False,confirmation_stop_disponible=False):
        """Manual, per-camera, time-limited trial; never moves the motor here."""
        report={'diagnostic':'aosu_ptz_c9_essai_b159','camera_numero':self.camera_numero,
            'commandes_envoyees':0,'mouvement_demarre':False,
            'secrets_retournes':False,'identifiants_retournes':False,
            'arret_physique_mesure':False}
        if confirmation_deplacement is not True or confirmation_stop_disponible is not True:
            return {**report,'etat':'deux_confirmations_requises'}
        did,row=self._selection()
        if did is None or row is None:
            return {**report,'etat':'identite_c9_non_confirmee'}
        if not self._confirmed_video():
            return {**report,'etat':'direct_video_c9_requis'}
        with self._lock:
            if self._closed or self._active is not None:
                return {**report,'etat':'ptz_deja_actif_ou_arrete'}
            self._trial_did=did
            self._trial_until=time.monotonic()+_TRIAL_SECONDS
        return {**report,'etat':'essai_temporaire_arme','validite_secondes':int(_TRIAL_SECONDS),
            'methode':'oem_http_119_116_experimentale',
            'stop_serveur_possible_non_garanti':True}

    def press(self,direction,gesture_id):
        st=self.status()
        if not st['commandes_ptz_autorisees']:
            return {'etat':'ptz_c9_schema_oem_non_confirme','camera_numero':self.camera_numero,
                    'liaison_c9_h1l_confirmee':st['liaison_c9_h1l_confirmee'],
                    'essai_temporaire_arme':st['essai_ptz_b159_arme'],
                    'autorisation_stable_active':st['autorisation_ptz_stable_active']}
        result=super().press(direction,gesture_id)
        if result.get('etat')=='appui_recu':
            # Emergency STOP must remain possible after trial expiry/release.
            with self._lock:
                self._stop_did=self._trial_did if st['essai_ptz_b159_arme'] else self._selection()[0]
                self._stop_until=time.monotonic()+_STOP_FALLBACK_SECONDS
        return result

    def _params(self):
        did,row=self._selection()
        if did is None:
            raise ValueError('camera_h1l_non_identifiee')
        caps=_ptz_flags(row)
        has_both=bool(caps['code_direction_repere'] and caps['code_arret_repere'])
        now=time.monotonic()
        active_trial=self._trial_valid(did,now)
        # The backup STOP may need another authenticated request after an
        # expired trial. It must not become an authorization for NEW presses.
        stop_window=did==self._stop_did and 0<=now<self._stop_until
        stable_grant=self._stable_valid(did)
        if not (has_both or (stable_grant and self._confirmed_video()) or
                (active_trial and self._confirmed_video()) or stop_window):
            raise ValueError('ptz_c9_schema_oem_non_confirme')
        client=self.coordinator.client
        ready=_ready_identity(client)
        if ready is None:raise ValueError('profil_oem_absent')
        hints,install_id=ready
        _,profile=_apk_preflight(client.apk_path)
        if profile is None:raise ValueError('ressources_oem_invalides')
        identity,signer=profile
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or not 0<=now-session.acquired_at<1200:
            password=getattr(client,'password',None)
            if not isinstance(password,str) or not password:
                raise ValueError('mot_de_passe_absent')
            auth,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,password=password,
                ttid=ttid,device_id=install_id,endpoint='https://a1.tuyaeu.com/api.json')
            if session is None:raise ValueError('session_oem_refusee')
            client._tuya_oem_session=session
        return identity,signer,session,did,ttid,install_id,'c9_h1l_b159_b158_selector',0
