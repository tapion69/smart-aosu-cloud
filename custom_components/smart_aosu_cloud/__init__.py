"""Smart AOSU Cloud — 0.8.9 stable, video/ptz with opt-in safeguards."""
from __future__ import annotations
from datetime import timedelta
from pathlib import Path
from functools import partial
from homeassistant.const import Platform
from homeassistant.core import SupportsResponse
from homeassistant.exceptions import ServiceValidationError
from .api import AosuCloudClient, AosuCloudError
from .audit_global import summarize_global_inventory, safe_dp_summary
from .media_audit import inspect_media
from .transport_audit import audit_cached_platforms
from .identity_audit import run_identity_capability_probe
from .mqtt_auth_probe import run_mqtt_auth_probe
from .uid_token_probe import run_tuya_uid_token_probe, run_tuya_uid_preflight, run_tuya_uid_login_probe
from .tuya_rtc_inventory import run_tuya_oem_inventory
from .tuya_capture_decode import decode_latest_capture
from .tuya_live_preview import LiveController
from .c9_direct_controller_b139 import C9DirectControllerB139
from .c9_direct_controller_b141 import C9DirectControllerB141
from .c9_captureless_b144 import audit_preparation_sans_capture_b144
from .c9_profile_comparison_b147 import comparer_profil_b147
from .c9_routing_audit_b151 import audit_routage_station_c9_b151
from .c9_success_reply_audit_b153 import audit_reponses_station_c9_b153
from .c9_ptz_b141 import C9PtzHoldB141
from .camera_compatibility import audit_camera_compatibility
from .c9_h1l_preflight_b98 import audit_c9_h1l_bridge
from .c9_h1l_identity_structure_b99 import audit_c9_oem_structure
from .c9_h1l_oem_detail_b100 import audit_oem_details_c9_h1l_b100
from .c9_rtc_candidate_b101 import read_c9_rtc_b101
from .h1l_local_probe_b103 import audit_local_h1l_b103
from .h1l_local_auth_b104 import audit_local_station_auth_b104
from .h1l_station_rtc_b105 import audit_station_rtc_b105
from .h1l_local_status_b107 import audit_h1l_read_status_b107
from .h1l_local_status_b108 import audit_h1l_local_status_b108
from .h1l_local_status_b109 import audit_h1l_local_status_b109
from .h1l_local_status_b110 import audit_h1l_local_status_b110
from .h1l_pcap_offline_b111 import audit_capture_h1l_b111 as analyse_capture_h1l_b111
from .c9_lan_signal_b119 import essai_negociation_lan_c9_b119 as lancer_essai_lan_c9_b119
from .c9_lan_signal_b120 import essai_negociation_lan_c9_b120 as lancer_essai_lan_c9_b120
from .c9_lan_signal_b121 import essai_negociation_lan_c9_b121 as lancer_essai_lan_c9_b121
from .c9_lan_signal_b122 import essai_negociation_lan_c9_b122 as lancer_essai_lan_c9_b122
from .c9_video_preflight_b123 import audit_preparation_video_c9_b123 as lancer_audit_c9_b123
from .c9_offer_gap_b124 import audit_ecarts_offre_video_c9_b124 as lancer_audit_c9_b124
from .c9_lan_signal_b125 import essai_negociation_lan_c9_b125 as lancer_essai_lan_c9_b125
from .c9_ice_lan_b126 import essai_connectivite_ice_c9_b126 as lancer_essai_ice_c9_b126
from .c9_ice_lan_b127 import essai_connectivite_ice_c9_b127 as lancer_essai_ice_c9_b127
from .c9_kcp_bootstrap_b128 import audit_bootstrap_kcp_c9_b128 as lancer_audit_kcp_c9_b128
from .c9_kcp_transport_b129 import essai_transport_kcp_c9_b129 as lancer_transport_kcp_c9_b129
from .c9_kcp_auth_profile_b130 import audit_auth_kcp_c9_b130 as lancer_audit_auth_c9_b130
from .c9_kcp_auth_b130 import essai_authentification_kcp_c9_b130 as lancer_auth_kcp_c9_b130
from .c9_kcp_auth_audit_b131 import audit_details_auth_kcp_c9_b131 as lancer_details_auth_c9_b131
from .c9_kcp_auth_identity_b132 import audit_correspondances_auth_c9_b132 as lancer_correspondances_auth_c9_b132
from .c9_kcp_auth_rtc_b133 import audit_schema_auth_c9_b133 as lancer_schema_auth_c9_b133, essai_auth_rtc_c9_b133 as lancer_essai_auth_c9_b133
from .c9_kcp_video_start_b137 import audit_profil_demarrage_c9_b137 as lancer_profil_video_b137, essai_demarrage_video_c9_b137 as lancer_demarrage_video_b137
from .c9_kcp_video_analyse_b138 import essai_analyse_media_c9_b138 as lancer_analyse_media_b138
from .c9_kcp_command_fields_b136 import audit_champs_commandes_c9_b136 as lancer_audit_champs_b136
from .c9_kcp_next_commands_b135 import audit_commandes_apres_auth_c9_b135 as lancer_audit_kcp_suite_b135
from .c9_kcp_auth_gateway_b134 import audit_cle_h1l_c9_b134 as lancer_audit_cle_h1l_c9_b134, essai_auth_station_c9_b134 as lancer_essai_auth_station_c9_b134
from .c9_ipc_config_b106 import audit_c9_ipc_config_b106
from .ptz_readiness import audit_ptz_readiness, refresh_ptz_inventory
from .ptz_device_detail_b39 import audit_ptz_device_detail_with_refresh
from .ptz_stop_probe_b40 import probe_ptz_stop_with_refresh
from .ptz_stop_numeric_b45 import test_stop_dp116_with_refresh
from .ptz_publication_b43 import audit_ptz_publication
from .ptz_mqtt_preflight_b46 import audit_mqtt_encoder_readiness
from .ptz_sdk_sources_b47 import audit_sources_ptz_c5l
from .ptz_product_model_b51 import audit_product_model
from .ptz_product_capability_b78 import audit_product_info_b78
from .ptz_stop_alternate_api_b79 import test_alternate_stop_b79_with_refresh
from .ptz_state_observer_b80 import audit_ptz_state_b80
from .ptz_right_test_b81 import try_right_with_refresh, emergency_stop_b81
from .ptz_direction_test_b82 import try_direction_with_refresh
from .ptz_hold_http_b83 import C5LPtzHoldB83
from .ptz_mqtt_transport_b53 import audit_ptz_mqtt_transport
from .ptz_mqtt_stop_b54 import test_mqtt_stop_once
from .ptz_live_control_b56 import ExperimentalPtzLiveController
from .ptz_packet_size_b69 import audit_packet_size_b69
from .coordinator import SmartAosuCloudCoordinator
from .const import CONF_EMAIL, CONF_PASSWORD, DOMAIN, CONF_SCAN_INTERVAL, CONF_STATION_IP, DEFAULT_SCAN_INTERVAL, ALLOWED_SCAN_INTERVALS
from .network_config import optional_station_ip
from .camera_topology import select_standalone_c9c_key, select_tuya_standalone_target
from .c9c_identity_diagnostic import inspect_c9c_identity_cache
from .c9c_detail_probe import probe_c9c_detail
PLATFORMS=[Platform.SENSOR, Platform.BINARY_SENSOR, Platform.IMAGE, Platform.CAMERA, Platform.BUTTON]

async def async_setup(hass,config):
    def _station_ip_for_call(call):
        """Use explicit card IP first; otherwise configured account station IP.

        Never infer an arbitrary station from other HA entries. The existing
        controllers still validate the selected IP before LAN requests.
        """
        raw = call.data.get('ip_station')
        if raw not in (None, ''):
            return raw
        entries = hass.config_entries.async_entries(DOMAIN)
        if len(entries) != 1:
            return None
        entry = entries[0]
        ip = entry.options.get(CONF_STATION_IP, entry.data.get(CONF_STATION_IP, ''))
        try:
            return optional_station_ip(ip) or None
        except ValueError:
            return None

    # Serve only public JS. Credentials never leave HA's authenticated services.
    from homeassistant.components.http import StaticPathConfig
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/ptz-hold-b56.js',
                str(Path(__file__).resolve().parent/'frontend'/'ptz-hold-b56.js'),False),
            StaticPathConfig('/smart-aosu/ptz-hold-b57.js',
                str(Path(__file__).resolve().parent/'frontend'/'ptz-hold-b57.js'),False),
            StaticPathConfig('/smart-aosu/ptz-hold-b83.js',
                str(Path(__file__).resolve().parent/'frontend'/'ptz-hold-b83.js'),False),
            StaticPathConfig('/smart-aosu/ptz-hold-b84.js',
                str(Path(__file__).resolve().parent/'frontend'/'ptz-hold-b84.js'),False)
        ])
    except RuntimeError:
        # Path can survive an integration reload.
        pass
    # B141 new public JS resource for the two C9 cards; old resources preserved.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b141.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b141.js'),False)
        ])
    except RuntimeError:
        pass
    # Video-only standalone C9C trial. This JS contains no PTZ controls.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9c-autonome-b1.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9c-autonome-b1.js'),False)
        ])
    except RuntimeError:
        pass
    # B142: new named C9 card and C5L 16:9/fullscreen card. Existing resources untouched.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b142.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b142.js'),False),
            StaticPathConfig('/smart-aosu/ptz-hold-b142.js',
                str(Path(__file__).resolve().parent/'frontend'/'ptz-hold-b142.js'),False)
        ])
    except RuntimeError:
        pass
    # B143: opt-in diagnostic card; no existing resources removed or changed.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b143.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b143.js'),False)
        ])
    except RuntimeError:
        pass
    # B145: dedicated progress card; the B144 path and other cameras stay available.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b146.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b146.js'),False)
        ])
    except RuntimeError:
        pass
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b145.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b145.js'),False)
        ])
    except RuntimeError:
        pass
    # B144: new capture-free C9 card; original B143 and C5L resources untouched.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b144.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b144.js'),False)
        ])
    except RuntimeError:
        pass
    # C9 B140: add a separate opt-in Lovelace card; C5L static paths untouched.
    try:
        await hass.http.async_register_static_paths([
            StaticPathConfig('/smart-aosu/c9-live-b140.js',
                str(Path(__file__).resolve().parent/'frontend'/'c9-live-b140.js'),False)
        ])
    except RuntimeError:
        # The path may already exist after an integration reload.
        pass

    async def inspect(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN) if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        client=loaded[0].runtime_data.client
        try:
            return await hass.async_add_executor_job(client.inspect_dp_schema)
        except AosuCloudError as exc:
            # Only fixed privacy-preserving errors are exposed; no raw server body.
            raise ServiceValidationError(str(exc)) from exc
    async def inspect_cached(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN) if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        try:
            # No network call: returns the sanitized schema cached by normal polling.
            return loaded[0].runtime_data.client.inspect_cached_metadata()
        except AosuCloudError as exc:
            raise ServiceValidationError(str(exc)) from exc

    async def audit_global(call):
        """One manual run: fresh inventory plus at most one DP read, no commands.

        The cached metadata was sanitized during refresh. The optional DP probe
        obeys the existing once-per-hour rate limiter in AosuCloudClient.
        """
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN) if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        coordinator=loaded[0].runtime_data
        # Explicitly requested inventory read, using the established session.
        # The periodic updater is not reconfigured by this service.
        await coordinator.async_refresh()
        if not coordinator.last_update_success or not isinstance(coordinator.data,dict):
            raise ServiceValidationError("Inventaire AOSU non accessible : verifier la connexion cloud")
        try:
            meta=coordinator.client.inspect_cached_metadata()
            report=summarize_global_inventory(coordinator.data,meta)
        except (AosuCloudError, ValueError) as exc:
            raise ServiceValidationError("Inventaire valide mais diagnostic global indisponible") from exc
        report["requete_getList"]={"etat":"reussie","actualisation_manuelle":True}
        # Explicit manual service invocation is opt-in to one additional read.
        # A repeated run in the same session is limited by the DP throttle.
        try:
            dp=await hass.async_add_executor_job(coordinator.client.inspect_dp_schema)
            report["requete_getValues"] = safe_dp_summary(dp)
        except AosuCloudError as exc:
            # Do not reveal server text or account/device secrets in service output.
            description=str(exc)
            if "une tentative par heure" in description:
                status="limite_une_par_heure"
            elif "Session ou liste" in description:
                status="session_non_disponible"
            else:
                status="erreur_de_lecture"
            report["requete_getValues"]={"etat":status}
        report["autres_api"]={
            "getFieldValues":"non_testee_sans_liste_dp_validee",
            "appSetting_getBySn":"non_testee_formulaire_non_valide",
            "event_getList":"non_testee_filtres_non_valides",
            "sts_getPlayInfo":"non_testee_autorisations_video_hors_perimetre",
        }
        report["appels_http_lecture_prevus"]=2
        report["note_reconnexion"]="Une connexion supplementaire peut etre requise si la session est expiree"
        report["commandes_envoyees_aux_cameras"]=0
        return report

    async def audit_objectifs(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN) if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        coordinator=loaded[0].runtime_data
        try:
            return await hass.async_add_executor_job(inspect_media,coordinator.client)
        except AosuCloudError as exc:
            # Fixed descriptions only, never a server response.
            if "une tentative par heure" in str(exc):
                raise ServiceValidationError("Diagnostic media limite a une tentative par heure") from exc
            raise ServiceValidationError("Session media indisponible ; verifier les appareils et la connexion") from exc

    async def audit_transport(call):
        """Determine C5L Gz/Ty and Tuya reference availability from existing getList cache; zero HTTP."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        coordinator=loaded[0].runtime_data
        if not coordinator.last_update_success:
            raise ServiceValidationError("Inventaire AOSU non disponible")
        return audit_cached_platforms(coordinator.data)

    async def audit_liaison_tuya(call):
        """At most two read-only API requests, explicit user action only."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        coordinator=loaded[0].runtime_data
        return await hass.async_add_executor_job(run_identity_capability_probe,coordinator.client)

    async def audit_oem_uid(call):
        """Inspect ONLY the previous AOSU login response cached in RAM."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration AOSU active necessaire")
        return loaded[0].runtime_data.client.inspect_oem_uid_status()

    async def audit_provider_p2p(call):
        """Read only already sanitized data from the last successful AOSU poll."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration AOSU active necessaire")
        report=loaded[0].runtime_data.client._provider_snapshot
        if report is None:
            raise ServiceValidationError("Attendre une actualisation reussie de l'inventaire")
        import copy
        return copy.deepcopy(report)

    async def audit_mqtt_authorisation(call):
        """Manual Gz AWS MQTT auth POST using APK-verified type; never Tuya login."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        # Explicit user action only; don't retry on failure or refresh login.
        return await hass.async_add_executor_job(
            run_mqtt_auth_probe,loaded[0].runtime_data.client)

    async def audit_tuya_uid_token(call):
        """Single user-triggered token-only call, no password and no streaming."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        return await hass.async_add_executor_job(
            run_tuya_uid_token_probe, loaded[0].runtime_data.client)

    async def audit_tuya_uid_login(call):
        """Explicit opt-in only: sends RSA-encrypted AOSU password to OEM Tuya."""
        if call.data.get("confirmation_envoi_mot_de_passe") is not True:
            raise ServiceValidationError("Confirmer explicitement l'envoi chiffre du mot de passe AOSU a Tuya")
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration AOSU active necessaire")
        return await hass.async_add_executor_job(
            partial(run_tuya_uid_login_probe,loaded[0].runtime_data.client,confirmation_envoi_mot_de_passe=True))

    async def audit_tuya_oem_inventory(call):
        """One user-triggered OEM inventory with optional RTC read, never media."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration AOSU active necessaire")
        opts=call.data
        return await hass.async_add_executor_job(partial(
            run_tuya_oem_inventory,loaded[0].runtime_data.client,
            confirmation_envoi_mot_de_passe=opts.get('confirmation_envoi_mot_de_passe') is True,
            tester_rtc=opts.get('tester_rtc') is True,
            autoriser_candidat_unique=opts.get('autoriser_candidat_unique') is True,
            autoriser_correspondance_nom_unique=opts.get('autoriser_correspondance_nom_unique') is True,
            tester_mqtt=opts.get('tester_mqtt') is True,
            tester_offre_mqtt=opts.get('tester_offre_mqtt') is True,
            confirmation_offre_mqtt=opts.get('confirmation_offre_mqtt') is True,
            tester_relais_tcp=opts.get('tester_relais_tcp') is True,
            confirmation_relais_tcp=opts.get('confirmation_relais_tcp') is True,
            tester_kcp=opts.get('tester_kcp') is True,
            confirmation_kcp=opts.get('confirmation_kcp') is True,
            tester_media=opts.get('tester_media') is True,
            confirmation_media=opts.get('confirmation_media') is True,
            capturer_media_localement=opts.get('capturer_media_localement') is True,
            confirmation_capture_locale=opts.get('confirmation_capture_locale') is True,
            repertoire_capture_locale=hass.config.path('smart_aosu_cloud','diagnostics')))

    async def decoder_capture_video_locale(call):
        """Decode an explicitly authorized existing capture. Zero network requests."""
        if call.data.get('confirmation_analyse_capture') is not True:
            raise ServiceValidationError('Confirmer l analyse locale des images potentiellement privees')
        return await hass.async_add_executor_job(partial(
            decode_latest_capture,
            hass.config.path('smart_aosu_cloud','diagnostics'),
            user_confirmed=True,
            save_private_preview=call.data.get('enregistrer_apercu_prive') is True))

    def _loaded_direct_controller():
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1 or getattr(loaded[0].runtime_data,'live_controller',None) is None:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return loaded[0].runtime_data.live_controller

    async def demarrer_direct_c5l(call):
        if call.data.get('confirmation_envoi_mot_de_passe') is not True or call.data.get('confirmation_camera_c5l') is not True:
            raise ServiceValidationError('Confirmer le login Tuya et la camera candidate avant le direct')
        return _loaded_direct_controller().start(password_confirmed=True,candidate_confirmed=True)

    async def diagnostiquer_identite_c9c_autonome(call):
        """Explicit read-only identity comparison, with optional Tuya cloud refresh.

        Refresh only the account's Tuya device inventory if cache is absent
        or older than ten minutes. Never ask for RTC, publish an MQTT offer,
        start a camera, move motors, return names, identifiers or passwords.
        """
        if call.data.get('confirmation_lecture_tuya') is not True:
            raise ServiceValidationError('Confirmer la lecture de l inventaire Tuya')
        entries=[e for e in hass.config_entries.async_entries(DOMAIN)
                 if getattr(e,'runtime_data',None)]
        if len(entries) != 1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise')
        runtime=entries[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une C9C autonome unique sans H1L est requise')
        client=runtime.client
        import time
        cache=getattr(client,'_tuya_oem_inventory_cache',None)
        refreshed=False
        network_calls=0
        created=cache.get('created') if isinstance(cache,dict) else None
        try:
            fresh=(isinstance(cache.get('devices'),dict) and
                   0 <= time.monotonic()-float(created) <= 600)
        except (AttributeError,TypeError,ValueError,OverflowError):
            fresh=False
        if not fresh:
            # Manual button authorizes a normal Tuya UID login when required,
            # and read-only home/group list calls. The existing rate limits
            # are kept; no RTC, MQTT, KCP, video or PTZ requests are made.
            inventory=await hass.async_add_executor_job(partial(
                run_tuya_oem_inventory,client,
                confirmation_envoi_mot_de_passe=True,tester_rtc=False,
                tester_mqtt=False,tester_offre_mqtt=False,tester_media=False))
            calls=inventory.get('appel_reseau')
            network_calls=min(20,max(0,calls)) if type(calls) is int else 0
            refreshed=True
            if inventory.get('etat') != 'inventaire_termine':
                status=inventory.get('etat')
                allowed=('test_deja_en_cours','limite_inventaire_30_minutes',
                    'limite_login_une_heure','login_UID_non_reussi',
                    'session_AOSU_ou_profil_absent','preflight_OEM_invalide',
                    'lecture_maisons_refusee','groupes_non_identifies',
                    'erreur_api_tuya','erreur_execution_sans_details')
                return {
                    'diagnostic':'aosu_c9c_identite_cache_b5',
                    'etat':'lecture_tuya_non_disponible',
                    'cause':status if status in allowed else 'autre',
                    'appels_reseau':network_calls,'commandes_camera':0,
                    'commandes_ptz':0,'video_lancee':False,
                    'identifiants_retournes':False,'secrets_retournes':False,
                }
            cache=getattr(client,'_tuya_oem_inventory_cache',None)
        result=inspect_c9c_identity_cache(
            data=runtime.data,client=client,cache=cache,
            select_standalone=select_standalone_c9c_key,
            select_tuya=select_tuya_standalone_target)
        result['actualisation_inventaire_tuya']=refreshed
        result['appels_reseau']=network_calls
        return result

    async def diagnostiquer_fiche_c9c_autonome(call):
        """Manual read-only AOSU detailed device lookup for one standalone C9C."""
        if call.data.get('confirmation_lecture_fiche') is not True:
            raise ServiceValidationError('Confirmer la lecture de la fiche AOSU')
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise')
        runtime=loaded[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une seule C9C autonome sans H1L est requise')
        return await hass.async_add_executor_job(probe_c9c_detail, runtime.client)

    async def diagnostiquer_rtc_c9c_autonome(call):
        """One explicit read of RTC metadata; no MQTT, offer, camera or PTZ."""
        if call.data.get('confirmation_lecture_rtc') is not True:
            raise ServiceValidationError('Confirmer la lecture RTC expérimentale')
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise')
        runtime=loaded[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une C9C autonome unique sans station est requise')
        report=await hass.async_add_executor_job(partial(
            run_tuya_oem_inventory, runtime.client,
            confirmation_envoi_mot_de_passe=True, tester_rtc=True,
            standalone_c9c_rtc_audit=True, tester_mqtt=False,
            tester_offre_mqtt=False, tester_relais_tcp=False,
            tester_kcp=False, tester_media=False))
        allowed_status={
            'configuration_rtc_obtenue','rtc_non_lance_c9c_non_identifiee',
            'configuration_rtc_refusee','erreur_api_tuya',
            'session_AOSU_ou_profil_absent','preflight_OEM_invalide',
            'limite_inventaire_30_minutes','limite_login_une_heure',
            'limite_rtc_cinq_minutes','test_deja_en_cours',
            'login_UID_non_reussi','lecture_maisons_refusee',
            'groupes_non_identifies','erreur_execution_sans_details',
            'audit_rtc_c9c_lecture_seule_uniquement',
        }
        selection=report.get('methode_selection_rtc')
        allowed_selection={'identite_exacte','camera_tuya_unique_non_confirmee',
            'appareil_tuya_unique_sans_categorie_video',
            'appareil_tuya_unique_categorie_non_video',
            'aucune_camera_tuya_identifiable',
            'cameras_tuya_multiples_ambigues','correspondance_ambigue'}
        safe=report.get('rtc_c9c_schema')
        return {
            'diagnostic':'aosu_c9c_rtc_passif_b8',
            'etat':report.get('etat') if report.get('etat') in allowed_status else 'autre',
            'selection':selection if selection in allowed_selection else 'non_disponible',
            'rtc_acceptee':report.get('configuration_rtc_acceptee') is True,
            'schema':safe if isinstance(safe,dict) else None,
            'appels_reseau':min(20, max(0,report.get('appel_reseau',0)))
                if type(report.get('appel_reseau')) is int else 0,
            'commandes_camera':0,'video_lancee':False,
            'identifiants_retournes':False,'secrets_retournes':False,
        }

    async def comparer_rtc_ipc_v4_c9c_autonome(call):
        """Inspect IPC-v4 RTC API; no offer, signaling or camera command."""
        if call.data.get('confirmation_lecture_rtc_v4') is not True:
            raise ServiceValidationError('Confirmer la lecture RTC IPC-v4')
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise')
        runtime=loaded[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une seule C9C autonome sans station est requise')
        if runtime.live_controller.running:
            raise ServiceValidationError('Arreter le direct HA avant ce diagnostic')
        report=await hass.async_add_executor_job(partial(
            run_tuya_oem_inventory,runtime.client,
            confirmation_envoi_mot_de_passe=True,tester_rtc=True,
            standalone_c9c_v4_rtc_audit=True,tester_mqtt=False,
            tester_offre_mqtt=False,tester_relais_tcp=False,
            tester_kcp=False,tester_media=False))
        schema=report.get('rtc_v4_schema')
        safe_schema={}
        allowed_schema_keys=(
            'p2p_config_presente','session_presente','moto_id_present',
            'serveurs_ice_presents','serveur_turn_dans_ices',
            'relais_tcp_declare','relais_udp_declare','cle_locale_presente',
            'session_id_present')
        if isinstance(schema,dict):
            safe_schema={k:schema.get(k) is True for k in allowed_schema_keys}
            pv=schema.get('version_mqtt_pv_connue')
            safe_schema['version_mqtt_pv_connue']=pv if pv in ('2.2','2.3') else 'non_identifiee'
        allowed_status=(
            'configuration_rtc_obtenue','configuration_rtc_refusee',
            'rtc_non_lance_c9c_non_identifiee','limite_inventaire_30_minutes',
            'limite_login_une_heure','limite_rtc_cinq_minutes',
            'login_UID_non_reussi','test_deja_en_cours',
            'session_AOSU_ou_profil_absent','preflight_OEM_invalide',
            'lecture_maisons_refusee','groupes_non_identifies',
            'erreur_api_tuya','erreur_execution_sans_details',
            'audit_rtc_v4_c9c_lecture_seule_uniquement')
        state=report.get('etat')
        # Backend errors are fixed local codes or raw vendor refusals.
        # Never echo untrusted reasons to the browser, only fixed categories.
        reason=report.get('raison')
        if state=='configuration_rtc_refusee':
            origine_echec='refus_du_serveur'
        elif state=='erreur_api_tuya':
            if reason in (
                'api_lecture_non_autorisee','parametres_lecture_invalides',
                'version_api_invalide','destination_non_autorisee',
                'identite_installation_invalide','session_tuya_absente'):
                origine_echec='validation_locale'
            elif reason in (
                'http_non_200','reponse_non_chiffree_ou_absente',
                'reponse_trop_volumineuse'):
                origine_echec='reponse_http_invalide'
            elif reason=='reseau_ou_reponse_invalide':
                origine_echec='reseau_ou_dechiffrement'
            else:
                origine_echec='erreur_inconnue'
        elif state=='configuration_rtc_obtenue':
            origine_echec='aucune'
        else:
            origine_echec='non_determinee'
        return {
            'diagnostic':'aosu_c9c_rtc_v4_passif_b14',
            'origine_echec':origine_echec,
            'etat':state if state in allowed_status else 'autre',
            'rtc_ipc_v4_accepte':report.get('configuration_rtc_acceptee') is True,
            'configuration_media_complete':report.get('media_v4_pret') is True,
            'schema':safe_schema,
            'offres_envoyees':0,'commandes_camera':0,'commandes_ptz':0,
            'video_lancee':False,'secrets_retournes':False,
            'identifiants_retournes':False,
            'selection_non_confirmee':True,
        }

    async def comparer_webrtc_c9c_autonome_b23(call):
        """Read IPC-v4 RTC WebRTC metadata and optionally subscribe, never publish."""
        if call.data.get('confirmation_lecture_webrtc') is not True:
            raise ServiceValidationError('Confirmer la lecture WebRTC')
        listen=call.data.get('confirmation_ecoute_webrtc') is True
        entries=[e for e in hass.config_entries.async_entries(DOMAIN)
                 if getattr(e,'runtime_data',None)]
        if len(entries)!=1:
            raise ServiceValidationError('Une seule configuration AOSU requise')
        runtime=entries[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une C9C autonome unique sans H1L requise')
        if runtime.live_controller.running:
            raise ServiceValidationError('Arreter le direct HA avant ce diagnostic')
        report=await hass.async_add_executor_job(partial(
            run_tuya_oem_inventory,runtime.client,
            confirmation_envoi_mot_de_passe=True,tester_rtc=True,
            standalone_c9c_webrtc_audit=True,
            standalone_c9c_webrtc_channel=listen,
            tester_mqtt=False,tester_offre_mqtt=False,
            tester_relais_tcp=False,tester_kcp=False,tester_media=False))
        raw=report.get('webrtc_b23')
        raw=raw if isinstance(raw,dict) else {}
        fields=('moto_id_present','auth_webrtc_present','msid_explicite_present',
                'msid_ambigu','webrtc_declare_oui','webrtc_declare_non',
                'webrtc_declaration_ambigue','ipc_aes_kcp_present',
                'offre_webrtc_preparee','signalisation_webrtc_confirmee',
                'abonnement_mqtt_possible')
        schema={key:raw.get(key) is True for key in fields}
        chan=report.get('webrtc_canal_b23')
        chan=chan if isinstance(chan,dict) else {}
        allowed_states=('configuration_rtc_obtenue','rtc_non_lance_c9c_non_identifiee',
                'configuration_rtc_refusee','limite_inventaire_30_minutes',
                'limite_login_une_heure','limite_rtc_cinq_minutes',
                'login_UID_non_reussi','test_deja_en_cours',
                'session_AOSU_ou_profil_absent','preflight_OEM_invalide',
                'lecture_maisons_refusee','groupes_non_identifies',
                'erreur_api_tuya','erreur_execution_sans_details',
                'audit_webrtc_c9c_lecture_seule_uniquement')
        channel_states=('msid_explicite_manquant','test_deja_en_cours',
                'limite_dix_minutes','cible_invalide','identite_mqtt_indisponible',
                'connexion_refusee','suback_invalide','abonnement_accepte',
                'abonnement_refuse','certificat_tls_invalide','mqtt_timeout',
                'reseau_mqtt_indisponible','trame_mqtt_invalide')
        return {
            'diagnostic':'aosu_c9c_webrtc_b23',
            'etat':report.get('etat') if report.get('etat') in allowed_states else 'autre',
            'rtc_acceptee':report.get('configuration_rtc_acceptee') is True,
            'schema':schema,
            'test_canal_demande':listen,
            'canal':{
                'etat':(chan.get('etat') if chan.get('etat') in channel_states
                        else 'non_teste' if not listen else 'inconnu'),
                'mqtt_tls':chan.get('mqtt_tls') is True,
                'mqtt_connack':chan.get('mqtt_connack') is True,
                'abonnement_accepte':chan.get('abonnement_accepte') is True,
            },
            'offres_envoyees':0,'commandes_camera':0,'commandes_ptz':0,
            'video_lancee':False,'identifiants_retournes':False,
            'secrets_retournes':False,
        }

    async def tester_reveil_c9c_autonome(call):
        """Explicit experimental wake packet; does not start preview or PTZ."""
        if call.data.get('confirmation_reveil_experimental') is not True:
            raise ServiceValidationError('Autoriser explicitement le test de reveil')
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise')
        runtime=loaded[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une seule C9C autonome sans station est requise')
        if runtime.live_controller.running:
            raise ServiceValidationError('Arreter le direct HA avant le reveil')
        report=await hass.async_add_executor_job(partial(
            run_tuya_oem_inventory,runtime.client,
            confirmation_envoi_mot_de_passe=True,
            tester_rtc=True,tester_mqtt=True,
            standalone_c9c_wake_only=True,
            tester_offre_mqtt=False,tester_relais_tcp=False,
            tester_kcp=False,tester_media=False))
        wake=report.get('reveil_c9c')
        wake=wake if isinstance(wake,dict) else {}
        allowed={
            'observation_terminee','mqtt_connexion_refusee',
            'mqtt_abonnement_refuse','identite_reveil_invalide',
            'certificat_tls_invalide','delai_mqtt_depasse',
            'reseau_mqtt_indisponible','trame_mqtt_invalide',
            'test_reveil_deja_en_cours','limite_reveil_dix_minutes',
            'configuration_rtc_expiree','session_tuya_incoherente',
            'preparation_reveil_invalide'}
        prep=report.get('etat')
        prep_allowed={
            'configuration_rtc_obtenue','limite_rtc_cinq_minutes',
            'limite_login_une_heure','limite_inventaire_30_minutes',
            'login_UID_non_reussi','test_deja_en_cours',
            'rtc_non_lance_c9c_non_identifiee','configuration_rtc_refusee',
            'erreur_api_tuya','test_reveil_c9c_manuel_uniquement'}
        def count(name):
            n=wake.get(name)
            return min(100,max(0,n)) if type(n) is int else 0
        return {
            'diagnostic':'aosu_c9c_reveil_manuel_b19',
            'etat':wake.get('etat') if wake.get('etat') in allowed else 'non_lance',
            'preparation':prep if prep in prep_allowed else 'autre',
            'wake_envoye':wake.get('wake_envoye') is True,
            'puback_wake':wake.get('puback_wake') is True,
            'dp149_vrai':count('dp149_vrai'),
            'dp149_faux':count('dp149_faux'),
            'messages_appareil':count('messages_appareil'),
            'messages_dechiffres':count('messages_dechiffres'),
            'requetes_reveil':count('requetes_reveil'),
            'confirmation_reveil':(
                'dp149_true_observe' if wake.get('confirmation_reveil')=='dp149_true_observe'
                else 'non_confirmee'),
            'video_lancee':False,'commandes_ptz':0,
            'identifiants_retournes':False,
            'secrets_retournes':False,'payloads_conserves':False,
        }

    async def observer_mqtt_c9c_autonome(call):
        """Watch known MQTT topics while the owner opens the official app live."""
        if call.data.get('confirmation_ecoute_mqtt') is not True:
            raise ServiceValidationError('Confirmer l ecoute MQTT passive')
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise')
        runtime=loaded[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une seule C9C autonome sans station est requise')
        if runtime.live_controller.running:
            raise ServiceValidationError('Arreter le direct Home Assistant avant cet essai')
        report=await hass.async_add_executor_job(partial(
            run_tuya_oem_inventory, runtime.client,
            confirmation_envoi_mot_de_passe=True,
            tester_rtc=True, tester_mqtt=True,
            standalone_c9c_mqtt_watch=True,
            tester_offre_mqtt=False, tester_relais_tcp=False,
            tester_kcp=False, tester_media=False))
        watch=report.get('signalisation_mqtt')
        watch=watch if isinstance(watch,dict) else {}
        selection=report.get('methode_selection_rtc')
        permitted={'identite_exacte','camera_tuya_unique_non_confirmee',
                   'appareil_tuya_unique_sans_categorie_video',
                   'aucune_camera_tuya_identifiable'}
        safe_status={'ecoute_terminee','uid_indisponible','connexion_mqtt_refusee',
                     'abonnement_inattendu','aucun_abonnement_accepte',
                     'certificat_tls_non_valide','mqtt_timeout',
                     'trame_mqtt_inattendue','erreur_reseau_mqtt',
                     'ecoute_deja_en_cours','limite_ecoute_dix_minutes',
                     'rtc_expire','session_incoherente',
                     'identite_mqtt_indisponible','device_id_indisponible'}
        state=watch.get('etat')
        cache_sleep = report.get('veille_inventaire_c9c')
        cache_sleep = cache_sleep if isinstance(cache_sleep,dict) else {}
        low_power = cache_sleep.get('low_power_hint')
        low_power = low_power if low_power in ('oui','non','inconnu') else 'inconnu'
        def count(field):
            x=watch.get(field)
            return min(100,max(0,x)) if type(x) is int else 0
        return {
            'diagnostic':'aosu_c9c_mqtt_passif_b18',
            'etat':state if state in safe_status else 'non_lance',
            'preparation':report.get('etat') if report.get('etat') in
                ('configuration_rtc_obtenue','limite_rtc_cinq_minutes',
                 'limite_login_une_heure','limite_inventaire_30_minutes',
                 'login_UID_non_reussi','test_deja_en_cours',
                 'rtc_non_lance_c9c_non_identifiee')
                else 'autre',
            'selection':selection if selection in permitted else 'non_confirmee',
            'abonnement_appareil':watch.get('abonnement_appareil') is True,
            'abonnement_moto':watch.get('abonnement_moto') is True,
            'abonnement_sortant':watch.get('abonnement_sortant') is True,
            'messages_appareil':count('messages_appareil'),
            'messages_moto':count('messages_moto'),
            'messages_autres':count('messages_autres'),
            'dp149_inventaire_present':cache_sleep.get('dp149_present') is True,
            'dp149_inventaire_vrai':cache_sleep.get('dp149_true') is True,
            'dp149_inventaire_faux':cache_sleep.get('dp149_false') is True,
            'dp149_indice_basse_consommation':low_power,
            'dp149_messages':count('dp149_messages'),
            'dp149_vrai':count('dp149_vrai'),
            'dp149_faux':count('dp149_faux'),
            'dp149_non_booleen':count('dp149_non_booleen'),
            'messages_sortants':count('messages_sortants'),
            'sortants_pv22':count('sortants_pv22'),
            'sortants_dechiffres':count('sortants_dechiffres'),
            'sortants_echecs':count('sortants_echecs'),
            'sortants_offer':count('sortants_offer'),
            'sortants_candidate':count('sortants_candidate'),
            'sortants_302_autres':count('sortants_302_autres'),
            'sortants_offre_depuis_utilisateur':count('sortants_offre_depuis_utilisateur'),
            'sortants_offre_vers_appareil':count('sortants_offre_vers_appareil'),
            'sortants_offre_sdp':count('sortants_offre_sdp'),
            'sortants_offre_aes_kcp':count('sortants_offre_aes_kcp'),
            'sortants_offre_sessionid':count('sortants_offre_sessionid'),
            'sortants_offre_moto_id':count('sortants_offre_moto_id'),
            'sortants_offre_path_mqtt':count('sortants_offre_path_mqtt'),
            'sortants_offre_trace':count('sortants_offre_trace'),
            'sortants_offre_is_pre_zero':count('sortants_offre_is_pre_zero'),
            'sortants_offre_p2p_skill':count('sortants_offre_p2p_skill'),
            'sortants_offre_security_3':count('sortants_offre_security_3'),
            'sortants_offre_preconnect':count('sortants_offre_preconnect'),
            'sortants_offre_token':count('sortants_offre_token'),
            'sortants_offre_tcp_token':count('sortants_offre_tcp_token'),
            'sortants_offre_log':count('sortants_offre_log'),
            'trames_pv22':count('trames_pv22'),
            'trames_autres':count('trames_autres'),
            'decodages_ok':count('decodages_ok'),
            'decodages_echec':count('decodages_echec'),
            'protocoles_22':count('protocoles_22'),
            'protocoles_302':count('protocoles_302'),
            'protocoles_autres':count('protocoles_autres'),
            'types_offer':count('types_offer'),
            'types_answer':count('types_answer'),
            'types_candidate':count('types_candidate'),
            'types_disconnect':count('types_disconnect'),
            'types_autres':count('types_autres'),
            'origine_appareil_confirmee':count('origine_appareil_confirmee'),
            'destinataire_appareil_confirme':count('destinataire_appareil_confirme'),
            'origine_utilisateur_confirmee':count('origine_utilisateur_confirmee'),
            'destinataire_utilisateur_confirme':count('destinataire_utilisateur_confirme'),
            'path_mqtt':count('path_mqtt'),
            'path_autre':count('path_autre'),
            'sessionid_present':count('sessionid_present'),
            'moto_id_present':count('moto_id_present'),
            'answers_avec_sdp':count('answers_avec_sdp'),
            'answers_aes_kcp':count('answers_aes_kcp'),
            'candidates_avec_ice':count('candidates_avec_ice'),
            'answers_vers_utilisateur':count('answers_vers_utilisateur'),
            'offres_envoyees':0, 'video_lancee':False,'commandes_ptz':0,
            'identifiants_retournes':False,'secrets_retournes':False,
            'payloads_conserves':False,
            'note':'Un compteur nul ne prouve pas que la camera est absente.',
        }

    async def demarrer_video_c9c_autonome_beta(call):
        """Explicit video-only C5L P2P experiment on one standalone C9C.

        No C5L PTZ or station PTZ service is invoked, even if video works.
        """
        if (call.data.get('confirmation_camera_c9c_autonome') is not True or
                call.data.get('confirmation_essai_video') is not True or
                call.data.get('confirmation_envoi_mot_de_passe') is not True):
            raise ServiceValidationError('Confirmer la camera C9C autonome et le direct experimental')
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une seule configuration AOSU active est requise pour cet essai')
        runtime=loaded[0].runtime_data
        if select_standalone_c9c_key(runtime.data) is None:
            raise ServiceValidationError('Une seule C9C autonome sans station est requise')
        if not getattr(runtime.client, '_standalone_c9c_sn', None):
            raise ServiceValidationError('Identite C9C non disponible: actualiser l inventaire')
        return runtime.live_controller.start(
            password_confirmed=True,candidate_confirmed=True,
            standalone_c9c_video_test=True,
            standalone_c9c_wake_then_video=(
                call.data.get('confirmation_reveil_et_video') is True))

    async def arreter_direct_c5l(call):
        return _loaded_direct_controller().stop()

    async def statut_direct_c5l(call):
        return _loaded_direct_controller().status()

    async def audit_preparation_autres_cameras(call):
        """Inspect the already cached camera metadata; no new web/device request."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return audit_camera_compatibility(loaded[0].runtime_data.data)

    async def audit_preparation_c9_h1l_b98(call):
        """Cache-only C9/H1L identity comparison, without camera or network commands."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, "runtime_data", None)]
        if len(loaded) != 1:
            raise ServiceValidationError("Une configuration Smart AOSU active est requise")
        coordinator = loaded[0].runtime_data
        if not coordinator.last_update_success or not isinstance(coordinator.data, dict):
            raise ServiceValidationError("Inventaire AOSU non disponible")
        return audit_c9_h1l_bridge(coordinator.data, coordinator.client)

    async def audit_structure_c9_h1l_b99(call):
        """RAM-only OEM identity/parent structure; no network or video."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, "runtime_data", None)]
        if len(loaded) != 1:
            raise ServiceValidationError("Une configuration Smart AOSU active est requise")
        coordinator = loaded[0].runtime_data
        if not coordinator.last_update_success or not isinstance(coordinator.data, dict):
            raise ServiceValidationError("Inventaire AOSU non disponible")
        return audit_c9_oem_structure(coordinator.data, coordinator.client)

    async def audit_fiches_oem_c9_h1l_b100(call):
        """Opt-in details: no login, video, RTC or PTZ, executor only."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, "runtime_data", None)]
        if len(loaded) != 1:
            raise ServiceValidationError("Une configuration Smart AOSU active est requise")
        coordinator = loaded[0].runtime_data
        if not coordinator.last_update_success or not isinstance(coordinator.data, dict):
            raise ServiceValidationError("Inventaire AOSU non disponible")
        return await hass.async_add_executor_job(partial(
            audit_oem_details_c9_h1l_b100, coordinator,
            consent=call.data.get("confirmation_lecture_fiches") is True))

    async def audit_rtc_c9_candidate_b101(call):
        """One explicit RTC config read for a probable C9; never start video."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, "runtime_data", None)]
        if len(loaded) != 1:
            raise ServiceValidationError("Une configuration Smart AOSU active est requise")
        coordinator = loaded[0].runtime_data
        return await hass.async_add_executor_job(partial(
            read_c9_rtc_b101, coordinator,
            camera_number=call.data.get("numero_camera_aosu"),
            confirm_candidate=call.data.get("confirmation_candidat_non_prouve") is True,
            confirm_rtc=call.data.get("confirmation_lecture_rtc") is True))

    async def audit_reseau_local_h1l_b103(call):
        """One manually confirmed STUN/TCP reachability probe; no camera traffic."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e, 'runtime_data', None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        controller=getattr(loaded[0].runtime_data,'live_controller',None)
        if controller is not None:
            status=controller.status()
            if isinstance(status,dict) and status.get('direct_actif') is True:
                raise ServiceValidationError('Arreter le direct C5L avant le test reseau local')
        try:
            return await hass.async_add_executor_job(partial(
                audit_local_h1l_b103,_station_ip_for_call(call),
                confirmed=call.data.get('confirmation_test_reseau_local') is True,
                check_tcp=call.data.get('tester_tcp_6668') is True))
        except ValueError as exc:
            raise ServiceValidationError(str(exc)) from exc

    async def audit_auth_locale_h1l_b104(call):
        """Explicit station-key Tuya 3.4 challenge, no data point queries."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_local_station_auth_b104, loaded[0].runtime_data,
            ip_station=_station_ip_for_call(call),
            confirm_identity=call.data.get('confirmation_station_candidate_non_prouvee') is True,
            confirm_handshake=call.data.get('confirmation_authentification_locale') is True))

    async def audit_ipc_config_c9_h1l_b106(call):
        """Read documented Tuya IPC camera config; never open media."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_c9_ipc_config_b106,loaded[0].runtime_data,
            camera_number=call.data.get('numero_camera_aosu'),
            confirm_candidate=call.data.get('confirmation_candidat_non_prouve') is True,
            confirm_ipc=call.data.get('confirmation_lecture_config_ipc') is True))

    async def audit_statut_local_h1l_b107(call):
        """Manual, read-only Tuya 3.4 DP_QUERY_NEW from validated station candidate."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_h1l_read_status_b107, loaded[0].runtime_data,
            ip_station=_station_ip_for_call(call),
            confirm_station=call.data.get('confirmation_station_candidate_non_prouvee') is True,
            confirm_read=call.data.get('confirmation_lecture_statut_lan') is True))

    async def audit_statut_local_h1l_b108(call):
        """Opt-in OEM cache recovery and the same safe B107 LAN status read."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_h1l_local_status_b108, loaded[0].runtime_data,
            ip_station=_station_ip_for_call(call),
            confirm_station=call.data.get('confirmation_station_candidate_non_prouvee') is True,
            confirm_read=call.data.get('confirmation_lecture_statut_lan') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_statut_local_h1l_b109(call):
        """B109: opt-in OEM recovery + authenticated local reply classification."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_h1l_local_status_b109, loaded[0].runtime_data,
            ip_station=_station_ip_for_call(call),
            confirm_station=call.data.get('confirmation_station_candidate_non_prouvee') is True,
            confirm_read=call.data.get('confirmation_lecture_statut_lan') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_statut_local_h1l_b110(call):
        """B110: authenticated DP_QUERY_NEW with correctly formatted JSON object."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_h1l_local_status_b110, loaded[0].runtime_data,
            ip_station=_station_ip_for_call(call),
            confirm_station=call.data.get('confirmation_station_candidate_non_prouvee') is True,
            confirm_read=call.data.get('confirmation_lecture_statut_lan') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_capture_h1l_b111(call):
        """B111: offline decode of user-provided PCAP; no camera command."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            analyse_capture_h1l_b111,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            confirmation_analyse_capture=call.data.get('confirmation_analyse_capture') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_negociation_lan_c9_b119(call):
        """B119: one user-confirmed active 0x20 SDP offer; no media or PTZ."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_lan_c9_b119, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_negociation_lan_c9_b120(call):
        """B120: one user-confirmed active 0x20 SDP offer; no media or PTZ."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_lan_c9_b120, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_negociation_lan_c9_b121(call):
        """B120: one owned offer plus one fresh LAN host ICE candidate; no UDP sends/PTZ."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_lan_c9_b121, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_negociation_lan_c9_b122(call):
        """B122: one owned offer plus one fresh LAN host ICE candidate; no UDP sends/PTZ."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_lan_c9_b122, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_preparation_video_c9_b123(call):
        """B123: in-memory authenticated PCAP structure comparison; no LAN sends."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_c9_b123, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_ecarts_offre_video_c9_b124(call):
        """B124: sanitized in-memory comparison; no LAN packet sent."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_c9_b124, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_negociation_lan_c9_b125(call):
        """B125: obtain fresh C9 RTC tokens, then one guarded LAN offer."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_lan_c9_b125, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_connectivite_ice_c9_b126(call):
        """B126: one fresh C9 LAN SDP and authenticated local-only STUN check."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_ice_c9_b126,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_connectivite_ice_c9_b127(call):
        """B127: one fresh C9 LAN SDP and authenticated local-only STUN check."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_ice_c9_b127,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_bootstrap_kcp_c9_b128(call):
        """B128: inspect the first 6 captured C9 control KCP packets offline."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_kcp_c9_b128, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_transport_kcp_c9_b129(call):
        """One fresh H1L KCP window query, following validated SDP+ICE."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_transport_kcp_c9_b129, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_auth_kcp_c9_b130(call):
        """Read-only C9 channel-zero profile check; may refresh OEM HTTPS."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_auth_c9_b130, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_authentification_kcp_c9_b130(call):
        """One bounded, fresh C9 authentication only with validated profile."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_auth_kcp_c9_b130, loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_schema_auth_c9_b133(call):
        """Strictly offline verification of the C9 296-byte auth layout."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_schema_auth_c9_b133,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_profil_demarrage_c9_b137(call):
        """Bounded capture-validated C9 command reconstruction audit."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_profil_video_b137,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_demarrage_video_c9_b137(call):
        """Strictly opt-in fresh 5-command C9 KCP video probe; no PTZ."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_demarrage_video_b137,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_essai_cle_station_b134=call.data.get('autoriser_essai_cle_station_b134') is True,
            autoriser_commandes_video_c9_b137=call.data.get('autoriser_commandes_video_c9_b137') is True))

    async def essai_analyse_media_c9_b138(call):
        """Opt-in C9 video short probe: unique KCP, ACK/UNA and HEVC metrics."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_analyse_media_b138,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_essai_cle_station_b134=call.data.get('autoriser_essai_cle_station_b134') is True,
            autoriser_commandes_video_c9_b137=call.data.get('autoriser_commandes_video_c9_b137') is True,
            autoriser_analyse_media_c9_b138=call.data.get('autoriser_analyse_media_c9_b138') is True))

    def _c9_controllers_b141():
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return loaded[0].runtime_data

    def _numero_c9_b141(call):
        number=call.data.get('camera_numero')
        if type(number) is not int or number not in (1,2):
            raise ServiceValidationError('La camera_numero doit etre 1 ou 2')
        return number

    async def demarrer_direct_c9_b141(call):
        runtime=_c9_controllers_b141()
        controller=runtime.c9_live_b141[_numero_c9_b141(call)]
        return controller.start(config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_essai_cle_station_b134=call.data.get('autoriser_essai_cle_station_b134') is True,
            autoriser_commandes_video_c9_b137=call.data.get('autoriser_commandes_video_c9_b137') is True,
            autoriser_direct_c9_b139=call.data.get('autoriser_direct_c9_b139') is True)

    async def audit_preparation_sans_capture_c9_b144(call):
        runtime=_c9_controllers_b141()
        return await hass.async_add_executor_job(
            partial(audit_preparation_sans_capture_b144,runtime,
               camera_numero=_numero_c9_b141(call),ip_station=_station_ip_for_call(call),
               autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
               confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def demarrer_direct_c9_b144(call):
        runtime=_c9_controllers_b141()
        controller=runtime.c9_live_b141[_numero_c9_b141(call)]
        return controller.start_sans_capture(
            ip_station=_station_ip_for_call(call),camera_numero=_numero_c9_b141(call),
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_direct_c9_b144=call.data.get('autoriser_direct_c9_b144') is True)

    async def demarrer_direct_c9_b145(call):
        runtime=_c9_controllers_b141()
        controller=runtime.c9_live_b141[_numero_c9_b141(call)]
        return controller.start_sans_capture(
            ip_station=_station_ip_for_call(call),camera_numero=_numero_c9_b141(call),
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_direct_c9_b144=call.data.get('autoriser_direct_c9_b145') is True,
            diagnostic_b145=True)

    async def tester_port_tcp_h1l_b146(call):
        """Run TCP probe in HA Core executor, never through the SSH add-on."""
        from .h1l_tcp_probe_b146 import tester_port_tcp_h1l_b146 as _probe_tcp
        return await hass.async_add_executor_job(partial(
            _probe_tcp,ip_station=_station_ip_for_call(call),
            confirmation_test_tcp_h1l=call.data.get('confirmation_test_tcp_h1l') is True))

    async def statut_direct_c9_b141(call):
        runtime=_c9_controllers_b141()
        return runtime.c9_live_b141[_numero_c9_b141(call)].status()

    async def arreter_direct_c9_b141(call):
        runtime=_c9_controllers_b141()
        return await runtime.c9_live_b141[_numero_c9_b141(call)].stop()

    async def autoriser_essai_ptz_c9_b159(call):
        runtime=_c9_controllers_b141()
        return runtime.c9_ptz_b141[_numero_c9_b141(call)].autoriser_essai(
            confirmation_deplacement=call.data.get('confirmation_deplacement') is True,
            confirmation_stop_disponible=call.data.get('confirmation_stop_disponible') is True)

    async def autoriser_ptz_c9_stable(call):
        """Persist per-camera approval only after explicit physical STOP confirmation."""
        runtime=_c9_controllers_b141()
        numero=_numero_c9_b141(call)
        ptz=runtime.c9_ptz_b141[numero]
        report,binding=ptz.preparer_autorisation_stable(
            confirmation_camera_correcte=call.data.get('confirmation_camera_correcte') is True,
            confirmation_deplacement_et_stop=call.data.get('confirmation_deplacement_et_stop') is True)
        if binding is None:
            return report
        async with runtime.c9_ptz_permissions_lock:
            grants=dict(runtime.c9_ptz_permissions)
            grants[str(numero)]=binding
            try:
                await runtime.c9_ptz_permissions_store.async_save({'bindings':grants})
            except Exception:
                return {**report,'etat':'enregistrement_autorisation_impossible'}
            runtime.c9_ptz_permissions=grants
            ptz.set_stable_binding(binding)
        return {**report,'etat':'autorisation_stable_enregistree',
                'autorisation_par_camera':True,'stop_physique_non_mesure_par_logiciel':True}

    async def retirer_ptz_c9_stable(call):
        """Let operators revoke approval independently for each camera."""
        runtime=_c9_controllers_b141()
        numero=_numero_c9_b141(call)
        ptz=runtime.c9_ptz_b141[numero]
        async with runtime.c9_ptz_permissions_lock:
            grants=dict(runtime.c9_ptz_permissions)
            grants.pop(str(numero),None)
            try:
                await runtime.c9_ptz_permissions_store.async_save({'bindings':grants})
            except Exception:
                return {'etat':'retrait_autorisation_impossible','camera_numero':numero}
            runtime.c9_ptz_permissions=grants
            if ptz.status().get('action_active'):
                ptz.stop()   # emergency STOP before revoking active grant
            ptz.set_stable_binding(None)
        return {'etat':'autorisation_stable_retiree','camera_numero':numero}

    async def statut_ptz_c9_b141(call):
        runtime=_c9_controllers_b141()
        return runtime.c9_ptz_b141[_numero_c9_b141(call)].status()

    async def appui_ptz_c9_b141(call):
        runtime=_c9_controllers_b141()
        return runtime.c9_ptz_b141[_numero_c9_b141(call)].press(
            call.data.get('direction'),call.data.get('geste_id'))

    async def relache_ptz_c9_b141(call):
        runtime=_c9_controllers_b141()
        return runtime.c9_ptz_b141[_numero_c9_b141(call)].release(call.data.get('geste_id'))

    async def stop_ptz_c9_b141(call):
        runtime=_c9_controllers_b141()
        return runtime.c9_ptz_b141[_numero_c9_b141(call)].stop()

    async def demarrer_direct_c9_b139(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
            if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        controller=loaded[0].runtime_data.c9_live_b139
        return controller.start(config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_essai_cle_station_b134=call.data.get('autoriser_essai_cle_station_b134') is True,
            autoriser_commandes_video_c9_b137=call.data.get('autoriser_commandes_video_c9_b137') is True,
            autoriser_direct_c9_b139=call.data.get('autoriser_direct_c9_b139') is True)

    async def statut_direct_c9_b139(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
            if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return loaded[0].runtime_data.c9_live_b139.status()

    async def arreter_direct_c9_b139(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
            if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await loaded[0].runtime_data.c9_live_b139.stop()

    async def audit_champs_commandes_c9_b136(call):
        """Passively inspect the field profiles in an operator-supplied C9 capture."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_champs_b136,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_commandes_kcp_c9_b135(call):
        """Offline comparison of C9 command sequence after KCP auth."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_kcp_suite_b135,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_cle_h1l_c9_b134(call):
        """Check station-key fallback hypothesis, no active LAN traffic."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_audit_cle_h1l_c9_b134,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def essai_auth_station_c9_b134(call):
        """Fresh RTC+H1L credential hypothesis; one authorized auth PUSH max."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_auth_station_c9_b134,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_essai_cle_station_b134=call.data.get('autoriser_essai_cle_station_b134') is True))

    async def essai_auth_rtc_c9_b133(call):
        """One explicitly authorized, experimental fresh C9 KCP auth."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_essai_auth_c9_b133,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True,
            autoriser_configuration_rtc=call.data.get('autoriser_configuration_rtc') is True,
            autoriser_offre_lan_active=call.data.get('autoriser_offre_lan_active') is True,
            autoriser_test_ice_actif=call.data.get('autoriser_test_ice_actif') is True,
            autoriser_test_kcp_actif=call.data.get('autoriser_test_kcp_actif') is True,
            autoriser_auth_kcp_active=call.data.get('autoriser_auth_kcp_active') is True,
            autoriser_auth_experimentale_b133=call.data.get('autoriser_auth_experimentale_b133') is True))

    async def audit_correspondances_auth_c9_b132(call):
        """Compare offline C9 auth fields with current known OEM IDs, no values exposed."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_correspondances_auth_c9_b132,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_details_auth_kcp_c9_b131(call):
        """Read-only redacted classification of C9 KCP auth extensions."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            lancer_details_auth_c9_b131,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            nom_capture=call.data.get('nom_capture'),
            ip_station=_station_ip_for_call(call),
            camera_numero=call.data.get('camera_numero'),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            confirmation_camera_candidate=call.data.get('confirmation_camera_candidate') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    async def audit_rtc_station_h1l_b105(call):
        """One manually authorized station RTC read; no stream or PTZ."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e, 'runtime_data', None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_station_rtc_b105, loaded[0].runtime_data,
            confirm_candidate=call.data.get('confirmation_station_candidate') is True,
            confirm_rtc=call.data.get('confirmation_lecture_rtc_station') is True))

    async def audit_ptz_c5l(call):
        """Zero-network PTZ readiness: does not send any motor command."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        coordinator = loaded[0].runtime_data
        if call.data.get('actualiser_cache_oem') is True:
            return await hass.async_add_executor_job(partial(
                refresh_ptz_inventory, coordinator,
                password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True))
        return audit_ptz_readiness(coordinator, coordinator.client)

    async def audit_ptz_schema_detaille_c5l(call):
        """Explicit, read-only Tuya device detail. No PTZ or video."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        coordinator=loaded[0].runtime_data
        return await hass.async_add_executor_job(partial(
            audit_ptz_device_detail_with_refresh,coordinator,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True))

    async def audit_structure_ptz_c5l(call):
        """b44: one authorized read-only device.get; returns structural labels only."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_ptz_device_detail_with_refresh,loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            include_structure=True))

    async def essayer_arret_ptz_c5l(call):
        """One explicitly confirmed STOP-only request; never moves the motor."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        coordinator=loaded[0].runtime_data
        return await hass.async_add_executor_job(partial(
            probe_ptz_stop_with_refresh,coordinator,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            stop_confirmed=call.data.get('confirmation_test_arret') is True))

    async def essayer_arret_ptz_dp116_c5l(call):
        """One explicitly authorized experimental STOP-only, numeric DP 116."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            test_stop_dp116_with_refresh, loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            stop_confirmed=call.data.get('confirmation_test_arret') is True,
            numeric_confirmed=call.data.get('confirmation_dp_116_experimental') is True))

    async def audit_canal_ptz_direct_c5l(call):
        """Passive inspection of already running C5L session; zero new packets."""
        return _loaded_direct_controller().audit_ptz_channel(
            mark=call.data.get('marquer_debut_comparaison') is True)

    async def audit_mqtt_ptz_direct_c5l(call):
        """Passively count MQTT messages on the existing live socket."""
        return _loaded_direct_controller().audit_ptz_mqtt(
            mark=call.data.get('marquer_debut_comparaison') is True)

    async def audit_publication_ptz_c5l(call):
        """b43: offline snapshot of C5L DP schema and MQTT publish prerequisites."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return audit_ptz_publication(loaded[0].runtime_data)

    async def audit_encodeur_mqtt_ptz_c5l(call):
        """b46: offline prerequisites of SDK's version-dependent MQTT DP format."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return audit_mqtt_encoder_readiness(loaded[0].runtime_data)

    async def audit_sdk_sources_ptz_c5l(call):
        """b47: one consented read of OEM inventory and device detail."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_sources_ptz_c5l,loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True))

    async def audit_tuya_uid_preflight(call):
        """Offline checksum + native decoder stages. Never contacts AOSU/Tuya."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,"runtime_data",None)]
        if len(loaded)!=1:
            raise ServiceValidationError("Une seule configuration Smart AOSU Cloud active est necessaire")
        return await hass.async_add_executor_job(
            run_tuya_uid_preflight, loaded[0].runtime_data.client)

    async def audit_modele_produit_ptz_c5l(call):
        """b51: inspect product-level Tuya model; explicit opt-in, read-only."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(
            partial(audit_product_model,loaded[0].runtime_data,
                password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
                camera_confirmed=call.data.get('confirmation_camera_c5l') is True))

    async def audit_capacite_produit_ptz_c5l_b78(call):
        """b78: APK-verified product info read, never a PTZ publication."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_product_info_b78,loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True))

    async def observer_etat_ptz_c5l_b80(call):
        """Compare two device-state reads; operator moves camera in official app."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_ptz_state_b80, loaded[0].runtime_data,
            phase=call.data.get('phase'),
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True))

    async def arret_urgence_c5l_b81(call):
        """Manual emergency STOP, no cooldown and no dependency on movement lock."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            emergency_stop_b81, loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            emergency_confirmed=call.data.get('confirmation_stop_urgence') is True))

    async def tester_direction_c5l_b82(call):
        """Opt-in one of three as-yet-unverified directions; automatic STOP."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            try_direction_with_refresh, loaded[0].runtime_data,
            direction=call.data.get('direction'),
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            stop_verified_confirmed=call.data.get('confirmation_stop_b81_physique') is True,
            physical_backup_confirmed=call.data.get('confirmation_application_aosu_secours') is True))

    async def tester_mouvement_droite_c5l_b81(call):
        """Opt-in single rightward pulse, with STOP and backup watchdog."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            try_right_with_refresh, loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            stop_verified_confirmed=call.data.get('confirmation_stop_b79_physique') is True,
            physical_backup_confirmed=call.data.get('confirmation_application_aosu_secours') is True))

    async def essayer_arret_api_alternative_c5l_b79(call):
        """Experimental one-shot STOP over alternate SDK API; never direction."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            test_alternate_stop_b79_with_refresh, loaded[0].runtime_data,
            password_confirmed=call.data.get('confirmation_envoi_mot_de_passe') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            stop_confirmed=call.data.get('confirmation_commande_arret') is True,
            unverified_dp_confirmed=call.data.get('confirmation_dp116_experimental') is True))

    async def audit_transport_mqtt_ptz_c5l(call):
        """b53: explicit opt-in TLS MQTT subscribe, no publish or camera control."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_ptz_mqtt_transport,loaded[0].runtime_data,
            mqtt_confirmed=call.data.get('confirmation_connexion_mqtt') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True))

    async def essayer_arret_mqtt_ptz_c5l_b54(call):
        """Experimental STOP only; direct video and direction controls untouched."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            test_mqtt_stop_once,loaded[0].runtime_data,
            mqtt_confirmed=call.data.get('confirmation_publication_mqtt') is True,
            camera_confirmed=call.data.get('confirmation_camera_c5l') is True,
            stop_confirmed=call.data.get('confirmation_test_stop') is True,
            mapping_experimental_confirmed=call.data.get('confirmation_mapping_experimental') is True))

    async def ptz_maintien_c5l_b83(call):
        """Production-style press/release/stop over B79's verified HTTP API.

        Still uses fixed C5L OEM selection and only four documented DP119
        values + DP116 STOP. No browser-provided ID, key or raw DP payload.
        """
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        control=getattr(loaded[0].runtime_data,'ptz_b83',None)
        if control is None:
            return {'etat':'controle_ptz_indisponible'}
        action=call.data.get('action')
        if action=='press':
            return control.press(call.data.get('direction'),call.data.get('gesture_id'))
        if action=='release':
            return control.release(call.data.get('gesture_id'))
        if action=='stop':
            return control.stop()
        if action=='status':
            return control.status()
        return {'etat':'action_invalide'}

    async def ptz_live_c5l_b56(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        control=getattr(loaded[0].runtime_data,'ptz_live_b55',None)
        if control is None:
            return {'etat':'controle_ptz_indisponible'}
        action=call.data.get('action')
        gesture_id=call.data.get('gesture_id')
        if action=='arm':
            return await hass.async_add_executor_job(partial(control.arm,
                consent=call.data.get('confirmation_test_moteur') is True))
        if action=='press':
            return control.press(call.data.get('direction'),gesture_id,
                                 consent=call.data.get('confirmation_test_moteur') is True)
        if action=='release':
            return control.release(gesture_id)
        if action=='status':
            return control.status()
        return {'etat':'action_invalide'}

    async def audit_mqtt_ptz_app_b61(call):
        """Passive comparison of native-app MQTT channels; no PTZ publication."""
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        from .ptz_app_passive_b61 import audit_mqtt_ptz_app_b61 as run
        return await hass.async_add_executor_job(partial(
            run,loaded[0].runtime_data,
            confirm_read=call.data.get('confirmation_ecoute_mqtt') is True,
            confirm_camera=call.data.get('confirmation_camera_c5l') is True))

    async def audit_taille_mqtt_ptz_c5l_b69(call):
        """b69 offline-size comparison; no network / camera / motor I/O."""
        loaded = [e for e in hass.config_entries.async_entries(DOMAIN)
                  if getattr(e, 'runtime_data', None)]
        if len(loaded) != 1:
            raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return audit_packet_size_b69(loaded[0].runtime_data)

    hass.services.async_register(DOMAIN, 'audit_taille_mqtt_ptz_c5l_b69',
                                 audit_taille_mqtt_ptz_c5l_b69,
                                 supports_response=SupportsResponse.ONLY)

    hass.services.async_register(DOMAIN,'audit_mqtt_ptz_app_b61',
                                 audit_mqtt_ptz_app_b61,
                                 supports_response=SupportsResponse.ONLY)

    hass.services.async_register(DOMAIN,'ptz_maintien_c5l_b83',
                                 ptz_maintien_c5l_b83,supports_response=SupportsResponse.ONLY)

    hass.services.async_register(DOMAIN,'ptz_live_c5l_b56',
                                 ptz_live_c5l_b56,supports_response=SupportsResponse.ONLY)

    hass.services.async_register(DOMAIN,'essayer_arret_mqtt_ptz_c5l_b54',
                                 essayer_arret_mqtt_ptz_c5l_b54,
                                 supports_response=SupportsResponse.ONLY)

    hass.services.async_register(DOMAIN,'audit_transport_mqtt_ptz_c5l',
                                 audit_transport_mqtt_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'observer_etat_ptz_c5l_b80',
                                 observer_etat_ptz_c5l_b80,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'arret_urgence_c5l_b81',
                                 arret_urgence_c5l_b81,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'tester_direction_c5l_b82',
                                 tester_direction_c5l_b82,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'tester_mouvement_droite_c5l_b81',
                                 tester_mouvement_droite_c5l_b81,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essayer_arret_api_alternative_c5l_b79',
                                 essayer_arret_api_alternative_c5l_b79,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_capacite_produit_ptz_c5l_b78',
                                 audit_capacite_produit_ptz_c5l_b78,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_modele_produit_ptz_c5l',
                                 audit_modele_produit_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_sdk_sources_ptz_c5l', audit_sdk_sources_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_encodeur_mqtt_ptz_c5l', audit_encodeur_mqtt_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_publication_ptz_c5l', audit_publication_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_mqtt_ptz_direct_c5l', audit_mqtt_ptz_direct_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_canal_ptz_direct_c5l', audit_canal_ptz_direct_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'essayer_arret_ptz_dp116_c5l', essayer_arret_ptz_dp116_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'essayer_arret_ptz_c5l', essayer_arret_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_structure_ptz_c5l', audit_structure_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_ptz_schema_detaille_c5l', audit_ptz_schema_detaille_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, 'audit_ptz_c5l', audit_ptz_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_preparation_autres_cameras',audit_preparation_autres_cameras,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_preparation_c9_h1l_b98',audit_preparation_c9_h1l_b98,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_structure_c9_h1l_b99',audit_structure_c9_h1l_b99,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_fiches_oem_c9_h1l_b100',audit_fiches_oem_c9_h1l_b100,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_rtc_c9_candidate_b101',audit_rtc_c9_candidate_b101,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_reseau_local_h1l_b103',audit_reseau_local_h1l_b103,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_auth_locale_h1l_b104',audit_auth_locale_h1l_b104,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_rtc_station_h1l_b105',audit_rtc_station_h1l_b105,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_ipc_config_c9_h1l_b106',audit_ipc_config_c9_h1l_b106,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_statut_local_h1l_b107',audit_statut_local_h1l_b107,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_statut_local_h1l_b108',audit_statut_local_h1l_b108,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_statut_local_h1l_b109',audit_statut_local_h1l_b109,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_statut_local_h1l_b110',audit_statut_local_h1l_b110,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_capture_h1l_b111',audit_capture_h1l_b111,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_negociation_lan_c9_b119',essai_negociation_lan_c9_b119,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_negociation_lan_c9_b120',essai_negociation_lan_c9_b120,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_negociation_lan_c9_b121',essai_negociation_lan_c9_b121,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_negociation_lan_c9_b122',essai_negociation_lan_c9_b122,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_connectivite_ice_c9_b126',essai_connectivite_ice_c9_b126,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_connectivite_ice_c9_b127',essai_connectivite_ice_c9_b127,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_bootstrap_kcp_c9_b128',audit_bootstrap_kcp_c9_b128,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_transport_kcp_c9_b129',essai_transport_kcp_c9_b129,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_auth_kcp_c9_b130',audit_auth_kcp_c9_b130,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_authentification_kcp_c9_b130',essai_authentification_kcp_c9_b130,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_details_auth_kcp_c9_b131',audit_details_auth_kcp_c9_b131,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_correspondances_auth_c9_b132',audit_correspondances_auth_c9_b132,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_schema_auth_c9_b133',audit_schema_auth_c9_b133,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_auth_rtc_c9_b133',essai_auth_rtc_c9_b133,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_profil_demarrage_c9_b137',audit_profil_demarrage_c9_b137,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_demarrage_video_c9_b137',essai_demarrage_video_c9_b137,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_analyse_media_c9_b138',essai_analyse_media_c9_b138,
                                 supports_response=SupportsResponse.ONLY)
    for _action,_callback in (
        ('demarrer_direct_c9_b141',demarrer_direct_c9_b141),
        ('statut_direct_c9_b141',statut_direct_c9_b141),
        ('arreter_direct_c9_b141',arreter_direct_c9_b141),
        ('autoriser_essai_ptz_c9_b159',autoriser_essai_ptz_c9_b159),
        ('autoriser_ptz_c9_stable',autoriser_ptz_c9_stable),
        ('retirer_ptz_c9_stable',retirer_ptz_c9_stable),
        ('statut_ptz_c9_b141',statut_ptz_c9_b141),
        ('appui_ptz_c9_b141',appui_ptz_c9_b141),
        ('relache_ptz_c9_b141',relache_ptz_c9_b141),
        ('stop_ptz_c9_b141',stop_ptz_c9_b141)):
        hass.services.async_register(DOMAIN,_action,_callback,
                                     supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_preparation_sans_capture_c9_b144',
                                 audit_preparation_sans_capture_c9_b144,
                                 supports_response=SupportsResponse.ONLY)
    async def comparer_profil_video_c9_b147(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            comparer_profil_b147,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            ip_station=_station_ip_for_call(call),
            confirmation_capture_personnelle=call.data.get('confirmation_capture_personnelle') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    hass.services.async_register(DOMAIN,'comparer_profil_video_c9_b147',
                                 comparer_profil_video_c9_b147,
                                 supports_response=SupportsResponse.ONLY)
    async def audit_routage_c9_b151(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_routage_station_c9_b151,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            ip_station=_station_ip_for_call(call),
            confirmation_captures_personnelles=call.data.get('confirmation_captures_personnelles') is True))

    hass.services.async_register(DOMAIN,'audit_routage_c9_h1l_b151',
                                 audit_routage_c9_b151,
                                 supports_response=SupportsResponse.ONLY)
    async def audit_reponses_station_c9_h1l_b153(call):
        loaded=[e for e in hass.config_entries.async_entries(DOMAIN)
                if getattr(e,'runtime_data',None)]
        if len(loaded)!=1:raise ServiceValidationError('Une configuration Smart AOSU active est requise')
        return await hass.async_add_executor_job(partial(
            audit_reponses_station_c9_b153,loaded[0].runtime_data,
            config_dir=hass.config.config_dir,
            ip_station=_station_ip_for_call(call),
            confirmation_captures_personnelles=call.data.get('confirmation_captures_personnelles') is True,
            autoriser_reconstitution_oem=call.data.get('autoriser_reconstitution_oem') is True,
            confirmation_envoi_mot_de_passe=call.data.get('confirmation_envoi_mot_de_passe') is True))

    hass.services.async_register(DOMAIN,'audit_reponses_station_c9_h1l_b153',
                                 audit_reponses_station_c9_h1l_b153,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'tester_port_tcp_h1l_b146',
                                 tester_port_tcp_h1l_b146,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'demarrer_direct_c9_b145',
                                 demarrer_direct_c9_b145,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'demarrer_direct_c9_b144',
                                 demarrer_direct_c9_b144,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'demarrer_direct_c9_b139',demarrer_direct_c9_b139,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'statut_direct_c9_b139',statut_direct_c9_b139,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'arreter_direct_c9_b139',arreter_direct_c9_b139,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_champs_commandes_c9_b136',audit_champs_commandes_c9_b136,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_commandes_kcp_c9_b135',audit_commandes_kcp_c9_b135,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_cle_h1l_c9_b134',audit_cle_h1l_c9_b134,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_auth_station_c9_b134',essai_auth_station_c9_b134,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'essai_negociation_lan_c9_b125',essai_negociation_lan_c9_b125,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_preparation_video_c9_b123',audit_preparation_video_c9_b123,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_ecarts_offre_video_c9_b124',audit_ecarts_offre_video_c9_b124,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'audit_rtc_c9_topologie_b102',audit_rtc_c9_candidate_b101,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'diagnostiquer_identite_c9c_autonome',
                                 diagnostiquer_identite_c9c_autonome,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'diagnostiquer_fiche_c9c_autonome',
                                 diagnostiquer_fiche_c9c_autonome,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'diagnostiquer_rtc_c9c_autonome',
                                 diagnostiquer_rtc_c9c_autonome,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'comparer_rtc_ipc_v4_c9c_autonome',
                                 comparer_rtc_ipc_v4_c9c_autonome,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'comparer_webrtc_c9c_autonome_b23',
                                 comparer_webrtc_c9c_autonome_b23,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'tester_reveil_c9c_autonome',
                                 tester_reveil_c9c_autonome,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'observer_mqtt_c9c_autonome',
                                 observer_mqtt_c9c_autonome,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'demarrer_video_c9c_autonome_beta',
                                 demarrer_video_c9c_autonome_beta,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'demarrer_direct_c5l',demarrer_direct_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'arreter_direct_c5l',arreter_direct_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,'statut_direct_c5l',statut_direct_c5l,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"decoder_capture_video_locale",decoder_capture_video_locale,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_tuya_oem_inventory",audit_tuya_oem_inventory,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_tuya_uid_login",audit_tuya_uid_login,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_tuya_uid_preflight",audit_tuya_uid_preflight,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_tuya_uid_token",audit_tuya_uid_token,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_mqtt_authorisation",audit_mqtt_authorisation,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_provider_p2p",audit_provider_p2p,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_oem_uid",audit_oem_uid,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_liaison_tuya",audit_liaison_tuya,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_transport",audit_transport,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"inspect_datapoints",inspect,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"inspect_cached_metadata",inspect_cached,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_global",audit_global,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN,"audit_objectifs",audit_objectifs,
                                 supports_response=SupportsResponse.ONLY)
    return True

def _poll_interval(options):
    """Use a safe, bounded interval even if stored options are corrupted."""
    value = options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    return value if type(value) is int and value in ALLOWED_SCAN_INTERVALS else DEFAULT_SCAN_INTERVAL


async def async_update_options(hass, entry):
    """Apply changes in-place; NEVER log in again just to change polling."""
    coordinator = entry.runtime_data
    coordinator.update_interval = timedelta(seconds=_poll_interval(entry.options))
    # Trigger one read and let the coordinator reschedule the timer.
    # No new login is performed while the existing session is valid.
    await coordinator.async_request_refresh()


async def async_setup_entry(hass,entry):
    client=AosuCloudClient(entry.data[CONF_EMAIL],entry.data[CONF_PASSWORD])
    coordinator=SmartAosuCloudCoordinator(hass,client, _poll_interval(entry.options))
    await coordinator.async_config_entry_first_refresh()
    coordinator.live_controller=LiveController(hass,client)
    coordinator.c9_live_b139=C9DirectControllerB139(hass,coordinator)
    coordinator.c9_live_b141={n:C9DirectControllerB141(hass,coordinator,n) for n in (1,2)}
    coordinator.c9_ptz_b141={n:C9PtzHoldB141(coordinator,n) for n in (1,2)}
    # Persistent per-camera user confirmation; never migrate temporary B159
    # trials into a permanent grant automatically.
    import asyncio
    import re
    from homeassistant.helpers.storage import Store
    coordinator.c9_ptz_permissions_store=Store(
        hass,1,f'{DOMAIN}_c9_ptz_permissions_{entry.entry_id}')
    coordinator.c9_ptz_permissions_lock=asyncio.Lock()
    try:
        permissions_data=await coordinator.c9_ptz_permissions_store.async_load()
    except Exception:
        permissions_data=None     # fail closed if storage is unavailable
    raw=permissions_data.get('bindings',{}) if isinstance(permissions_data,dict) else {}
    coordinator.c9_ptz_permissions={}
    for n in (1,2):
        val=raw.get(str(n)) if isinstance(raw,dict) else None
        if isinstance(val,str) and re.fullmatch(r'[0-9a-f]{64}',val):
            coordinator.c9_ptz_permissions[str(n)]=val
            coordinator.c9_ptz_b141[n].set_stable_binding(val)
    coordinator.ptz_live_b55=ExperimentalPtzLiveController(coordinator)
    coordinator.ptz_b83=C5LPtzHoldB83(coordinator)
    entry.runtime_data=coordinator
    await hass.config_entries.async_forward_entry_setups(entry,PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(async_update_options))
    return True

async def async_unload_entry(hass,entry):
    ok=await hass.config_entries.async_unload_platforms(entry,PLATFORMS)
    if ok:
        if getattr(entry.runtime_data,'ptz_b83',None) is not None:
            entry.runtime_data.ptz_b83.close()
        if getattr(entry.runtime_data,'ptz_live_b55',None) is not None:
            await hass.async_add_executor_job(entry.runtime_data.ptz_live_b55.shutdown)
        for _ptz in getattr(entry.runtime_data,'c9_ptz_b141',{}).values():
            _ptz.close()
        for _controller in getattr(entry.runtime_data,'c9_live_b141',{}).values():
            await _controller.shutdown()
        if getattr(entry.runtime_data,"c9_live_b139",None) is not None:
            await entry.runtime_data.c9_live_b139.shutdown()
        if getattr(entry.runtime_data,"live_controller",None) is not None:
            await entry.runtime_data.live_controller.shutdown()
        await hass.async_add_executor_job(entry.runtime_data.client.close)
    return ok
