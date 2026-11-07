"""B133: experimental *fresh* C9/H1L KCP auth, trace-verified layout.

The 296-byte C9 auth shape and its station/camera metadata are verified against
an owned authenticated capture. No captured auth digest, identifier, token,
plaintext or ciphertext is reused. A brand-new credential is derived from the
current C9 RTC response password and the selected current camera local key.
This derivation is a hypothesis, NOT cryptographically verified against the old
capture. The action is opt-in, sends at most ONE control-channel auth PUSH only
after authenticated fresh SDP, nominated ICE and KCP WINS; no video/PTZ.
Never return secret values, content or fingerprints to Home Assistant.
"""
from __future__ import annotations
import hashlib,hmac,struct
from pathlib import Path
from typing import Any
from .c9_kcp_auth_audit_b131 import _record_first_auth
from .c9_kcp_auth_identity_b132 import audit_correspondances_auth_c9_b132,_ID_META
from .c9_kcp_auth_b130 import _session_kcp_b130
from .c9_lan_signal_b125 import essai_negociation_lan_c9_b125
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_probe_b103 import _validate_target
from .c9_rtc_candidate_b101 import _candidate

_HEADER=struct.pack('<II',0x12345678,1)
_MAX_PW=2048


def _unique_meta(plain:bytes,station_id:str,camera_id:str,devices:dict)->tuple[dict,str|None]:
    """Prove all capture bytes outside digest from CURRENT known fields."""
    out={'auth_structure_296_valide':False,'auth_bloc_station_conforme':False,
         'auth_bloc_camera_conforme':False,'auth_blocs_inconnus':0,
         'auth_md5_capture_conserve':False,'auth_schema_reconstructible':False,
         'hypothese_md5_rtc_non_verifiee':True,'secrets_retournes':False,
         'identifiants_retournes':False,'donnees_privees_retournees':False}
    if not isinstance(plain,bytes) or len(plain)!=296 or plain[:8]!=_HEADER:
        return out,None
    body=plain[8:]
    if body[:5]!=b'admin' or body[5:32]!=bytes(27):return out,None
    if not all(x in b'0123456789abcdefABCDEF' for x in body[32:64]):return out,None
    out['auth_structure_296_valide']=True
    out['auth_blocs_inconnus']=sum(any(body[i*32:(i+1)*32]) for i in (2,4,6,7,8))
    if out['auth_blocs_inconnus']:return out,None
    if not isinstance(station_id,str) or not 1<=len(station_id.encode('utf-8'))<=32:
        return out,None
    bstation=station_id.encode('utf-8').ljust(32,b'\0')
    out['auth_bloc_station_conforme']=hmac.compare_digest(body[96:128],bstation)
    if not out['auth_bloc_station_conforme']:return out,None
    camera=devices.get(camera_id)
    if not isinstance(camera,dict):return out,None
    # Do not infer the camera id from a name alone. B101 already proves one-to-
    # one inventory mapping; match the exact captured field against known OEM
    # metadata. Use ONLY its present-day live value in the rebuilt auth.
    matches=set()
    for prop in _ID_META:
        value=camera.get(prop)
        if isinstance(value,str) and 1<=len(value.encode('utf-8'))<=32 and \
                all(32<=b<=126 for b in value.encode('utf-8')):
            if hmac.compare_digest(body[160:192],value.encode('utf-8').ljust(32,b'\0')):
                matches.add(value)
    if len(matches)!=1:return out,None
    chosen=next(iter(matches))
    out['auth_bloc_camera_conforme']=True
    out['auth_schema_reconstructible']=True
    return out,chosen


def _new_auth(plain:bytes,station_id:str,camera_id:str,devices:dict,rtc:dict)->tuple[dict,bytes|None]:
    checks,matched_camera_meta=_unique_meta(plain,station_id,camera_id,devices)
    checks['auth_mot_de_passe_rtc_present']=False
    checks['auth_cle_locale_camera_valide']=False
    checks['auth_preparable_avec_rtc']=False
    if matched_camera_meta is None:return checks,None
    if not isinstance(rtc,dict):return checks,None
    password=rtc.get('password')
    checks['auth_mot_de_passe_rtc_present']=isinstance(password,str) and 1<=len(password)<=_MAX_PW
    device=devices.get(camera_id,{})
    local=device.get('localKey') if isinstance(device,dict) else None
    checks['auth_cle_locale_camera_valide']=isinstance(local,str) and len(local.encode('utf-8'))==16
    if not checks['auth_mot_de_passe_rtc_present'] or not checks['auth_cle_locale_camera_valide']:
        return checks,None
    # Only documented formula for the older channel-0 profile. Its validity
    # for the C9 extension remains to be tested by the owned H1L device.
    digest=hashlib.md5((password+'||'+local).encode('utf-8'),usedforsecurity=False).hexdigest().encode('ascii')
    body=bytearray(288)
    body[:5]=b'admin';body[32:64]=digest
    body[96:128]=station_id.encode('utf-8').ljust(32,b'\0')
    body[160:192]=matched_camera_meta.encode('utf-8').ljust(32,b'\0')
    result=_HEADER+bytes(body)
    assert len(result)==296
    # Explicitly refuse to send the 32-byte digest lifted from PCAP, even if
    # it happens to equal the regenerated one. The fresh input is authoritative.
    checks['auth_preparable_avec_rtc']=True
    return checks,result


def _context(coordinator:Any,config_dir:str|Path,nom_capture:str,ip_station:str):
    ip=_validate_target(ip_station)
    base=Path(config_dir)/'smart_aosu_traces'
    root=base.resolve();capture=(root/nom_capture).resolve()
    if capture.parent!=root or not capture.is_file() or capture.stat().st_size>32*1024*1024:
        raise ValueError('capture_absente')
    client=getattr(coordinator,'client',None)
    cache=getattr(client,'_tuya_oem_inventory_cache',{})
    devices=cache.get('devices',{}) if isinstance(cache,dict) else {}
    data=getattr(coordinator,'data',None)
    if not isinstance(devices,dict) or not isinstance(data,dict):raise ValueError('inventaire_absent')
    stationrows=[obj for obj in data.values() if isinstance(obj,dict) and
                 obj.get('model')=='H1L' and obj.get('is_camera') is False]
    if len(stationrows)!=1:raise ValueError('station_ambigue')
    stations=[(did,dev) for did,dev in devices.items() if isinstance(dev,dict)
              and _match_name(dev,stationrows[0].get('name'))]
    if len(stations)!=1:raise ValueError('station_ambigue')
    station_id,station=stations[0]
    key=station.get('localKey')
    if not isinstance(key,str) or len(key.encode('utf-8'))!=16:raise ValueError('cle_station_absente')
    camera_id,_=_candidate(data,client,2)
    if not isinstance(camera_id,str) or camera_id not in devices:raise ValueError('camera_absente')
    plain=_record_first_auth(capture,ip,key.encode('utf-8'),station_id)
    if plain is None:raise ValueError('auth_capture_invalide')
    return plain,station_id,camera_id,devices


def audit_schema_auth_c9_b133(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
        confirmation_capture_personnelle,confirmation_camera_candidate,
        autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    report={'diagnostic':'aosu_audit_schema_auth_c9_b133','analyse_hors_ligne':True,
            'offres_0x20_envoyees':0,'stun_envoyes':0,'kcp_auth_push_envoyes':0,
            'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
            'secrets_retournes':False,'identifiants_retournes':False,
            'auth_schema_reconstructible':False}
    if confirmation_capture_personnelle is not True or confirmation_camera_candidate is not True:
        return {**report,'etat':'confirmations_requises'}
    if camera_numero!=2 or type(camera_numero) is not int or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_correspondances_auth_c9_b132(coordinator,config_dir=config_dir,
        nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
        confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for key in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if key in pre:report[key]=pre[key]
    if pre.get('etat')!='correspondances_identifiants_anonymisees':
        return {**report,'etat':pre.get('etat','auth_preflight_invalide')}
    try:
        plain,station_id,camera_id,devices=_context(coordinator,config_dir,nom_capture,ip_station)
        checks,_unused=_unique_meta(plain,station_id,camera_id,devices)
        # Do NOT include a credential from RTC here: this audit performs no RTC
        # request. Auth attempt makes a new RTC request just in time.
        return {**report,**checks,'auth_password_rtc_non_encore_demande':True,
                'etat':'schema_auth_c9_296_identifie' if checks['auth_schema_reconstructible']
                else 'schema_auth_c9_non_identifie'}
    except (OSError,TypeError,ValueError,KeyError,IndexError,UnicodeError):
        return {**report,'etat':'schema_auth_c9_inexploitable'}
    except Exception:return {**report,'etat':'erreur_interne_masquee'}


def essai_auth_rtc_c9_b133(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
        confirmation_capture_personnelle,confirmation_camera_candidate,
        autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False,
        autoriser_configuration_rtc=False,autoriser_offre_lan_active=False,
        autoriser_test_ice_actif=False,autoriser_test_kcp_actif=False,
        autoriser_auth_kcp_active=False,autoriser_auth_experimentale_b133=False)->dict:
    report={'diagnostic':'aosu_essai_auth_rtc_c9_b133','offres_0x20_envoyees':0,
          'stun_envoyes':0,'kcp_wask_envoyes':0,'kcp_auth_push_envoyes':0,
          'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
          'secrets_retournes':False,'identifiants_retournes':False,
          'auth_schema_reconstructible':False,'hypothese_md5_rtc_non_verifiee':True}
    if not all(x is True for x in (confirmation_capture_personnelle,
        confirmation_camera_candidate,autoriser_configuration_rtc,
        autoriser_offre_lan_active,autoriser_test_ice_actif,autoriser_test_kcp_actif,
        autoriser_auth_kcp_active,autoriser_auth_experimentale_b133)):
        return {**report,'etat':'consentements_experimentaux_requis'}
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_schema_auth_c9_b133(coordinator,config_dir=config_dir,
        nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
        confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    if pre.get('auth_schema_reconstructible') is not True:
        return {**report,**pre,'diagnostic':'aosu_essai_auth_rtc_c9_b133',
                'etat':'auth_non_emise_schema_non_reconstructible'}
    # B125 obtains one fresh RTC config and holds it in memory. The closure
    # consumes it at most once, before any LAN offer is emitted.
    def from_fresh_rtc(rtc,client,station_id,camera_id):
        plain,sid,cid,devices=_context(coordinator,config_dir,nom_capture,ip_station)
        if sid!=station_id or cid!=camera_id:raise ValueError('auth_schema_identites_non_conforme')
        checks,auth=_new_auth(plain,sid,cid,devices,rtc)
        if auth is None:
            if not checks.get('auth_mot_de_passe_rtc_present'):
                raise ValueError('auth_rtc_password_absent')
            if not checks.get('auth_cle_locale_camera_valide'):
                raise ValueError('auth_rtc_cle_camera_absente')
            raise ValueError('auth_schema_identites_non_conforme')
        return lambda ip,key,offer,candidate,udp: _session_kcp_b130(ip,key,offer,candidate,udp,auth)
    result=essai_negociation_lan_c9_b125(coordinator,config_dir=config_dir,
        nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
        confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
        autoriser_configuration_rtc=True,autoriser_offre_lan_active=True,
        session_context_factory=from_fresh_rtc)
    # Values returned by B125/B130 are diagnostic counters only; keep source
    # of candidate auth clear for later analysis, never return credentials.
    result['diagnostic']='aosu_essai_auth_rtc_c9_b133'
    result['auth_hypothese']='md5_mot_de_passe_rtc_cle_locale_c9'
    result['hypothese_md5_rtc_non_verifiee']=True
    result['auth_capture_rejouee']=False
    result['auth_ancien_secret_reutilise']=False
    result['secrets_retournes']=False
    return result
