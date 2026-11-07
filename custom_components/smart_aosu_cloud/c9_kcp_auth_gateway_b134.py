"""B134: explicitly opt-in H1L gateway-key hypothesis for a C9 subcamera.

No key is extracted or replayed from old PCAP. The H1L key comes ONLY from
current OEM inventory. The capture is used to validate immutable authorization
schema and both device IDs. A camera-specific key, if present, is never
silently replaced. A fresh RTC password is consumed in RAM just in time.

The gateway-key KCP auth digest remains an UNPROVEN hypothesis for AOSU C9s.
At most one application auth PUSH, without video/PTZ. Fail closed.
"""
from __future__ import annotations
import hashlib,struct
from typing import Any
from .c9_kcp_auth_rtc_b133 import (_context,_unique_meta,_HEADER,_MAX_PW,
    audit_schema_auth_c9_b133)
from .c9_lan_signal_b125 import essai_negociation_lan_c9_b125
from .c9_kcp_auth_b130 import _session_kcp_b130


def _new_auth_with_h1l_key(plain:bytes,station_id:str,camera_id:str,devices:dict,rtc:dict)->tuple[dict,bytes|None]:
    checks,meta=_unique_meta(plain,station_id,camera_id,devices)
    checks.update({'auth_mot_de_passe_rtc_present':False,
        'cle_locale_camera_absente':False,'cle_locale_station_valide':False,
        'auth_preparable_avec_cle_station':False,
        'utilisation_cle_station_hypothese':True,
        'formule_md5_c9_confirmee':False})
    if meta is None or not isinstance(devices,dict) or not isinstance(rtc,dict):return checks,None
    camera=devices.get(camera_id)
    station=devices.get(station_id)
    if not isinstance(camera,dict) or not isinstance(station,dict) or station_id==camera_id:return checks,None
    # Never substitute station key when a camera-specific key is available.
    own=camera.get('localKey')
    checks['cle_locale_camera_absente']=own is None or own==''
    if not checks['cle_locale_camera_absente']:return checks,None
    key=station.get('localKey')
    checks['cle_locale_station_valide']=isinstance(key,str) and len(key.encode('utf-8'))==16
    password=rtc.get('password')
    checks['auth_mot_de_passe_rtc_present']=isinstance(password,str) and 1<=len(password)<=_MAX_PW
    if not checks['cle_locale_station_valide'] or not checks['auth_mot_de_passe_rtc_present']:return checks,None
    # Hypothesis ONLY: gateway key may be the auth key for a camera behind H1L.
    md5=hashlib.md5((password+'||'+key).encode('utf-8'),usedforsecurity=False).hexdigest().encode('ascii')
    body=bytearray(288);body[:5]=b'admin';body[32:64]=md5
    body[96:128]=station_id.encode('utf-8').ljust(32,b'\0')
    body[160:192]=meta.encode('utf-8').ljust(32,b'\0')
    fresh=_HEADER+bytes(body)
    if len(fresh)!=296: return checks,None
    checks['auth_preparable_avec_cle_station']=True
    return checks,fresh


def audit_cle_h1l_c9_b134(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
        confirmation_capture_personnelle,confirmation_camera_candidate,
        autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    report={'diagnostic':'aosu_audit_cle_h1l_c9_b134','analyse_hors_ligne':True,
            'offres_0x20_envoyees':0,'stun_envoyes':0,'kcp_auth_push_envoyes':0,
            'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
            'secrets_retournes':False,'identifiants_retournes':False,
            'cle_locale_station_valide':False,'cle_locale_camera_absente':False,
            'liaison_station_camera_capture_confirmee':False,
            'auth_gateway_key_preparable':False,'formule_md5_c9_confirmee':False}
    pre=audit_schema_auth_c9_b133(coordinator,config_dir=config_dir,nom_capture=nom_capture,
        ip_station=ip_station,camera_numero=camera_numero,
        confirmation_capture_personnelle=confirmation_capture_personnelle,
        confirmation_camera_candidate=confirmation_camera_candidate,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for k in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if k in pre:report[k]=pre[k]
    if pre.get('auth_schema_reconstructible') is not True:
        return {**report,'etat':pre.get('etat','schema_non_reconstructible')}
    try:
        plain,sid,cid,devices=_context(coordinator,config_dir,nom_capture,ip_station)
        structure,meta=_unique_meta(plain,sid,cid,devices)
        if meta is None or structure.get('auth_schema_reconstructible') is not True:
            return {**report,'etat':'schema_capture_incoherent'}
        # _context uses B101's one-to-one matching AND the AOSU via_device
        # relation. Captured station+camera IDs must also match current OEM.
        station=devices[sid];camera=devices[cid]
        sk=station.get('localKey');ck=camera.get('localKey')
        report['cle_locale_station_valide']=isinstance(sk,str) and len(sk.encode('utf-8'))==16
        report['cle_locale_camera_absente']=ck is None or ck==''
        report['liaison_station_camera_capture_confirmee']=True
        report['auth_gateway_key_preparable']=(report['cle_locale_station_valide'] and
              report['cle_locale_camera_absente'])
        report['etat']=('hypothese_cle_station_preparable' if report['auth_gateway_key_preparable']
            else 'cle_station_non_applicable')
        return report
    except (TypeError,ValueError,KeyError,IndexError,OSError,UnicodeError):
        return {**report,'etat':'inventaire_ou_capture_inexploitable'}
    except Exception:return {**report,'etat':'erreur_interne_masquee'}


def essai_auth_station_c9_b134(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
    confirmation_capture_personnelle,confirmation_camera_candidate,
    autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False,
    autoriser_configuration_rtc=False,autoriser_offre_lan_active=False,
    autoriser_test_ice_actif=False,autoriser_test_kcp_actif=False,
    autoriser_auth_kcp_active=False,autoriser_essai_cle_station_b134=False)->dict:
    report={'diagnostic':'aosu_essai_auth_station_c9_b134','offres_0x20_envoyees':0,
       'stun_envoyes':0,'kcp_wask_envoyes':0,'kcp_auth_push_envoyes':0,
       'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
       'secrets_retournes':False,'identifiants_retournes':False,
       'auth_hypothese':'md5_mot_de_passe_rtc_cle_station_h1l',
       'formule_md5_c9_confirmee':False,'auth_capture_rejouee':False}
    if not all(x is True for x in (confirmation_capture_personnelle,
        confirmation_camera_candidate,autoriser_configuration_rtc,
        autoriser_offre_lan_active,autoriser_test_ice_actif,
        autoriser_test_kcp_actif,autoriser_auth_kcp_active,
        autoriser_essai_cle_station_b134)):
        return {**report,'etat':'consentements_experimentaux_requis'}
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_cle_h1l_c9_b134(coordinator,config_dir=config_dir,nom_capture=nom_capture,
        ip_station=ip_station,camera_numero=2,
        confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    if pre.get('auth_gateway_key_preparable') is not True:
        return {**report,**pre,'diagnostic':'aosu_essai_auth_station_c9_b134',
                'etat':'auth_non_emise_cle_station_non_confirmee'}
    def fresh_session(rtc,client,station_id,camera_id):
        plain,sid,cid,devices=_context(coordinator,config_dir,nom_capture,ip_station)
        if sid!=station_id or cid!=camera_id:
            raise ValueError('auth_schema_identites_non_conforme')
        checks,auth=_new_auth_with_h1l_key(plain,sid,cid,devices,rtc)
        if auth is None:
            if not checks['cle_locale_camera_absente']:
                raise ValueError('auth_cle_camera_present_politique_refus')
            if not checks['cle_locale_station_valide']:
                raise ValueError('auth_rtc_cle_station_absente')
            if not checks['auth_mot_de_passe_rtc_present']:
                raise ValueError('auth_rtc_password_absent')
            raise ValueError('auth_rtc_profil_invalide')
        return lambda ip,key,offer,candidate,udp:_session_kcp_b130(ip,key,offer,candidate,udp,auth)
    result=essai_negociation_lan_c9_b125(coordinator,config_dir=config_dir,
       nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
       confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
       autoriser_reconstitution_oem=autoriser_reconstitution_oem,
       confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe,
       autoriser_configuration_rtc=True,autoriser_offre_lan_active=True,
       session_context_factory=fresh_session)
    result['diagnostic']='aosu_essai_auth_station_c9_b134'
    result['auth_hypothese']='md5_mot_de_passe_rtc_cle_station_h1l'
    result['formule_md5_c9_confirmee']=False
    result['auth_capture_rejouee']=False
    result['auth_ancien_secret_reutilise']=False
    result['secrets_retournes']=False
    return result
