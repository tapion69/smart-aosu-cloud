"""Home Assistant preflight for the locally supplied compatible AOSU APK.

Lite APK can stay unmodified; use a separately verified OEM resource archive
created from the same AOSU original APK. Only offline preflight is automatic.
"""
from __future__ import annotations
import hashlib
import zipfile
from pathlib import Path
import threading
import time
from .native_v2 import _load_native, _consts, recover_intermediate, transform
from .oem_preflight_b7 import load_identity, TuyaSigner
from .tuya_uid_gateway import do_token_request, do_uid_login_request, TuyaAuthSession
from .oem_resource_bundle import load_verified_oem_resources

ORIGINAL_APK_SHA256='ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7'
ORIGINAL_APK_SIZE=200265946
LITE_APK_SHA256='6a3692aa0dc2385f9d988ffbcf7a703249d426b022f78857d2b380748e790be1'
LITE_APK_SIZE=1690990
_LOCK=threading.Lock()
_ALLOWED_AFTER: dict[int,float]={}
_COOLDOWN=3600


def _ready_identity(client):
    hints=getattr(client,'_oem_identity_hints',None)
    if hints is None or not hints.country_code or not hints.tuya_username:
        return None
    profile=getattr(client,'_profile',None)
    if not isinstance(profile,dict):return None
    headers=profile.get('additional_headers')
    if not isinstance(headers,dict):return None
    imei=headers.get('Gz-Imei')
    if not isinstance(imei,str) or not 5<=len(imei)<=128 or any(ord(ch)<33 or ord(ch)>126 for ch in imei):
        return None
    return hints,imei


def _failure(status,stage,code):
    return {**status,'preflight_valide':False,'etape_arret':stage,'cause':code},None


def _hash_file(p:Path)->str:
    sha=hashlib.sha256()
    with p.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1048576),b''):
            sha.update(chunk)
    return sha.hexdigest()


def _apk_preflight(apk_path):
    status={'diagnostic':'aosu_uid_preflight_b10','preflight_valide':False,
            'mode_ressources':'inconnu','apk_identique_a_reference':False,
            'apk_lite_reconnu':False,'empreinte_apk_verifiee':False,
            'complement_oem_verifie':False,'decodage_native_valide':False,
            'signature_oem_validee_par_serveur':False,
            'appel_reseau':0,'secrets_retournes':False}
    stage='verification_fichier'
    try:
        p=Path(apk_path)
        if not p.is_file():return _failure(status,stage,'apk_introuvable')
        size=p.stat().st_size
        if size not in (ORIGINAL_APK_SIZE,LITE_APK_SIZE):
            return _failure(status,stage,'apk_format_non_reconnu')
        digest=_hash_file(p)
        status['empreinte_apk_verifiee']=True
        if size==ORIGINAL_APK_SIZE and digest==ORIGINAL_APK_SHA256:
            status['mode_ressources']='apk_complet_original'
            status['apk_identique_a_reference']=True
            stage='lecture_identite_apk'
            identity=load_identity(p)
            stage='lecture_bibliotheque_arm64'
            so=_load_native(p)
        elif size==LITE_APK_SIZE and digest==LITE_APK_SHA256:
            status['mode_ressources']='apk_lite_avec_complement'
            status['apk_lite_reconnu']=True
            stage='lecture_complement_oem'
            try:
                identity,so=load_verified_oem_resources(p.parent)
            except FileNotFoundError:
                return _failure(status,stage,'complement_oem_absent')
            except (OSError,ValueError,zipfile.BadZipFile):
                return _failure(status,stage,'complement_oem_invalide')
            status['complement_oem_verifie']=True
        else:
            return _failure(status,stage,'empreinte_apk_differente')
        stage='reconstruction_bmp_v2'
        raw=recover_intermediate(identity.app_id,identity.t_s_bmp)
        stage='transformation_native'
        key=transform(raw,_consts(so))
        if len(key)!=32 or not key.isascii() or not key.isalnum():
            return _failure(status,stage,'sortie_native_invalide')
        stage='preparation_signature'
        signer=TuyaSigner(identity,key.decode('ascii'))
        status['decodage_native_valide']=True
        status['preflight_valide']=True
        status['etat']='verification_locale_reussie'
        return status,(identity,signer)
    except (OSError,ValueError,KeyError,IndexError,TypeError,OverflowError,MemoryError):
        return _failure(status,stage,'erreur_locale')
    except Exception:
        return _failure(status,stage,'erreur_execution_inattendue')


def run_tuya_uid_preflight(client):
    report,_=_apk_preflight(client.apk_path)
    return report


def run_tuya_uid_token_probe(client):
    report={'diagnostic':'smart_aosu_tuya_uid_token_b13','appel_reseau':0,
            'requete_max':1,'mot_de_passe_envoye':False,'login_tuya_oem_valide':False,
            'session_video_creee':False,'commande_camera':0,'secrets_retournes':False,
            'methode_signature':'candidat_python_non_valide_par_reference_native',
            'api_jeton':'thing.m.user.username.token.get',
            'version_api_jeton':'2.0','is_uid':True,
            'ttid_source':'hypothese_sdk_international',
            'device_id_source':'profil_android_Gz_Imei_non_valide_pour_Tuya'}
    if not _LOCK.acquire(blocking=False):return {**report,'etat':'essai_deja_en_cours'}
    try:
        now=time.monotonic()
        key=id(client)
        if now<_ALLOWED_AFTER.get(key,0):
            return {**report,'etat':'limite_une_tentative_par_heure'}
        ready=_ready_identity(client)
        if ready is None:return {**report,'etat':'connexion_AOSU_ou_profil_android_indisponible'}
        hints,install_id=ready
        local,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**report,**local,'etat':'echec_preparation_locale'}
        identity,signer=parsed
        _ALLOWED_AFTER[key]=now+_COOLDOWN
        try:
            response=do_token_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                ttid=f'sdk_international@{identity.app_id}',device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            return {**report,**local,**response,'etat':'reponse_tuya_obtenue',
                    'preflight_valide':True}
        except Exception:
            return {**report,**local,'appel_reseau':1,
                    'etat':'echec_reseau_ou_reponse_non_decodable'}
    finally:
        _LOCK.release()


_LOGIN_ALLOWED_AFTER: dict[int,float]={}

def run_tuya_uid_login_probe(client, *, confirmation_envoi_mot_de_passe:bool=False):
    """Manual opt-in ONLY: sends user's locally stored AOSU password to Tuya as RSA+AES+TLS."""
    base={'diagnostic':'aosu_tuya_uid_login_b13','appel_reseau':0,
          'confirmation_envoi_mot_de_passe':confirmation_envoi_mot_de_passe is True,
          'mot_de_passe_envoye':False,'session_tuya_authentifiee':False,
          'session_video_creee':False,'commande_camera':0,'secrets_retournes':False}
    if confirmation_envoi_mot_de_passe is not True:
        return {**base,'etat':'confirmation_explicite_requise'}
    if not _LOCK.acquire(blocking=False):
        return {**base,'etat':'essai_deja_en_cours'}
    try:
        now=time.monotonic()
        # Rate limit across config entry reloads during this HA process lifetime.
        identity_key=id(client)
        if now<_LOGIN_ALLOWED_AFTER.get(identity_key,0):
            return {**base,'etat':'limite_une_tentative_login_par_heure'}
        ready=_ready_identity(client)
        if ready is None:return {**base,'etat':'identite_oem_non_disponible'}
        hints,installation=ready
        if not isinstance(client.password,str) or not client.password:
            return {**base,'etat':'mot_de_passe_absent_de_la_configuration'}
        status,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**base,**status,'etat':'preflight_invalide'}
        identity,signer=parsed
        _LOGIN_ALLOWED_AFTER[identity_key]=now+3600
        try:
            details,session=do_uid_login_request(identity,signer,'sha256_material',
                  uid=hints.tuya_username,country_code=hints.country_code,password=client.password,
                  ttid=f'sdk_international@{identity.app_id}',device_id=installation,
                  endpoint='https://a1.tuyaeu.com/api.json')
            if session is not None:
                # Never persist secrets to disk; valid only during this process lifetime.
                client._tuya_oem_session=session
            return {**base,**details,'preflight_valide':True}
        except Exception:
            return {**base,'etat':'echec_execution_gateway','appel_reseau':'inconnu'}
    finally:
        _LOCK.release()
