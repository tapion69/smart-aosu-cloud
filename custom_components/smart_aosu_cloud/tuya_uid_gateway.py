"""Opt-in OEM UID token/login transport. Secrets never enter HA service results/logs.

The native-equivalence of the candidate signer is NOT independently established.
The server response, rather than local signature shape, must establish success.
"""
from __future__ import annotations
import base64
import gzip
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Any

import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .oem_preflight_b7 import canonical_string, APKIdentity, TuyaSigner

_ENDPOINT = 'https://a1.tuyaeu.com/api.json'
_MAX_RESPONSE = 65536

@dataclass(repr=False)
class TuyaAuthSession:
    sid: str = field(repr=False)
    ecode: str = field(repr=False)
    uid: str = field(repr=False)
    acquired_at: float = field(default_factory=time.monotonic, repr=False)
    def __repr__(self):return '<TuyaAuthSession redacted>'

class OEMGatewayError(Exception):
    """Code known to be safe to publish (never network-supplied text)."""
    def __init__(self,code:str,network_calls:int=0,http_ok:bool=False):
        super().__init__(code);self.code=code;self.calls=network_calls;self.http_ok=http_ok


def _require_string(record:dict,name:str,max_length:int=8192)->str:
    value=record.get(name)
    if not isinstance(value,str) or not value or len(value)>max_length:
        raise OEMGatewayError('champ_'+name+'_absent')
    return value


def _envelope_status(outer:dict, decoded:dict)->dict:
    """Distinguish the signed outer transport envelope and decrypted API payload.

    Do not treat missing outer `success` as refusal when the inner body has it.
    Explicit rejection from either layer always wins.
    """
    o=outer.get('success')
    root=decoded
    layers=[decoded]
    # Some OEM responses wrap `result` twice, each with a separate status.
    for _ in range(2):
        nested=layers[-1].get('result')
        if not isinstance(nested,dict):break
        layers.append(nested)
    i=next((level['success'] for level in layers if type(level.get('success')) is bool),None)
    rejected=(o is False or any(level.get('success') is False or bool(level.get('errorCode')) for level in [outer,*layers]))
    explicitly_accepted=not rejected and (o is True or any(level.get('success') is True for level in layers))
    inner=layers[-1]
    return {'rejet_explicite':rejected,'acceptation_explicite':explicitly_accepted,
            'statut_exterieur': 'oui' if o is True else 'non' if o is False else 'absent',
            'statut_interieur': 'oui' if i is True else 'non' if i is False else 'absent',
            'data':inner}


def _safe_code(outer:dict, decoded:dict):
    levels=[decoded]
    if isinstance(decoded.get("result"),dict):levels.append(decoded["result"])
    for d in (*levels,outer):
        c=d.get('errorCode')
        if type(c) is int and 0<=c<=99999999:return str(c)
        if isinstance(c,str) and c.isdecimal() and len(c)<=8:return c
    return None



# The backend error is untrusted. Never send its raw text to a HA service response.
# Only literal numeric error codes (<=8 digits) may be reported verbatim.
_REFUSAL_HINTS = (
    ('mot_de_passe_ou_identifiants', ('PASSWORD', 'PASSWD', 'PWD', 'CREDENTIAL', 'INCORRECT_PASSWORD', 'INVALID_PASSWORD')),
    ('trop_de_tentatives', ('TOO_MANY', 'FREQUENT', 'RATE_LIMIT', 'LOCKED', 'BANNED')),
    ('jeton_invalide', ('TOKEN', 'TICKET', 'EXPIRE')),
    ('region', ('REGION', 'COUNTRY', 'DATACENTER')),
    ('signature_ou_application', ('SIGNATURE', 'SIGN_INVALID', 'APPKEY', 'CLIENTID', 'APP_SECRET', 'APPID')),
    ('installation', ('DEVICEID', 'DEVICE_ID', 'DEVICE ID', 'IMEI')),
    ('autorisation', ('PERMISSION', 'FORBIDDEN', 'DENIED', 'AUTHORIZATION')),
    ('compte_ou_uid', ('USERNAME', 'ACCOUNT', 'USER_NOT', 'USER_EXIST', 'UID', 'USERID')),
    ('parametres', ('PARAM_ERROR', 'PARAMETER', 'INVALID_PARAM', 'MISSING_PARAM')),
)


def _safe_server_refusal(outer:dict, decoded:dict)->dict[str,object]:
    """Classify a refused request without exposing untrusted error strings.

    Inspect only the most common envelope layers. Both the raw error message and
    any symbolic error code remain private. Never echo remote data or a hash of
    a user-supplied identifier.
    """
    layers=[('enveloppe_https',outer),('reponse_dechiffree',decoded)]
    node=decoded
    for depth in range(2):
        node=node.get('result') if isinstance(node,dict) else None
        if not isinstance(node,dict):break
        layers.append((f'resultat_imbrique_{depth+1}',node))
    candidates=[]
    numeric=None
    code_type='absent'
    code_present=False
    msg_present=False
    source='inconnue'
    for location, obj in layers:
        code=obj.get('errorCode')
        if code is None: code=obj.get('error_code')
        if code is None: code=obj.get('code') if obj.get('success') is False else None
        message=obj.get('errorMsg')
        if message is None: message=obj.get('error_msg')
        if message is None: message=obj.get('msg') if obj.get('success') is False else None
        if message is None: message=obj.get('message') if obj.get('success') is False else None
        has_error = obj.get('success') is False or (code is not None and code not in ('',0,'0',False))
        if has_error and source=='inconnue':source=location
        if code not in (None,''):
            code_present=True
            if type(code) is int or isinstance(code,str) and code.isdecimal():
                v=str(code)
                if 0<len(v)<=8 and v!='0' and numeric is None:numeric=v
                if code_type=='absent':code_type='numerique'
            elif isinstance(code,str):
                code_type='symbolique'
                if len(code)<=160:candidates.append(code)
            else: code_type='autre'
        if isinstance(message,str) and message:
            msg_present=True
            candidates.append(message[:240])
    # The code string itself may be a sensitive identifier. Never return it.
    # Classification only using fixed, public keyword sets.
    category='indeterminee'
    for candidate in candidates:
        normalized=candidate.upper()
        for label,keywords in _REFUSAL_HINTS:
            if any(keyword in normalized for keyword in keywords):
                category=label
                break
        if category!='indeterminee':break
    safe={'source_refus':source,
          'code_erreur_present':code_present,
          'type_code_erreur':code_type,
          'message_erreur_present':msg_present,
          'categorie_refus':category,
          'code_et_message_bruts_masques':True}
    if numeric is not None:safe['code_erreur_tuya']=numeric
    return safe


def _call_api(identity:APKIdentity,signer:TuyaSigner,mode:str,*,
              action:str,form_data:dict[str,Any],ttid:str,device_id:str,
              api_version:str='1.0',endpoint:str=_ENDPOINT,session:TuyaAuthSession|None=None,
              biz_domain:str|None=None)->tuple[dict,dict,dict]:
    u=urlparse(endpoint)
    if u.scheme!='https' or u.hostname not in {'a1.tuyaeu.com','a1-eu.iotbing.com'} or u.path!='/api.json':
        raise OEMGatewayError('destination_non_autorisee')
    if api_version not in ('1.0','2.0','2.2','4.1'):
        raise OEMGatewayError('version_api_invalide')
    if not ttid or len(ttid)>100 or not device_id or len(device_id)>128:
        raise OEMGatewayError('identite_installation_invalide')
    request_id=secrets.token_hex(16)
    derived_key=signer.derive_key(request_id,session.ecode if session else None)
    nonce=os.urandom(12)
    body=json.dumps(form_data,separators=(',',':'),ensure_ascii=False).encode('utf8')
    encrypted=base64.b64encode(nonce+AESGCM(derived_key).encrypt(nonce,body,None)).decode('ascii')
    fields={'a':action,'v':api_version,'clientId':identity.app_id,'os':'Android','appVersion':'5.10.12',
            'chKey':signer.channel_key(),'deviceId':device_id,'time':str(int(time.time())),
            'requestId':request_id,'et':'3','lang':'fr','ttid':ttid,'postData':encrypted}
    if biz_domain is not None:
        if biz_domain!='ipc':raise OEMGatewayError('biz_domain_non_autorise')
        fields['bizDM']=biz_domain
    if session:fields['sid']=session.sid
    fields['sign']=signer.sign_candidate(canonical_string(fields),mode)
    try:
        with requests.Session() as s:
            s.trust_env=False
            response=s.post(endpoint,data=fields,headers={'User-Agent':'TY/5.10.12'},
                            timeout=(8,20),allow_redirects=False,verify=True)
        if response.status_code!=200:
            raise OEMGatewayError('http_non_200',1,False)
        if len(response.content)>_MAX_RESPONSE:
            raise OEMGatewayError('reponse_trop_volumineuse',1,True)
        outer=response.json()
        if not isinstance(outer,dict):raise ValueError('not dict')
        encrypted_result=outer.get('result')
        if not isinstance(encrypted_result,str) or not encrypted_result:
            raise OEMGatewayError('reponse_non_chiffree_ou_absente',1,True)
        raw=base64.b64decode(encrypted_result,validate=True)
        if len(raw)<29:raise ValueError('too short')
        plain=AESGCM(derived_key).decrypt(raw[:12],raw[12:],None)
        try:plain=gzip.decompress(plain)
        except OSError:pass
        decoded=json.loads(plain)
        if not isinstance(decoded,dict):raise ValueError('not dict')
        status=_envelope_status(outer,decoded)
        return outer,decoded,status
    except OEMGatewayError:raise
    except Exception:
        # Never relay raw remote response or request headers; type alone is safe.
        raise OEMGatewayError('reseau_ou_reponse_invalide',1,False) from None


def _token(identity:APKIdentity,signer:TuyaSigner,mode:str,*,uid:str,country_code:str,ttid:str,device_id:str,endpoint:str):
    if not isinstance(uid,str) or not uid or len(uid)>256 or not country_code.isdigit() or not 1<=len(country_code)<=4:
        raise OEMGatewayError('parametres_uid_invalides')
    outer,decoded,status=_call_api(identity,signer,mode,action='thing.m.user.username.token.get',
              api_version='2.0',form_data={'countryCode':country_code,'username':uid,'isUid':True},
              ttid=ttid,device_id=device_id,endpoint=endpoint)
    data=status['data']
    if not isinstance(data,dict):data={}
    fields={'jeton_present':isinstance(data.get('token'),str) and bool(data.get('token')),
            'cle_publique_presente':isinstance(data.get('publicKey'),str) and bool(data.get('publicKey')),
            'exposant_rsa_present':str(data.get('exponent') or '').isdigit()}
    safe={'appel_reseau':1,'http_ok':True,
          'serveur_accepte':status['acceptation_explicite'],
          'rejet_explicite':status['rejet_explicite'],
          'statut_exterieur':status['statut_exterieur'],'statut_interieur':status['statut_interieur'],
          'reponse_dechiffree':True,**fields,'secrets_retournes':False}
    code=_safe_code(outer,decoded)
    if code:safe['code_erreur_tuya']=code
    return data,safe


def do_token_request(identity:APKIdentity,signer:TuyaSigner,mode:str,*,uid:str,country_code:str,ttid:str,device_id:str,endpoint:str)->dict[str,object]:
    try:
        _,safe=_token(identity,signer,mode,uid=uid,country_code=country_code,ttid=ttid,device_id=device_id,endpoint=endpoint)
        return safe
    except OEMGatewayError as exc:
        return {'appel_reseau':exc.calls,'http_ok':exc.http_ok,'serveur_accepte':False,
                'etat_requete':exc.code,'secrets_retournes':False}


def _encrypt_password(password:str,public_key:str,exponent:str)->str:
    """PKCS1v1.5 RSA over ASCII MD5, as used by Tuya mobile UID login."""
    if not isinstance(password,str) or not password or len(password)>1024:
        raise OEMGatewayError('mot_de_passe_indisponible')
    try:
        n=int(public_key,10);e=int(exponent,10)
        if not 1024<=n.bit_length()<=8192 or e not in (3,65537):
            raise ValueError('rsa parameters')
        pk=rsa.RSAPublicNumbers(e,n).public_key()
        digest=hashlib.md5(password.encode('utf8'),usedforsecurity=False).hexdigest().encode('ascii')
        return pk.encrypt(digest,padding.PKCS1v15()).hex()
    except (ValueError,TypeError,OverflowError):
        raise OEMGatewayError('parametres_rsa_invalides') from None


def do_uid_login_request(identity:APKIdentity,signer:TuyaSigner,mode:str,*,uid:str,country_code:str,
                         password:str,ttid:str,device_id:str,endpoint:str)->tuple[dict[str,object],TuyaAuthSession|None]:
    """Two HTTPS calls only after EXPLICIT action; no retries and no camera actions."""
    try:
        token,safe=_token(identity,signer,mode,uid=uid,country_code=country_code,ttid=ttid,device_id=device_id,endpoint=endpoint)
        summary={'diagnostic':'aosu_tuya_uid_login_b13','appel_reseau':1,'mot_de_passe_envoye':False,
                 'session_tuya_authentifiee':False,'session_video_creee':False,'commande_camera':0,
                 'secrets_retournes':False,'token':safe}
        if not safe['serveur_accepte'] or safe['rejet_explicite']:
            return {**summary,'etat':'jeton_non_accepte'},None
        if not all(safe[k] for k in ('jeton_present','cle_publique_presente','exposant_rsa_present')):
            return {**summary,'etat':'jeton_rsa_incomplet'},None
        passwd=_encrypt_password(password,_require_string(token,'publicKey'),_require_string(token,'exponent'))
        form={'countryCode':country_code,'uid':uid,'passwd':passwd,
              'token':_require_string(token,'token'),'ifencrypt':1,'options':'{"group": 1}'}
        try:
            outer,decoded,status=_call_api(identity,signer,mode,action='thing.m.user.uid.password.login',
                  form_data=form,ttid=ttid,device_id=device_id,endpoint=endpoint)
        except OEMGatewayError as exc:
            return {**summary,'appel_reseau':1+exc.calls,
                    'mot_de_passe_envoye':bool(exc.calls),'etat':exc.code},None
        # 2nd call encrypted the password in both RSA and HTTPS; report only flags.
        summary.update({'appel_reseau':2,'mot_de_passe_envoye':True,
                       'login_serveur_accepte':status['acceptation_explicite'],
                       'login_rejet_explicite':status['rejet_explicite']})
        if status['rejet_explicite']:
            summary.update(_safe_server_refusal(outer,decoded))
        elif not status['acceptation_explicite']:
            summary['categorie_refus']='statut_non_confirme'
        if not status['acceptation_explicite'] or status['rejet_explicite']:
            return {**summary,'etat':'login_refuse_ou_non_confirme'},None
        data=status['data']
        if not isinstance(data,dict):return {**summary,'etat':'reponse_login_non_structuree'},None
        try:
            session=TuyaAuthSession(_require_string(data,'sid'),_require_string(data,'ecode'),_require_string(data,'uid'))
        except OEMGatewayError:
            return {**summary,'etat':'login_accepte_session_incomplete'},None
        return {**summary,'etat':'login_uid_reussi','session_tuya_authentifiee':True},session
    except OEMGatewayError as exc:
        return {'diagnostic':'aosu_tuya_uid_login_b13','etat':exc.code,'appel_reseau':exc.calls,
                'mot_de_passe_envoye':False,
                'session_tuya_authentifiee':False,'session_video_creee':False,
                'commande_camera':0,'secrets_retournes':False},None


# Allowlisted read-only actions verified against the AOSU / Tuya SDK.
_READ_ACTIONS = {
    'm.life.home.space.list': '1.0',
    'm.life.my.group.device.list': '2.2',
    'thing.m.rtc.config.get': '1.0',
    # Official Tuya Smart App SDK IPC configuration; v2.0, devId only.
    'thing.m.ipc.config.get': '2.0',
    'thing.m.device.get': '4.1',
    # b51: product-level model documented by AOSU's own Android SDK.
    'thing.m.product.thing.model': '1.0',
    # b78: product info read verified in APK classes4.dex #23820.
    'thing.m.product.info.get': '1.0',
}

def do_oem_read(identity:APKIdentity,signer:TuyaSigner,mode:str,
                session:TuyaAuthSession,*,action:str,form_data:dict,ttid:str,
                device_id:str,endpoint:str)->tuple[dict,dict]:
    """Read-only Tuya API call. Raw data stays in RAM and never in HA results."""
    if not isinstance(session,TuyaAuthSession) or not all(
            isinstance(getattr(session,k,None),str) and getattr(session,k)
            for k in ('sid','ecode','uid')):
        raise OEMGatewayError('session_tuya_absente')
    if action not in _READ_ACTIONS:
        raise OEMGatewayError('api_lecture_non_autorisee')
    if not isinstance(form_data,dict) or len(form_data)>3:
        raise OEMGatewayError('parametres_lecture_invalides')
    if action == 'm.life.home.space.list':
        if form_data != {}:raise OEMGatewayError('parametres_lecture_invalides')
    elif action == 'm.life.my.group.device.list':
        gid=form_data.get('gid')
        if set(form_data)!={'gid'} or type(gid) not in (int,str) or not str(gid).isdigit() or not 1<=len(str(gid))<=20:
            raise OEMGatewayError('parametres_lecture_invalides')
    elif action == 'thing.m.product.info.get':
        import re
        pid=form_data.get('productId')
        if set(form_data)!={'productId'} or not isinstance(pid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}',pid):
            raise OEMGatewayError('parametres_lecture_invalides')
    elif action == 'thing.m.product.thing.model':
        import re
        pid=form_data.get('productId')
        ver=form_data.get('productVersion')
        if (set(form_data)!={'productId','productVersion'} or
            not isinstance(pid,str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}',pid) or
            not isinstance(ver,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,32}',ver)):
            raise OEMGatewayError('parametres_lecture_invalides')
    else:
        dev=form_data.get('devId')
        if set(form_data)!={'devId'} or not isinstance(dev,str) or not 1<=len(dev)<=128:
            raise OEMGatewayError('parametres_lecture_invalides')
    outer,decoded,status=_call_api(identity,signer,mode,action=action,
        api_version=_READ_ACTIONS[action],form_data=form_data,ttid=ttid,
        device_id=device_id,endpoint=endpoint,session=session,
        biz_domain='ipc' if action in ('thing.m.rtc.config.get', 'thing.m.ipc.config.get') else None)
    safe={'http_ok':True,'serveur_accepte':status['acceptation_explicite'],
          'rejet_explicite':status['rejet_explicite']}
    if status['rejet_explicite']:safe.update(_safe_server_refusal(outer,decoded))
    return status['data'],safe


def publish_ptz_stop_once(identity:APKIdentity, signer:TuyaSigner, mode:str,
                          session:TuyaAuthSession, *, dev_id:str, ttid:str,
                          device_id:str, endpoint:str=_ENDPOINT)->dict:
    """Single explicit STOP-only Tuya DP publication, never a movement command.

    The APK's DPBusiness publishes `thing.m.device.dp.publish` v2.0 using
    gwId/devId/dps. Using the code rather than an invented numeric DP ID is
    deliberately conservative. Tuya may reject it; this is an experimental test.
    """
    import re
    if not isinstance(session,TuyaAuthSession) or not all(
        isinstance(getattr(session,k,None),str) and getattr(session,k)
        for k in ('sid','ecode','uid')):
        raise OEMGatewayError('session_tuya_absente')
    if not isinstance(dev_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}',dev_id):
        raise OEMGatewayError('identifiant_non_compatible')
    # Never accept a caller-provided DP name/value: only ptz_stop=true.
    form={'gwId':dev_id,'devId':dev_id,
          'dps':json.dumps({'ptz_stop':True},separators=(',',':'))}
    outer, decoded, status=_call_api(identity,signer,mode,
          action='thing.m.device.dp.publish',api_version='2.0',
          form_data=form,ttid=ttid,device_id=device_id,endpoint=endpoint,
          session=session)
    safe={'publication_http_repondue':True,
          'publication_acceptee_par_serveur':bool(status['acceptation_explicite']),
          'publication_refusee_par_serveur':bool(status['rejet_explicite']),
          'retour_ne_prouve_pas_arret_moteur':True}
    if status['rejet_explicite']:
        refusal=_safe_server_refusal(outer,decoded)
        safe['categorie_refus']=refusal.get('categorie_refus','indeterminee')
        if 'code_erreur_tuya' in refusal:safe['code_erreur_tuya']=refusal['code_erreur_tuya']
    return safe


def publish_ptz_stop_dp116_once(identity: APKIdentity, signer: TuyaSigner, mode: str,
                                 session: TuyaAuthSession, *, dev_id: str, ttid: str,
                                 device_id: str, endpoint: str = _ENDPOINT) -> dict:
    """b45: explicit experimental STOP, using documented *numeric* DP 116.

    This is an OEM HTTP publication experiment, NOT a reimplementation of
    IThingDevice.publishDps, and not evidence the C5L implements DP 116.
    The device's DP ID was not independently read from its schemaMap.
    No direction, no fallback, no automatic retries.
    """
    import re
    if not isinstance(session, TuyaAuthSession) or not all(
        isinstance(getattr(session, key, None), str) and getattr(session, key)
        for key in ('sid', 'ecode', 'uid')
    ):
        raise OEMGatewayError('session_tuya_absente')
    if not isinstance(dev_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{5,128}', dev_id):
        raise OEMGatewayError('identifiant_non_compatible')
    # Only this literal DP and boolean. Absolutely no direction parameter.
    form = {'gwId': dev_id, 'devId': dev_id,
            'dps': json.dumps({'116': True}, separators=(',', ':'))}
    outer, decoded, status = _call_api(
        identity, signer, mode, action='thing.m.device.dp.publish',
        api_version='2.0', form_data=form, ttid=ttid, device_id=device_id,
        endpoint=endpoint, session=session
    )
    report = {
        'publication_http_repondue': True,
        'publication_acceptee_par_serveur': bool(status['acceptation_explicite']),
        'publication_refusee_par_serveur': bool(status['rejet_explicite']),
        'retour_ne_prouve_pas_arret_moteur': True,
        'id_dp_documente_tuya_mais_non_valide_c5l': True,
        'code_publie': '116',
        'commande_direction_envoyee': False,
    }
    if status['rejet_explicite']:
        refusal = _safe_server_refusal(outer, decoded)
        report['categorie_refus'] = refusal.get('categorie_refus', 'indeterminee')
        if 'code_erreur_tuya' in refusal:
            report['code_erreur_tuya'] = refusal['code_erreur_tuya']
    return report
