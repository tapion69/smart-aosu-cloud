"""b78 - One consented read of SDK product info, never a PTZ publication.

APK classes4.dex #23820 / classes5.dex #3374: thing.m.product.info.get
v1.0, productId, optional mac/uuid. We send productId only.

SDK classes4.dex #33576: ProductBean.getCapability() == 8 can select
sendDpsByApi -> #31068 thing.m.nb.device.dp.publish v1.0.
An API product-info value is *not* proof of the runtime ProductBean value.
"""
from __future__ import annotations
import threading
import time
from typing import Any

_LOCK = threading.Lock()
_LAST: dict[int, float] = {}
_INTERVAL = 180


def inspect_product_info_capability(payload: Any) -> dict:
    """Anonymized, bounded extraction only from plausible product descriptors."""
    result = {'produit_info_lisible': isinstance(payload, dict),
              'champs_capability_trouves': 0,
              'valeurs_contradictoires': False,
              'valeur_numerique': None,
              'capability_8_observee': False,
              'source_productbean_confirmee': False,
              'branche_sdk_active_confirmee': False,
              'autorisation_publication': False,
              'donnees_brutes_retournees': False,
              'identifiants_retournes': False,
              'secrets_retournes': False}
    if not isinstance(payload,dict):
        result['verdict'] = 'reponse_produit_non_exploitable'
        return result
    queue=[(payload,0)]
    values=[]
    count=0
    while queue and count<32:
        node,depth=queue.pop(0);count+=1
        if not isinstance(node,dict) or depth>3:
            continue
        if 'capability' in node:
            raw=node.get('capability')
            val=None
            if type(raw) is int and 0<=raw<2**32:
                val=raw
            elif isinstance(raw,str) and raw.isascii() and raw.isdecimal() and len(raw)<11:
                num=int(raw)
                if num<2**32:val=num
            result['champs_capability_trouves']+=1
            if val is not None:values.append(val)
        for key in ('result','data','product','productInfo','productBean','info'):
            sub=node.get(key)
            if isinstance(sub,dict):queue.append((sub,depth+1))
    distinct=set(values)
    result['valeurs_contradictoires']=len(distinct)>1
    if len(distinct)==1 and len(values)==result['champs_capability_trouves']:
        value=next(iter(distinct))
        result['valeur_numerique']=value
        result['capability_8_observee']=value==8
        result['verdict']='capability_8_candidate_pour_branche_api' if value==8 else 'capability_differente_de_8_dans_cette_reponse'
    elif result['champs_capability_trouves']:
        result['verdict']='capability_ambiguë_ou_invalide'
    else:
        result['verdict']='capability_absente_de_la_reponse'
    return result


def audit_product_info_b78(coordinator:Any,*,password_confirmed:bool=False,
                           camera_confirmed:bool=False)->dict:
    out={'diagnostic':'aosu_info_produit_b78', 'lecture_seule':True,
         'api_lue':'thing.m.product.info.get','version_api':'1.0',
         'appels_reseau':0,'commandes_ptz_envoyees':0,'commandes_stop_envoyees':0,
         'publications_mqtt':0,'publications_http':0,'video_modifiee':False,
         'identifiants_retournes':False,'secrets_retournes':False,
         'branche_sdk_active_confirmee':False}
    if password_confirmed is not True or camera_confirmed is not True:
        return {**out,'etat':'deux_confirmations_requises'}
    if bool(getattr(getattr(coordinator,'live_controller',None),'running',False)):
        return {**out,'etat':'direct_en_cours'}
    from .ptz_device_detail_b39 import select_c5l_oem
    from .ptz_product_model_b51 import find_product_identity
    from .ptz_readiness import audit_ptz_readiness,refresh_ptz_inventory
    from .tuya_uid_gateway import TuyaAuthSession,OEMGatewayError,do_uid_login_request,do_oem_read
    from .uid_token_probe import _ready_identity,_apk_preflight
    ready=audit_ptz_readiness(coordinator,coordinator.client)
    if ready.get('cache_oem_recent') is not True:
        update=refresh_ptz_inventory(coordinator,password_confirmed=True)
        out['appels_reseau']+=int(update.get('appels_reseau',0))
        if update.get('etat') not in ('inventaire_oem_ptz_lu','cache_recent_reutilise'):
            return {**out,'etat':'inventaire_non_disponible'}
    selected,reason=select_c5l_oem(coordinator)
    if selected is None:return {**out,'etat':reason}
    _,row,method=selected
    out['selection_oem']=method
    pid,_=find_product_identity(row)
    if pid is None:return {**out,'etat':'product_id_absent_ou_ambigu'}
    client=coordinator.client
    key=id(client)
    if time.monotonic()<_LAST.get(key,0):return {**out,'etat':'temporisation_lecture_produit'}
    if not _LOCK.acquire(False):return {**out,'etat':'audit_produit_deja_en_cours'}
    try:
        now=time.monotonic()
        if now<_LAST.get(key,0):return {**out,'etat':'temporisation_lecture_produit'}
        _LAST[key]=now+_INTERVAL
        ident=_ready_identity(client)
        if ident is None:return {**out,'etat':'profil_oem_absent'}
        hints,install_id=ident
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**out,'etat':'ressources_oem_invalides'}
        identity,signer=parsed
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or not 0<=now-session.acquired_at<1200:
            pwd=getattr(client,'password',None)
            if not isinstance(pwd,str) or not pwd:return {**out,'etat':'mot_de_passe_absent'}
            login,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                password=pwd,ttid=ttid,device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            out['appels_reseau']+=int(login.get('appel_reseau',0))
            if session is None:return {**out,'etat':'authentification_refusee'}
            client._tuya_oem_session=session
        out['appels_reseau']+=1
        response,status=do_oem_read(identity,signer,'sha256_material',session,
            action='thing.m.product.info.get',form_data={'productId':pid},
            ttid=ttid,device_id=install_id,endpoint='https://a1.tuyaeu.com/api.json')
        if status.get('rejet_explicite') or not status.get('serveur_accepte'):
            return {**out,'etat':'lecture_produit_refusee',
                    'categorie_refus':status.get('categorie_refus','indeterminee')}
        return {**out,'etat':'fiche_produit_lue',
                'analyse':inspect_product_info_capability(response)}
    except OEMGatewayError as exc:
        return {**out,'etat':'erreur_api_oem','raison':exc.code}
    except Exception:
        return {**out,'etat':'erreur_sans_details'}
    finally:
        _LOCK.release()
