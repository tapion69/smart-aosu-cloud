"""b51: explicitly requested read-only Tuya PRODUCT model lookup.

SDK-confirmed AOSU 5.10.12 classes4.dex method 33369:
  thing.m.product.thing.model v1.0, productId, productVersion.
DeviceBean.schemaMap is product-derived (methods 31371, 4689 classes4/6).
NEVER returns product identifiers, localKeys, topics, model payload, DP values or server text.
One request maximum on a valid OEM session; no motor/video/MQTT operations.
"""
from __future__ import annotations

import re
import json
import threading
import time
from typing import Any

_PRODUCT_RE = re.compile(r"[A-Za-z0-9_-]{5,128}\Z")
_VERSION_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}\Z")
_LOCK=threading.Lock()
_LAST_READ:dict[int,float]={}
_RATE_LIMIT=120


def find_product_identity(row:Any)->tuple[str|None,str|None]:
    """Search only the selected OEM device's own product descriptor.

    Never use `pv` as productVersion: PV 2.2 is the MQTT protocol.
    Conflicting product identifiers fail closed.
    """
    if not isinstance(row,dict):return None,None
    candidates=[row]
    for key in ('product','productInfo','productBean','deviceInfo'):
        value=row.get(key)
        if isinstance(value,dict):candidates.append(value)
    pids=set();vers=set()
    for obj in candidates:
        for key in ('productId','product_id','pid'):
            v=obj.get(key)
            if isinstance(v,str) and _PRODUCT_RE.fullmatch(v):pids.add(v)
        for key in ('productVersion','productVer','product_version'):
            v=obj.get(key)
            if isinstance(v,(str,int)) and not isinstance(v,bool):
                s=str(v)
                if _VERSION_RE.fullmatch(s):vers.add(s)
    return (next(iter(pids)) if len(pids)==1 else None,
            next(iter(vers)) if len(vers)==1 else None)


def _parse_json_blob(value:Any)->Any:
    """Parse bounded, model-shaped JSON strings; never expose the original text.

    Tuya product model responses may carry result.model as a serialized JSON
    string. Avoid parsing unrelated text or storing any decoded SDK payload.
    """
    if not isinstance(value,str) or len(value)>524288:
        return value
    if not value.lstrip().startswith(('{','[')):
        return value
    try:
        parsed=json.loads(value)
    except (ValueError,TypeError,RecursionError):
        return value
    return parsed if isinstance(parsed,(dict,list)) else value


def _walk(value:Any):
    """Bounded recursive model walk, including JSON strings in model/schema.

    Yields (dict, path) only. Paths are *fixed structural categories*, never
    response keys, device identifiers or arbitrary values.
    """
    stack=[(value,0,'root')]
    nodes=0
    while stack and nodes<1800:
        node,depth,context=stack.pop()
        if depth>14:
            continue
        node=_parse_json_blob(node)
        if isinstance(node,dict):
            nodes+=1
            yield node,context
            for key,child in list(node.items())[:120]:
                if isinstance(child,(dict,list)) or (key in ('result','model','schema','schemaInfo','data','services','properties','functions','dps','dpCodes','thingModel','typeSpec') and isinstance(child,str)):
                    next_context=('model' if key in ('model','thingModel') else
                                  'properties' if key in ('properties','functions','dpCodes') else
                                  'schema' if key in ('schema','schemaInfo') else context)
                    stack.append((child,depth+1,next_context))
        elif isinstance(node,list):
            nodes+=1
            for child in node[:160]:
                if isinstance(child,(dict,list,str)):
                    stack.append((child,depth+1,context))


def _numeric_id(value:Any)->int|None:
    if type(value) is int and 0<value<65536:return value
    if isinstance(value,str) and value.isascii() and value.isdigit() and len(value)<=5:
        n=int(value)
        return n if n>0 else None
    return None


def _schema_type(node:dict)->str:
    """See Tuya's typeSpec.type, including JSON-serialized typeSpec."""
    for raw in (node.get('typeSpec'),node.get('type'),node.get('dataType'),node.get('propertyType')):
        raw=_parse_json_blob(raw)
        if isinstance(raw,dict):raw=raw.get('type',raw.get('dataType'))
        if isinstance(raw,str):
            t=raw.lower().strip()
            if t in ('bool','boolean'):return 'bool'
            if t in ('enum','string','value','raw','fault','bitmap'):return t
    return 'inconnu'


def inspect_product_model(payload:Any)->dict:
    """Return anonymized DP evidence, without assuming abilityId equals dpId.

    On product thing models, abilityId is a model-level property identifier;
    it is *not automatically* a verified numeric DP for legacy IPC devices.
    All returned strings are from fixed, predefined allowlists.
    """
    flags={code:{'code_present':False,'id_standard_confirme':False,
                 'type_declare':'inconnu','ecriture_declaree':False,
                 'typeSpec_present':False,'abilityId_present':False,
                 'abilityId_correspond_au_standard':False,
                 'id_explicitement_non_standard':False,
                 'champs_identification':[], 'sources_structurales':[]}
           for code in ('ptz_control','ptz_stop')}
    nodes=0
    json_schema=False
    for node,context in _walk(payload):
        nodes+=1
        if nodes>1600:break
        code=node.get('code',node.get('dpCode',node.get('identifier')))
        if not isinstance(code,str) or code not in flags:continue
        info=flags[code]
        info['code_present']=True
        if context in ('model','schema','properties') and context not in info['sources_structurales']:
            info['sources_structurales'].append(context)
        if context=='model':json_schema=True
        expected=119 if code=='ptz_control' else 116
        for field in ('dpId','dp_id','id','abilityId'):
            if field not in node:continue
            if field not in info['champs_identification']:info['champs_identification'].append(field)
            ident=_numeric_id(node[field])
            if field=='abilityId':
                info['abilityId_present']=True
                if ident==expected:info['abilityId_correspond_au_standard']=True
            else:
                if ident==expected:info['id_standard_confirme']=True
                elif ident is not None:info['id_explicitement_non_standard']=True
        if 'typeSpec' in node:info['typeSpec_present']=True
        declared=_schema_type(node)
        if declared!='inconnu':
            if info['type_declare']=='inconnu':info['type_declare']=declared
            elif info['type_declare']!=declared:info['type_declare']='contradictoire'
        mode=node.get('accessMode',node.get('mode',node.get('permission')))
        if isinstance(mode,str) and mode.lower().strip() in ('rw','wr','write','readwrite','read_write','w'):
            info['ecriture_declaree']=True
    for code,info in flags.items():
        if info['id_explicitement_non_standard']:
            info['id_standard_confirme']=False
        info['champs_identification']=[k for k in ('dpId','dp_id','id','abilityId') if k in info['champs_identification']]
        info['sources_structurales']=[k for k in ('model','properties','schema') if k in info['sources_structurales']]
    return {'noeuds_examines':min(nodes,1600),
            'modele_json_encapsule_ou_natif':json_schema,
            'datapoints':flags,
            'mapping_116_119_confirme':all(f['id_standard_confirme'] for f in flags.values()),
            'types_attendus_confirmes':(flags['ptz_control']['type_declare']=='enum'
                                         and flags['ptz_stop']['type_declare']=='bool'),
            'ecritures_declarees':all(f['ecriture_declaree'] for f in flags.values()),
            'autorisation_mouvement':False,
            'donnees_brutes_retournees':False,'identifiants_retournes':False,'secrets_retournes':False}


def audit_product_model(coordinator:Any, *,password_confirmed:bool=False,
                        camera_confirmed:bool=False)->dict:
    out={'diagnostic':'aosu_ptz_product_model_b52','lecture_seule':True,
         'api_sdk':'thing.m.product.thing.model','version_api':'1.0',
         'appels_reseau':0,'commandes_ptz_envoyees':0,'commandes_arret_envoyees':0,
         'connexion_mqtt_nouvelle':False,'video_modifiee':False,
         'publication_ptz_autorisee':False,'identifiants_retournes':False,
         'secrets_retournes':False}
    if password_confirmed is not True or camera_confirmed is not True:
        return {**out,'etat':'confirmations_requises'}
    from .ptz_readiness import audit_ptz_readiness,refresh_ptz_inventory
    from .ptz_device_detail_b39 import select_c5l_oem
    from .tuya_uid_gateway import TuyaAuthSession,OEMGatewayError,do_uid_login_request,do_oem_read
    from .uid_token_probe import _ready_identity,_apk_preflight
    controller=getattr(coordinator,'live_controller',None)
    if controller is not None and getattr(controller,'running',False):
        return {**out,'etat':'direct_en_cours'}
    before=audit_ptz_readiness(coordinator,coordinator.client)
    if before.get('cache_oem_recent') is not True:
        refreshed=refresh_ptz_inventory(coordinator,password_confirmed=True)
        out['appels_reseau']+=int(refreshed.get('appels_reseau',0))
        if refreshed.get('etat') not in ('inventaire_oem_ptz_lu','cache_recent_reutilise'):
            return {**out,'etat':'inventaire_non_disponible',
                    'etat_actualisation':refreshed.get('etat','erreur_sans_details')}
        out['cache_oem']='actualise'
    else:out['cache_oem']='reutilise'
    selected,why=select_c5l_oem(coordinator)
    if selected is None:return {**out,'etat':why}
    _device_id,row,selection=selected
    out['selection_oem']=selection
    pid,version=find_product_identity(row)
    out['product_id_present']=pid is not None
    out['product_version_presente']=version is not None
    if pid is None or version is None:
        return {**out,'etat':'identite_produit_incomplete',
                'prochaine_etape':'rechercher_productId_et_productVersion_dans_source_sdk'}
    now=time.monotonic()
    if now<_LAST_READ.get(id(coordinator.client),0):
        return {**out,'etat':'temporisation_lecture_produit'}
    if not _LOCK.acquire(blocking=False):return {**out,'etat':'autre_lecture_en_cours'}
    try:
        now=time.monotonic()
        if now<_LAST_READ.get(id(coordinator.client),0):
            return {**out,'etat':'temporisation_lecture_produit'}
        _LAST_READ[id(coordinator.client)]=now+_RATE_LIMIT
        client=coordinator.client
        ident=_ready_identity(client)
        if ident is None:return {**out,'etat':'profil_oem_absent'}
        hints,install_id=ident
        _,parsed=_apk_preflight(client.apk_path)
        if parsed is None:return {**out,'etat':'ressources_oem_invalides'}
        identity,signer=parsed
        ttid=f'sdk_international@{identity.app_id}'
        session=getattr(client,'_tuya_oem_session',None)
        if not isinstance(session,TuyaAuthSession) or now-session.acquired_at>1200:
            session=None
        if session is None:
            password=getattr(client,'password',None)
            if not isinstance(password,str) or not password:
                return {**out,'etat':'mot_de_passe_absent'}
            login,session=do_uid_login_request(identity,signer,'sha256_material',
                uid=hints.tuya_username,country_code=hints.country_code,
                password=password,ttid=ttid,device_id=install_id,
                endpoint='https://a1.tuyaeu.com/api.json')
            out['appels_reseau']+=int(login.get('appel_reseau',0))
            if session is None:return {**out,'etat':'authentification_refusee'}
            client._tuya_oem_session=session
        out['appels_reseau']+=1
        response,status=do_oem_read(identity,signer,'sha256_material',session,
            action='thing.m.product.thing.model',
            form_data={'productId':pid,'productVersion':version},
            ttid=ttid,device_id=install_id,endpoint='https://a1.tuyaeu.com/api.json',
)
        if status.get('rejet_explicite') or not status.get('serveur_accepte'):
            return {**out,'etat':'lecture_modele_refusee',
                    'categorie_refus':status.get('categorie_refus','indeterminee')}
        from .ptz_schema_map_b67 import inspect_sdk_schema_map
        return {**out,'etat':'modele_produit_lu',
                'analyse':inspect_product_model(response),
                'schema_map_sdk_b67':inspect_sdk_schema_map(response)}
    except OEMGatewayError as exc:
        return {**out,'etat':'erreur_oem','raison':exc.code}
    except Exception:
        return {**out,'etat':'erreur_sans_details'}
    finally:_LOCK.release()
