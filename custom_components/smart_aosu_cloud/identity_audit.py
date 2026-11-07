"""Manual, read-only C5L identity/capability probe.

Based on APK AOSU 5.10.12:
- DeviceWebService POST /v1/dev/getInfoBySn, Field:sn
- DeviceWebService POST /v1/dev/capability, Body: DeviceCapabilityReq {snList:[...]}
- UUIDInfoWebDataItem.coopUUID is assigned into GzDeviceInfo.cpDeviceId.

Never export identifiers or a server-provided key/value/name in service outputs.
"""
from __future__ import annotations
from .provider_audit import summarize_detail_provider
import time
import requests

TARGET_INFO='https://api-eu.aosulife.com/v1/dev/getInfoBySn'
TARGET_CAPABILITY='https://api-eu.aosulife.com/v1/dev/capability'

# Only these *literal* keys are inspected; do not return arbitrary keys from JSON.
REFERENCE_KEYS=('cpDeviceId','coopUUID','cpUuid','cpDeviceInfo','deviceUuid')
CAPABILITY_KEYS=('ptz','ptz_control','ptz_stop','PtzControlDirectionSupport','ptzControlDirection')


def _valid_ref(v):
    return isinstance(v,str) and bool(v.strip()) and len(v)<=256


def summarize_info(payload):
    """Structure and private-reference presence, no identifier hashes or values."""
    out={'etat':'accepte','type_data':'autre','references':{k:False for k in REFERENCE_KEYS},
         'emplacement':'non_observe','nombre_objets_examines':0}
    if not isinstance(payload,dict) or payload.get('errno')!=0:
        return {**out,'etat':'refuse_ou_format_non_reconnu'}
    root=payload.get('data')
    out['type_data']='objet' if isinstance(root,dict) else 'liste' if isinstance(root,list) else 'autre'
    # Short, bounded walk, no dynamic keys reported, values never retained.
    todo=[(root,0)]
    while todo and out['nombre_objets_examines'] < 80:
        item,depth=todo.pop()
        if isinstance(item,dict):
            out['nombre_objets_examines']+=1
            for k in REFERENCE_KEYS:
                v=item.get(k)
                if k=='cpDeviceInfo':
                    found=isinstance(v,dict) and bool(v)
                else:
                    found=_valid_ref(v)
                if found:
                    out['references'][k]=True
                    if out['emplacement']=='non_observe':
                        out['emplacement']='data' if depth==0 else 'structure_imbriquee'
            if depth<5:
                for child in list(item.values())[:80]:
                    if isinstance(child,(dict,list)):
                        todo.append((child,depth+1))
        elif isinstance(item,list) and depth<5:
            for child in item[:15]:
                if isinstance(child,(dict,list)):
                    todo.append((child,depth+1))
    out['reference_potentielle_presente']=bool(out['references']['coopUUID'] or out['references']['cpDeviceId'])
    out['audit_provider_p2p']=summarize_detail_provider(payload)
    out['note']='Presence de la reference ne prouve ni droit Tuya ni session SDK active.'
    return out


def summarize_capability(payload):
    result={'etat':'accepte','type_data':'autre','familles_ptz_reconnues':[],
            'capacite_ptz_confirmee':False}
    if not isinstance(payload,dict) or payload.get('errno')!=0:
        return {**result,'etat':'refuse_ou_format_non_reconnu'}
    root=payload.get('data')
    result['type_data']='objet' if isinstance(root,dict) else 'liste' if isinstance(root,list) else 'autre'
    todo=[(root,0)]; found=set();count=0
    while todo and count<80:
        item, depth=todo.pop()
        if isinstance(item,dict):
            count+=1
            for k in CAPABILITY_KEYS:
                if k in item: found.add(k)
            key=item.get('key')
            if isinstance(key,str) and key in CAPABILITY_KEYS:
                found.add(key)
            if depth<5:
                todo.extend((v,depth+1) for v in list(item.values())[:80] if isinstance(v,(dict,list)))
        elif isinstance(item,list) and depth<5:
            todo.extend((v,depth+1) for v in item[:15] if isinstance(v,(dict,list)))
    result['familles_ptz_reconnues']=sorted(found)
    # A name present in the capability response is not proof it is enabled.
    result['note']='Les cles PTZ reconnues sont des indices, pas une verification des commandes.'
    return result


def run_identity_capability_probe(client):
    """Two manual read-only POSTs, at most once per 60 min per live client."""
    with client._dp_lock:
        now=time.monotonic()
        last=getattr(client,'_last_identity_probe',0.0)
        if last and now-last<3600:
            return {'resultat':'audit_liaison_tuya_0_8_8','etat':'limite_une_fois_par_heure',
                    'appels_http':0,'commandes_ptz':0,'video':False}
        sn=getattr(client,'_c5l_sn',None)
        if not isinstance(sn,str) or not sn or len(sn)>256:
            return {'resultat':'audit_liaison_tuya_0_8_8','etat':'c5l_absente_du_cache',
                    'appels_http':0,'commandes_ptz':0,'video':False}
        if not client._sid or not client._uid or not client._login_headers:
            return {'resultat':'audit_liaison_tuya_0_8_8','etat':'session_indisponible',
                    'appels_http':0,'commandes_ptz':0,'video':False}
        client._last_identity_probe=now
        from . import protocol_060 as proto
        params, headers=proto.build_device_list_request(
            client._suffix,client._login_headers,client._sid,client._uid)
        headers=dict(headers)
        result={'resultat':'audit_liaison_tuya_0_8_8',
                'source':'APK DeviceWebService, UUIDInfoWebDataItem',
                'etat':'termine','appels_http':0,'commandes_ptz':0,
                'video':False,'secrets_retournes':False,
                'reference_cache_getList':getattr(client,'_c5l_coop_present',False)}
        probes=[('fiche_detaillee',TARGET_INFO,{'sn':sn},False),
                ('capacites',TARGET_CAPABILITY,{'snList':[sn]},True)]
        for name,url,data,json_body in probes:
            result['appels_http']+=1
            try:
                hdr=dict(headers)
                if json_body:
                    hdr['Content-Type']='application/json'
                    response=client.session.post(url,params=params,json=data,headers=hdr,
                                                 timeout=(8,20),verify=True,allow_redirects=False)
                else:
                    hdr['Content-Type']='application/x-www-form-urlencoded'
                    response=client.session.post(url,params=params,data=data,headers=hdr,
                                                 timeout=(8,20),verify=True,allow_redirects=False)
                if response.status_code!=200:
                    result[name]={'etat':'http_non_200','http_statut':int(response.status_code)}
                    continue
                if len(response.content)>262144:
                    result[name]={'etat':'reponse_trop_grande'}
                    continue
                payload=response.json()
                result[name]=summarize_capability(payload) if json_body else summarize_info(payload)
            except (requests.RequestException, ValueError,TypeError):
                result[name]={'etat':'erreur_lecture'}
        return result
