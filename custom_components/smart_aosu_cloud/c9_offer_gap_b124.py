"""B124 - in-memory gap audit for C9 LAN offer; never transmits camera commands.

The B122 offer drops token/tcp_token/udp_token/auth/password fields, mutates
ICE/SDP and trace_id, and may retain an old topic. This audit determines
which omissions occurred on the authenticated personal C9 capture. It never
returns captured values, secrets, SDP, topic, IDs, or network endpoints.
"""
from __future__ import annotations
import re
import time
from pathlib import Path
from .c9_video_preflight_b123 import audit_preparation_video_c9_b123, _authenticated_transcript
from .c9_lan_signal_b122 import _fresh_offer
from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name

_SENSITIVE=('auth','password','token','tcp_token','udp_token')
_SAFE_EXTRA=('moto_id','is_pre','p2p_skill','security_level','sub_dev_id')

def _field_inventory(tree:object, depth:int=0)->dict[str,int]:
    if depth>10:raise ValueError('structure_trop_profonde')
    out={key:0 for key in _SENSITIVE}
    if isinstance(tree,dict):
        for k,v in list(tree.items())[:100]:
            if k in out:out[k]+=1
            if isinstance(v,(dict,list)):
                child=_field_inventory(v,depth+1)
                for key,count in child.items():out[key]+=count
    elif isinstance(tree,list):
        for v in tree[:50]:
            if isinstance(v,(dict,list)):
                child=_field_inventory(v,depth+1)
                for key,count in child.items():out[key]+=count
    return out

def _trace_shape(trace:object, recipient:object)->dict:
    if not isinstance(trace,str) or not trace or len(trace)>2048:
        return {'contient_id_station':False,'timestamp_millisecondes_final':False,'uuid_initial':False}
    first=trace.split('_',1)[0]
    return {
        'contient_id_station':isinstance(recipient,str) and bool(recipient) and recipient in trace,
        'timestamp_millisecondes_final':bool(re.search(r'_[0-9]{13}\Z',trace)),
        'uuid_initial':bool(re.fullmatch(r'[0-9a-fA-F]{32}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',first))
    }

def _topic_shape(msg:dict,*, uid:str,station_id:str,camera_id:str,old_sid:object)->dict:
    from .h1l_pcap_offline_b111 import _field_values_b117
    vals=_field_values_b117(msg,'topic')
    if len(vals)!=1 or not isinstance(vals[0][1],str):
        return {'unique':False,'contient_id_session':False,'contient_id_station':False,'contient_uid':False,'contient_id_camera':False}
    topic=vals[0][1]
    def contains(item:object)->bool:return bool(isinstance(item,str) and item and item in topic)
    return {'unique':True,'contient_id_session':contains(old_sid),'contient_id_station':contains(station_id),
        'contient_uid':contains(uid),'contient_id_camera':contains(camera_id)}

def inspect_offer_gap_b124(offer:dict,*, uid:str,station_id:str,camera_id:str)->dict:
    """No raw values returned; all secret-carrying objects stay in memory."""
    head=offer.get('header');msg=offer.get('msg')
    if not isinstance(head,dict) or not isinstance(msg,dict):raise ValueError('offre_invalide')
    target=head.get('to')
    if target!=station_id:raise ValueError('cible_offre_non_station')
    session=head.get('sessionid')
    if not isinstance(session,str) or len(session)>1024:raise ValueError('session_capture_invalide')
    # A B122 dry run (fresh random material, no network or persistence).
    fake=f'{station_id}{int(time.time())}12345678'
    b122, _ = _fresh_offer(offer, allowed_ids={station_id,camera_id},session_id=fake,local_port=51000)
    b122['header']['from']=uid
    original_fields=_field_inventory(offer)
    new_fields=_field_inventory(b122)
    extras=sorted(set(head)-{'type','path','to','from','sessionid','sessionId','trace_id'})
    old_shape=_trace_shape(head.get('trace_id'),target)
    new_shape=_trace_shape(b122['header'].get('trace_id'),target)
    return {
      'champs_supplementaires_en_tete_reconnus':[name for name in _SAFE_EXTRA if name in extras],
      'champs_supplementaires_non_classes':sum(1 for n in extras if n not in _SAFE_EXTRA),
      'champs_supplementaires_preserves':all(name in b122['header'] for name in extras),
      'champs_sensibles_capture_presents':{k:original_fields[k]>0 for k in _SENSITIVE},
      'champs_sensibles_supprimes_en_b122':{k:original_fields[k]>0 and new_fields[k]==0 for k in _SENSITIVE},
      'trace_capture':old_shape,
      'trace_b122':new_shape,
      'trace_format_modifie_b122':old_shape!=new_shape,
      'session_capture_prefixe_station':session.startswith(station_id),
      'session_b122_prefixe_station':b122['header']['sessionid'].startswith(station_id),
      'topic_capture':_topic_shape(msg,uid=uid,station_id=station_id,camera_id=camera_id,old_sid=session),
      'nouvelle_offre_preparable_hors_ligne':True,
      'secrets_retournes':False,'ids_retournes':False,
    }

def audit_ecarts_offre_video_c9_b124(coordinator,*, config_dir:str|Path,
    nom_capture:object,ip_station:object,camera_numero:object,
    confirmation_capture_personnelle:bool,confirmation_camera_candidate:bool,
    autoriser_reconstitution_oem:bool=False,confirmation_envoi_mot_de_passe:bool=False)->dict:
    prior=audit_preparation_video_c9_b123(coordinator,config_dir=config_dir,
      nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
      confirmation_capture_personnelle=confirmation_capture_personnelle,
      confirmation_camera_candidate=confirmation_camera_candidate,
      autoriser_reconstitution_oem=autoriser_reconstitution_oem,
      confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    report={'diagnostic':'aosu_audit_ecarts_offre_video_c9_b124','analyse_hors_ligne':True,
      'offres_0x20_envoyees':0,'offres_mqtt_envoyees':0,'stun_envoyes':0,'kcp_demarre':False,
      'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
      'donnees_privees_retournees':False,'identifiants_retournes':False,'secrets_retournes':False,
      'cache_oem_avant':prior.get('cache_oem_avant'),
      'appels_http_oem':prior.get('appels_http_oem',0),
      'mot_de_passe_envoye':prior.get('mot_de_passe_envoye',False)}
    if prior.get('etat')!='comparaison_preparation_capture_terminee':
        return {**report,'etat':prior.get('etat','preflight_indisponible')}
    try:
        from .h1l_local_probe_b103 import _validate_target
        ip=_validate_target(ip_station)
        data=getattr(coordinator,'data',None)
        client=getattr(coordinator,'client',None)
        camera_id,_=_candidate(data,client,2)
        stations=[v for v in data.values() if isinstance(v,dict) and v.get('model')=='H1L' and v.get('is_camera') is False]
        if len(stations)!=1:raise ValueError('station_ambigue')
        matches=[(did,dev) for did,dev in client._tuya_oem_inventory_cache['devices'].items()
                 if isinstance(dev,dict) and _match_name(dev,stations[0].get('name'))]
        if len(matches)!=1:raise ValueError('station_ambigue')
        station_id,dev=matches[0]
        key=dev.get('localKey')
        uid=client._tuya_oem_session.uid
        if not isinstance(camera_id,str) or not isinstance(uid,str) or not isinstance(key,str) or len(key.encode('utf-8'))!=16:
            raise ValueError('identite_absente')
        root=Path(config_dir)/'smart_aosu_traces'
        offer,candidates,metrics=_authenticated_transcript(root/nom_capture,ip,key.encode('utf-8'))
        if offer is None:return {**report,'etat':'offre_capture_introuvable'}
        report.update(inspect_offer_gap_b124(offer,uid=uid,station_id=station_id,camera_id=camera_id))
        report['etat']='ecarts_offre_identifies'
    except (ValueError,TypeError,KeyError,AttributeError,IndexError,OSError):
        report['etat']='analyse_offre_non_exploitable'
    return report
