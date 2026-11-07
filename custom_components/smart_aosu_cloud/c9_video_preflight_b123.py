"""B123: passive authenticated audit of what differs before the first C9 SDP.

Strictly local PCAP reading. Only optional OEM inventory HTTPS login can occur,
never a Tuya TCP 0x20 offer, UDP, STUN, MQTT publish, PTZ or video request.
Private IDs and SDP contents are examined in memory, never returned/logged.
"""
from __future__ import annotations
import hashlib
import hmac
import json
from pathlib import Path
import re
import time
from .c9_lan_signal_b122 import _find_offer_from_capture, _json_payload, _FreshSDP, _fresh_offer, _NAME
from .c9_rtc_candidate_b101 import _candidate
from .c9_h1l_identity_structure_b99 import _match_name
from .h1l_local_status_b108 import _cache_state
from .h1l_pcap_offline_b111 import _read_pcap, _frames_from_segments, _verify_and_decode, _field_values_b117
from .h1l_local_status_b107 import _session_key
from .h1l_local_probe_b103 import _validate_target
from .tuya_rtc_inventory import run_tuya_oem_inventory


def _kind(value:object, uid:str, camera_id:str, station_id:str)->str:
    if not isinstance(value,str) or not value:return 'absent'
    if value==uid:return 'uid_compte'
    if value==camera_id:return 'id_camera'
    if value==station_id:return 'id_station'
    return 'autre_valeur'


def _candidate_type(text:str)->str:
    if not isinstance(text,str):return 'non_standard'
    s=text.lower().replace('a=candidate:','candidate:').split()
    if len(s)<8 or 'typ' not in s:return 'non_standard'
    try:t=s[s.index('typ')+1]
    except IndexError:return 'non_standard'
    return t if t in ('host','srflx','relay','prflx') else 'non_standard'


def _safe_offer_inspection(offer:dict, candidates:list[dict], *, uid:str, camera_id:str, station_id:str)->dict:
    header=offer.get('header',{})
    msg=offer.get('msg',{})
    if not isinstance(header,dict) or not isinstance(msg,dict):raise ValueError('offre_invalide')
    sdp_fields=_field_values_b117(msg,'sdp')
    topics=_field_values_b117(msg,'topic')
    session_fields=[]
    for field in ('sessionId','sessionid','session_id'):
        session_fields+=_field_values_b117(msg,field)
    header_known={'type','path','to','from','sessionid','sessionId','trace_id'}
    candidates_types=[];candidates_from=[];candidates_to=[]
    for obj in candidates:
        h=obj.get('header',{})
        if not isinstance(h,dict):continue
        vals=_field_values_b117(obj.get('msg',{}),'candidate')
        candidates_types.append(_candidate_type(vals[0][1]) if len(vals)==1 else 'non_standard')
        candidates_from.append(h.get('from')==header.get('from'))
        candidates_to.append(h.get('to')==header.get('to'))
    original_topic=topics[0][1] if len(topics)==1 and isinstance(topics[0][1],str) else None
    old_sid=header.get('sessionid')
    # B122 reconstructs the topic only by replacement if captured header.sessionid occurs in it.
    # An unchanged topic may be a static routing address OR an expired session route:
    # do not claim a cause solely from this flag.
    topic_sid_literal=(isinstance(old_sid,str) and bool(old_sid)
                       and isinstance(original_topic,str) and old_sid in original_topic)
    return {
      'offre_to_role':_kind(header.get('to'),uid,camera_id,station_id),
      'offre_from_role_capture':_kind(header.get('from'),uid,camera_id,station_id),
      'b122_force_from_uid':True,
      'b122_from_identique_capture':header.get('from')==uid,
      'champs_entete_offre_inconnus_conserves_b122':len(set(header)-header_known),
      'sdp_unique_capture':len(sdp_fields)==1,
      'sdp_application':any(isinstance(s,str) and re.search(r'(?m)^m=application ',s)
                             for _,s in sdp_fields),
      'sdp_ufrag_present':any(isinstance(s,str) and 'a=ice-ufrag:' in s for _,s in sdp_fields),
      'sdp_pwd_present':any(isinstance(s,str) and 'a=ice-pwd:' in s for _,s in sdp_fields),
      'sdp_aes_key_present':any(isinstance(s,str) and 'a=aes-key:' in s for _,s in sdp_fields),
      'topic_unique_capture':len(topics)==1,
      'topic_reference_ancienne_session':bool(topic_sid_literal),
      'b122_topic_reconstruit_avec_session_neuve':bool(topic_sid_literal),
      'b122_topic_inchange_par_rapport_capture':bool(original_topic is not None and not topic_sid_literal),
      'sessionid_imbrique_present':len(session_fields)>0,
      'candidats_capture_par_type':{t:candidates_types.count(t) for t in ('host','srflx','relay','prflx','non_standard')},
      'candidats_from_identique_offre':sum(candidates_from),
      'candidats_to_identique_offre':sum(candidates_to),
      'candidats_capture_total':len(candidates),
    }


def _authenticated_transcript(path:Path,ip:str,key:bytes)->tuple[dict|None,list[dict],dict]:
    analysis=_read_pcap(path,ip)
    for flow in analysis['flows'].values():
        outgoing=_frames_from_segments(flow['client']);incoming=_frames_from_segments(flow['station'])
        init=next((f for f in outgoing if f[0]==3),None)
        chall=next((f for f in incoming if f[0]==4),None)
        finish=next((f for f in outgoing if f[0]==5),None)
        if not (init and chall and finish):continue
        nonce=_verify_and_decode(init,key,False)
        response=_verify_and_decode(chall,key,True)
        fin=_verify_and_decode(finish,key,False)
        if not(nonce and response and fin and len(nonce)==16 and len(response)==48 and len(fin)==32):continue
        if not (hmac.compare_digest(response[16:],hmac.new(key,nonce,hashlib.sha256).digest())
                and hmac.compare_digest(fin,hmac.new(key,response[:16],hashlib.sha256).digest())):continue
        session_key=_session_key(key,nonce,response[:16]);offer=None;candidates=[];ack=0;answers=0
        for frame in outgoing:
            if frame[0]!=0x20:continue
            plain=_verify_and_decode(frame,session_key,False)
            if plain is None:continue
            obj=_json_payload(plain)
            if obj is None:continue
            h=obj.get('header')
            if not isinstance(h,dict):continue
            if h.get('type')=='offer' and offer is None:offer=obj
            if h.get('type')=='candidate':candidates.append(obj)
        for frame in incoming:
            if frame[0]!=0x20:continue
            plain=_verify_and_decode(frame,session_key,True)
            if plain is None:continue
            if not plain:ack+=1
            elif _json_payload(plain) is not None:answers+=1
        if offer:
            return offer,candidates,{'acquittements_vides_capture':ack,
                     'messages_json_station_capture':answers}
    return None,[],{}


def audit_preparation_video_c9_b123(coordinator, *, config_dir:str|Path,
    nom_capture:object,ip_station:object,camera_numero:object,
    confirmation_capture_personnelle:bool,confirmation_camera_candidate:bool,
    autoriser_reconstitution_oem:bool=False,confirmation_envoi_mot_de_passe:bool=False)->dict:
    report={'diagnostic':'aosu_audit_preparation_video_b123','analyse_hors_ligne':True,
      'offres_0x20_envoyees':0,'offres_mqtt_envoyees':0,'stun_envoyes':0,'kcp_demarre':False,
      'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
      'donnees_privees_retournees':False,'identifiants_retournes':False,'secrets_retournes':False}
    if confirmation_capture_personnelle is not True or confirmation_camera_candidate is not True:
        return {**report,'etat':'consentement_capture_et_camera_requis'}
    if type(camera_numero) is not int or camera_numero!=2:
        return {**report,'etat':'camera_numero_2_requise'}
    if nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_2_attendue'}
    try:ip=_validate_target(ip_station)
    except ValueError:return {**report,'etat':'ip_station_invalide'}
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    path=(root/nom_capture).resolve()
    if path.parent!=root or not path.is_file():return {**report,'etat':'capture_absente'}
    client=getattr(coordinator,'client',None)
    report['cache_oem_avant']=_cache_state(client,time.monotonic())
    if report['cache_oem_avant']!='cache_utilisable':
        if autoriser_reconstitution_oem is not True or confirmation_envoi_mot_de_passe is not True:
            return {**report,'etat':'cache_oem_ou_autorisation_absent'}
        try:inv=run_tuya_oem_inventory(client,confirmation_envoi_mot_de_passe=True,
             tester_rtc=False,tester_mqtt=False,tester_offre_mqtt=False,
             tester_relais_tcp=False,tester_kcp=False,tester_media=False)
        except Exception:return {**report,'etat':'erreur_reconstitution_oem_non_detaillee'}
        report['appels_http_oem']=inv.get('appel_reseau',0)
        report['mot_de_passe_envoye']=inv.get('mot_de_passe_envoye') is True
        if inv.get('etat')!='inventaire_termine' or _cache_state(client,time.monotonic())!='cache_utilisable':
            return {**report,'etat':'inventaire_oem_non_disponible'}
    data=getattr(coordinator,'data',None)
    if not isinstance(data,dict):return {**report,'etat':'inventaire_aosu_absent'}
    camera_id,_=_candidate(data,client,2)
    if camera_id is None:return {**report,'etat':'candidat_camera_ambigu'}
    stations=[v for v in data.values() if isinstance(v,dict) and v.get('model')=='H1L' and v.get('is_camera') is False]
    if len(stations)!=1:return {**report,'etat':'station_ambigue'}
    matches=[(did,dev) for did,dev in client._tuya_oem_inventory_cache['devices'].items()
             if isinstance(dev,dict) and _match_name(dev,stations[0].get('name'))]
    if len(matches)!=1:return {**report,'etat':'station_candidate_ambigue'}
    station_id,dev=matches[0]
    key=dev.get('localKey')
    if not isinstance(key,str) or len(key.encode('utf-8'))!=16:
        return {**report,'etat':'cle_station_invalide'}
    uid=getattr(getattr(client,'_tuya_oem_session',None),'uid',None)
    if not isinstance(uid,str) or not uid:return {**report,'etat':'uid_compte_absent'}
    try:
        offer,candidates,metrics=_authenticated_transcript(path,ip,key.encode('utf-8'))
        if offer is None:return {**report,'etat':'offre_capture_introuvable'}
        report.update(_safe_offer_inspection(offer,candidates,
                         uid=uid,camera_id=camera_id,station_id=station_id))
        report.update(metrics)
        report['etat']='comparaison_preparation_capture_terminee'
    except (ValueError,TypeError,KeyError,IndexError,OSError):
        report['etat']='analyse_capture_non_exploitable'
    return report
