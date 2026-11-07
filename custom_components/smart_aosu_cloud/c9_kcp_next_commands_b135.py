"""B135: offline audit of C9's *five post-auth* KCP messages.

Compare only the types and lengths against independently authored startup
commands. Never replay captured plaintext, encrypted frames, tokens, or hashes.
No video/PTZ/TCP/UDP action in this diagnostic. OEM HTTPS refresh is explicit.
"""
from __future__ import annotations
import hmac,hashlib,struct
from pathlib import Path
from typing import Any
from .c9_kcp_auth_rtc_b133 import _context,_unique_meta
from .c9_kcp_auth_identity_b132 import audit_correspondances_auth_c9_b132
from .c9_kcp_bootstrap_b128 import _client_first_six_kcp
from .c9_video_preflight_b123 import _authenticated_transcript
from .tuya_channel0_probe import _parse_answer_key,_record_decrypt,_startup_commands


def _compare_start_burst(packets:list[bytes],key:bytes)->dict:
    out={'kcp_six_trames_valides':False,'kcp_auth_premiere':False,
         'commandes_apres_auth':0,'commandes_structure_valide':0,
         'commandes_comparaison_blueprint':[],
         'sequence_standard_c5l_integralement_identique':False,
         'commandes_observees':[], 'payloads_bruts_retournes':False,
         'secrets_retournes':False,'identifiants_retournes':False,
         'captures_rejouees':False}
    if not isinstance(key,bytes) or len(key)!=16 or len(packets)!=6:return out
    # Dummy credentials are used ONLY to derive constant command templates;
    # actual tokens, digests, passwords, and camera/station IDs are never sent.
    templates=_startup_commands('placeholder','0'*16)
    identified=[]
    for i,p in enumerate(packets):
        if not isinstance(p,bytes) or len(p)<76 or len(p)>1420:return out
        conv,cmd,frg,wnd,ts,seq,una,n=struct.unpack_from('<IBBHIIII',p)
        if conv!=0 or cmd!=0x51 or frg!=0 or seq!=i or n+44!=len(p):return out
        if not hmac.compare_digest(hmac.new(key,p[:-20],hashlib.sha1).digest(),p[-20:]):return out
        try:plain=_record_decrypt(key,p[24:-20])
        except ValueError:return out
        if len(plain)<8 or struct.unpack_from('<I',plain,0)[0]!=0x12345678:return out
        kind=struct.unpack_from('<I',plain,4)[0]
        if i==0:
            if kind!=1 or len(plain)!=296:return out
            out['kcp_auth_premiere']=True
            continue
        out['commandes_apres_auth']+=1
        # Only fixed-size metadata. No payload bytes, hash, token, arbitrary
        # text, camera or account ID ever enter the service response.
        structured=len(plain)>=20 and struct.unpack_from('<I',plain,16)[0]==len(plain)-20
        if structured:out['commandes_structure_valide']+=1
        sub=struct.unpack_from('<I',plain,12)[0] if len(plain)>=16 else None
        is_template=(i<len(templates) and hmac.compare_digest(plain,templates[i]))
        out['commandes_comparaison_blueprint'].append(bool(is_template))
        out['commandes_observees'].append({
            'ordre':i,'type_hex':f'0x{kind:08x}',
            'sous_type_hex':f'0x{sub:08x}' if sub is not None else 'absent',
            'octets_clairs':len(plain),
            'longueur_payload_coherente':bool(structured),
            'modele_commande_c5l_identique':bool(is_template)})
        identified.append(bool(structured))
    out['kcp_six_trames_valides']=True
    out['sequence_standard_c5l_integralement_identique']=(
        len(out['commandes_comparaison_blueprint'])==5 and
        all(out['commandes_comparaison_blueprint']))
    return out


def audit_commandes_apres_auth_c9_b135(coordinator:Any,*,config_dir,nom_capture,
        ip_station,camera_numero,confirmation_capture_personnelle,
        confirmation_camera_candidate,autoriser_reconstitution_oem=False,
        confirmation_envoi_mot_de_passe=False)->dict:
    report={'diagnostic':'aosu_audit_commandes_kcp_b135','analyse_hors_ligne':True,
            'offres_0x20_envoyees':0,'stun_envoyes':0,'kcp_envoyes':0,
            'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
            'secrets_retournes':False,'donnees_privees_retournees':False,
            'identifiants_retournes':False}
    if confirmation_capture_personnelle is not True or confirmation_camera_candidate is not True:
        return {**report,'etat':'confirmations_requises'}
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_correspondances_auth_c9_b132(coordinator,config_dir=config_dir,
        nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
        confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for k in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if k in pre:report[k]=pre[k]
    if pre.get('etat')!='correspondances_identifiants_anonymisees':
        return {**report,'etat':pre.get('etat','identites_non_verifiees')}
    try:
        old_auth,station_id,camera_id,devices=_context(coordinator,config_dir,nom_capture,ip_station)
        checks,meta=_unique_meta(old_auth,station_id,camera_id,devices)
        if meta is None or not checks['auth_schema_reconstructible']:
            return {**report,'etat':'schema_auth_non_valide'}
        station_key=devices[station_id]['localKey'].encode('utf-8')
        path=(Path(config_dir)/'smart_aosu_traces'/nom_capture).resolve()
        offer,_,_=_authenticated_transcript(path,ip_station,station_key)
        if not isinstance(offer,dict):return {**report,'etat':'offre_capture_absente'}
        key=_parse_answer_key(offer.get('msg',{}).get('sdp'))
        if key is None:return {**report,'etat':'cle_media_capture_absente'}
        packets=_client_first_six_kcp(path,ip_station)
        result=_compare_start_burst(packets,key)
        return {**report,**result,'etat':('cinq_commandes_post_auth_analysees' if
            result['kcp_six_trames_valides'] and result['commandes_apres_auth']==5
            else 'commandes_post_auth_non_exploitables')}
    except (OSError,ValueError,TypeError,KeyError,IndexError,UnicodeError,struct.error):
        return {**report,'etat':'analyse_commandes_non_exploitable'}
    except Exception:
        return {**report,'etat':'erreur_interne_masquee'}
