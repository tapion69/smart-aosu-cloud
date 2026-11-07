"""B136: offline, privacy-preserving field classification for C9 post-auth KCP.

Never transmits LAN packets or returns decrypted bytes, IDs, hashes or keys.
"""
from __future__ import annotations
import hmac, hashlib, struct
from pathlib import Path
from typing import Any
from .c9_kcp_next_commands_b135 import audit_commandes_apres_auth_c9_b135
from .c9_kcp_auth_rtc_b133 import _context, _unique_meta
from .c9_kcp_bootstrap_b128 import _client_first_six_kcp
from .c9_video_preflight_b123 import _authenticated_transcript
from .tuya_channel0_probe import _record_decrypt, _parse_answer_key

_ALT='c9_camera_1_reference.pcap'
_KINDS=(0,2,0x10004,0x10003,0x10005)


def _decrypt_six(packets:list[bytes], key:bytes)->list[bytes]:
    if not isinstance(key,bytes) or len(key)!=16 or len(packets)!=6:
        raise ValueError('sequence_invalide')
    plains=[]
    for i,p in enumerate(packets):
        if len(p)<76 or len(p)>1420:raise ValueError('kcp_taille')
        conv,cmd,frag,wnd,ts,seq,una,n=struct.unpack_from('<IBBHIIII',p)
        if (conv,cmd,frag,seq)!=(0,0x51,0,i) or n+44!=len(p):
            raise ValueError('kcp_entete')
        if not hmac.compare_digest(hmac.new(key,p[:-20],hashlib.sha1).digest(),p[-20:]):
            raise ValueError('kcp_hmac')
        plain=_record_decrypt(key,p[24:-20])
        if len(plain)<8 or struct.unpack_from('<I',plain)[0]!=0x12345678:
            raise ValueError('kcp_magic')
        if i==0:
            if len(plain)!=296 or struct.unpack_from('<I',plain,4)[0]!=1:
                raise ValueError('auth_c9_invalide')
        elif (len(plain)<20 or len(plain)>256 or
              struct.unpack_from('<I',plain,4)[0] not in _KINDS or
              struct.unpack_from('<I',plain,16)[0]!=len(plain)-20):
            raise ValueError('commande_c9_invalide')
        plains.append(plain)
    return plains


def _field_summary(plain:bytes, references:list[tuple[str,bytes]])->dict:
    if len(plain)<20 or len(plain)>256:raise ValueError('taille')
    kind=struct.unpack_from('<I',plain,4)[0]
    sub=struct.unpack_from('<I',plain,12)[0]
    n=struct.unpack_from('<I',plain,16)[0]
    payload=plain[20:]
    if len(payload)!=n:raise ValueError('longueur')
    recognized=[]
    for i in range(0,max(0,len(payload)-31),4):
        segment=payload[i:i+32]
        for role,ref in references:
            if hmac.compare_digest(segment,ref.ljust(32,b'\x00')):
                recognized.append({'offset':i,'role':role})
    words=[struct.unpack_from('<I',payload,i)[0] for i in range(0,len(payload)-3,4)]
    return {'type_hex':f'0x{kind:08x}', 'sous_type_hex':f'0x{sub:08x}',
      'octets_payload':n, 'octets_non_nuls':sum(b!=0 for b in payload),
      'remplissage_zero_final':len(payload)-len(payload.rstrip(b'\x00')),
      'mots_u32_zero':sum(x==0 for x in words),
      'mots_u32_petits':sum(0<x<=65535 for x in words),
      'ascii_imprimable_majoritaire':sum(32<=x<=126 for x in payload)>n//2,
      'references_oem_reconnues':recognized[:6],
      'references_supplementaires':max(0,len(recognized)-6),
      'payload_retourne':False}


def _compare_second(first:list[bytes],second:list[bytes])->list[dict]:
    out=[]
    for a,b in zip(first[1:],second[1:]):
        x,y=a[20:],b[20:]
        out.append({'type_et_sous_type_identiques':a[4:16]==b[4:16],
           'taille_identique':len(x)==len(y),
           'payload_identique':len(x)==len(y) and hmac.compare_digest(x,y),
           'octets_differents':sum(i!=j for i,j in zip(x,y))+abs(len(x)-len(y))})
    return out


def audit_champs_commandes_c9_b136(coordinator:Any,*,config_dir,nom_capture,
        ip_station,camera_numero,confirmation_capture_personnelle,
        confirmation_camera_candidate,autoriser_reconstitution_oem=False,
        confirmation_envoi_mot_de_passe=False)->dict:
    report={'diagnostic':'aosu_audit_champs_commandes_kcp_b136',
       'analyse_hors_ligne':True,'offres_0x20_envoyees':0,
       'stun_envoyes':0,'kcp_envoyes':0,'commandes_video_envoyees':0,
       'commandes_ptz_envoyees':0,'secrets_retournes':False,
       'identifiants_retournes':False,'payloads_bruts_retournes':False,
       'autre_c9_analysee':False}
    if confirmation_capture_personnelle is not True or confirmation_camera_candidate is not True:
        return {**report,'etat':'confirmations_requises'}
    if type(camera_numero) is not int or camera_numero!=2 or nom_capture!='c9_camera_2_reference.pcap':
        return {**report,'etat':'capture_c9_numero_2_requise'}
    pre=audit_commandes_apres_auth_c9_b135(coordinator,config_dir=config_dir,
       nom_capture=nom_capture,ip_station=ip_station,camera_numero=2,
       confirmation_capture_personnelle=True,confirmation_camera_candidate=True,
       autoriser_reconstitution_oem=autoriser_reconstitution_oem,
       confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for field in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if field in pre:report[field]=pre[field]
    if pre.get('etat')!='cinq_commandes_post_auth_analysees':
        return {**report,'etat':pre.get('etat','audit_b135_non_valide')}
    try:
        auth,sid,cid,devices=_context(coordinator,config_dir,nom_capture,ip_station)
        checked,meta=_unique_meta(auth,sid,cid,devices)
        if meta is None or not checked.get('auth_schema_reconstructible'):
            return {**report,'etat':'identites_non_validees'}
        root=(Path(config_dir)/'smart_aosu_traces').resolve()
        path=(root/nom_capture).resolve()
        if path.parent!=root or not path.is_file() or path.stat().st_size>32*1024*1024:
            return {**report,'etat':'capture_absente'}
        station_key=devices[sid]['localKey'].encode('utf-8')
        offer,_,_=_authenticated_transcript(path,ip_station,station_key)
        key=_parse_answer_key(offer.get('msg',{}).get('sdp')) if isinstance(offer,dict) else None
        if key is None:return {**report,'etat':'cle_media_capture_invalide'}
        plain=_decrypt_six(_client_first_six_kcp(path,ip_station),key)
        refs=[]
        for role,val in (('station_h1l',sid),('camera_c9',cid),('reference_oem_camera',meta)):
            if not isinstance(val,str):continue
            raw=val.encode('utf-8')
            if 5<=len(raw)<=32 and all(32<=x<=126 for x in raw):refs.append((role,raw))
        fields=[_field_summary(p,refs) for p in plain[1:]]
        report.update({'commandes_analysees':len(fields),'champs_commandes':fields,
            'references_oem_identifiees':sum(len(f['references_oem_reconnues']) for f in fields)})
        alt=(root/_ALT).resolve()
        if alt.parent==root and alt.is_file() and alt.stat().st_size<=32*1024*1024:
            try:
                other_offer,_,_=_authenticated_transcript(alt,ip_station,station_key)
                other_key=(_parse_answer_key(other_offer.get('msg',{}).get('sdp'))
                           if isinstance(other_offer,dict) else None)
                if other_key is not None:
                    second=_decrypt_six(_client_first_six_kcp(alt,ip_station),other_key)
                    report['comparaison_c9_par_commande']=_compare_second(plain,second)
                    report['autre_c9_analysee']=True
                else:report['autre_c9_etat']='capture_non_authentifiable'
            except (ValueError,TypeError,OSError,KeyError,IndexError,struct.error):
                report['autre_c9_etat']='capture_non_authentifiable'
        report['etat']='cinq_payloads_c9_profils_anonymises'
        return report
    except (OSError,ValueError,TypeError,KeyError,IndexError,UnicodeError,struct.error):
        return {**report,'etat':'analyse_champs_non_exploitable'}
    except Exception:
        return {**report,'etat':'erreur_interne_masquee'}
