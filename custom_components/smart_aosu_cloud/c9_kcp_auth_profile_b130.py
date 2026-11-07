"""B130: conservative schema validation for C9/H1L channel-zero authorization.

An authenticated PCAP is opened in RAM only. A fresh auth body may
only be constructed if its verified format is reproducible from the *current*
OEM inventory; no captured credentials or KCP bytes are reused. On an unknown
profile this module declines to send anything.
"""
from __future__ import annotations
import hashlib
import hmac
from pathlib import Path
import struct
from typing import Any

from .c9_kcp_bootstrap_b128 import _client_first_six_kcp,_audit_startup_packets
from .c9_video_preflight_b123 import _authenticated_transcript
from .h1l_local_probe_b103 import _validate_target
from .tuya_channel0_probe import _record_decrypt,_parse_answer_key,_CONTROL_MAGIC


def _inspect_auth_record(packet:bytes,media_key:bytes,devices:dict,station_id:str)->tuple[dict,bytes|None]:
    """Return restricted metrics and an entirely new plaintext auth, or None.

    Never returns a recovered value from the capture. Candidates come solely
    from the current OEM device inventory; all matches are verified in constant
    time against the capture's existing 32-byte MD5 digest.
    """
    summary={'auth_enregistrements_verifies':0,'auth_longueur_clair':0,
             'auth_format_admin':False,'auth_champ_md5_hex':False,
             'auth_extension_zero':False,'auth_identite_oem_correspondante':False,
             'auth_schema_reconstructible':False,
             'auth_blocs_supplementaires_non_vides':0,
             'auth_ancien_secret_reutilise':False,'auth_capture_rejouee':False}
    if not isinstance(packet,bytes) or not isinstance(media_key,bytes) or len(media_key)!=16 or not isinstance(devices,dict):
        return summary,None
    if len(packet)!=364 or not hmac.compare_digest(hmac.new(media_key,packet[:-20],hashlib.sha1).digest(),packet[-20:]):
        return summary,None
    try:
        plain=_record_decrypt(media_key,packet[24:-20])
    except ValueError:return summary,None
    summary['auth_enregistrements_verifies']=1
    summary['auth_longueur_clair']=len(plain)
    if len(plain)!=296 or plain[:8]!=struct.pack('<II',_CONTROL_MAGIC,1):
        return summary,None
    body=plain[8:]
    summary['auth_format_admin']=body[:5]==b'admin' and body[5:32]==bytes(27)
    digest=body[32:64]
    summary['auth_champ_md5_hex']=(len(digest)==32 and all(c in b'0123456789abcdefABCDEF' for c in digest))
    summary['auth_extension_zero']=not any(body[64:])
    summary['auth_blocs_supplementaires_non_vides']=sum(any(body[i:i+32]) for i in range(64,len(body),32))
    if not (summary['auth_format_admin'] and summary['auth_champ_md5_hex'] and summary['auth_extension_zero']):
        return summary,None
    candidates=[]
    for did,dev in list(devices.items())[:32]:
        if not isinstance(did,str) or not isinstance(dev,dict):continue
        key=dev.get('localKey');password=dev.get('password')
        if not isinstance(key,str) or len(key.encode('utf-8'))!=16:continue
        if not isinstance(password,str) or not 1<=len(password)<=2048:continue
        expected=hashlib.md5((password+'||'+key).encode(),usedforsecurity=False).hexdigest().encode()
        if hmac.compare_digest(expected.lower(),digest.lower()):candidates.append((did,password,key))
    # Only one matching *current* credential. Fail closed if the wrong device
    # or several accounts/devices share this identifier combination.
    if len(candidates)!=1:return summary,None
    did,password,key=candidates[0]
    summary['auth_identite_oem_correspondante']=True
    # No byte of the old plaintext body is used in the new auth. The prefix is
    # a documented constant; digest is regenerated from current OEM values.
    newbody=bytearray(288);newbody[:5]=b'admin'
    newbody[32:64]=hashlib.md5((password+'||'+key).encode(),usedforsecurity=False).hexdigest().encode()
    fresh=struct.pack('<II',_CONTROL_MAGIC,1)+bytes(newbody)
    if not hmac.compare_digest(fresh,plain):
        # The old auth MUST have precisely this reproducible schema. Do not
        # transmit an uncertain structure even when digest happens to match.
        return summary,None
    summary['auth_schema_reconstructible']=True
    return summary,fresh


def _current_auth_profile(coordinator:Any,*,config_dir,nom_capture,ip_station)->tuple[dict,bytes|None]:
    info={'analyse_hors_ligne':True,'offres_0x20_envoyees':0,'stun_envoyes':0,
          'kcp_auth_push_envoyes':0,'requetes_video_envoyees':0,'commandes_ptz_envoyees':0,
          'donnees_privees_retournees':False,'secrets_retournes':False,
          'auth_schema_reconstructible':False}
    try:
        ip=_validate_target(ip_station)
        root=(Path(config_dir)/'smart_aosu_traces').resolve()
        path=(root/str(nom_capture)).resolve()
        if path.parent!=root or not path.is_file() or path.stat().st_size>32*1024*1024:
            return {**info,'etat':'capture_absente'},None
        client=getattr(coordinator,'client',None)
        cache=getattr(client,'_tuya_oem_inventory_cache',{})
        devices=cache.get('devices',{}) if isinstance(cache,dict) else {}
        if not isinstance(devices,dict):return {**info,'etat':'inventaire_oem_absent'},None
        data=getattr(coordinator,'data',None)
        if not isinstance(data,dict):return {**info,'etat':'inventaire_ha_absent'},None
        stations=[v for v in data.values() if isinstance(v,dict) and v.get('model')=='H1L' and v.get('is_camera') is False]
        if len(stations)!=1:return {**info,'etat':'station_ambigue'},None
        from .c9_h1l_identity_structure_b99 import _match_name
        matches=[(did,dev) for did,dev in devices.items() if isinstance(dev,dict) and _match_name(dev,stations[0].get('name'))]
        if len(matches)!=1:return {**info,'etat':'station_ambigue'},None
        station_id,dev=matches[0]
        sk=dev.get('localKey')
        if not isinstance(sk,str) or len(sk.encode())!=16:return {**info,'etat':'cle_station_absente'},None
        offer,_,_=_authenticated_transcript(path,ip,sk.encode())
        if not isinstance(offer,dict) or offer.get('header',{}).get('to')!=station_id:
            return {**info,'etat':'capture_offre_station_incoherente'},None
        sdp=offer.get('msg',{}).get('sdp')
        key=_parse_answer_key(sdp)
        if key is None:return {**info,'etat':'cle_offre_capture_absente'},None
        packets=_client_first_six_kcp(path,ip)
        check=_audit_startup_packets(packets,key)
        if (check['kcp_hmac_valides']!=6 or check['kcp_enregistrements_aes_dechiffres']!=6 or
            check['kcp_commandes_structure_connue']!=6):
            return {**info,'etat':'bootstrap_kcp_capture_non_confirme'},None
        metrics,fresh=_inspect_auth_record(packets[0],key,devices,station_id)
        info.update(metrics)
        if fresh is None:return {**info,'etat':'schema_auth_c9_inconnu_ou_identifiants_absents'},None
        return {**info,'etat':'schema_auth_c9_regenerable'},fresh
    except (OSError,KeyError,TypeError,ValueError,IndexError,UnicodeError,struct.error):
        return {**info,'etat':'audit_auth_c9_inexploitable'},None
    except Exception:return {**info,'etat':'erreur_interne_masquee'},None


def audit_auth_kcp_c9_b130(coordinator:Any,*,config_dir,nom_capture,ip_station,camera_numero,
    confirmation_capture_personnelle,confirmation_camera_candidate,
    autoriser_reconstitution_oem=False,confirmation_envoi_mot_de_passe=False)->dict:
    from .c9_kcp_bootstrap_b128 import audit_bootstrap_kcp_c9_b128
    base={'diagnostic':'aosu_audit_auth_kcp_c9_b130','analyse_hors_ligne':True,
          'offres_0x20_envoyees':0,'stun_envoyes':0,'kcp_auth_push_envoyes':0,
          'commandes_ptz_envoyees':0,'requetes_video_envoyees':0,
          'secrets_retournes':False}
    status=audit_bootstrap_kcp_c9_b128(coordinator,config_dir=config_dir,
        nom_capture=nom_capture,ip_station=ip_station,camera_numero=camera_numero,
        confirmation_capture_personnelle=confirmation_capture_personnelle,
        confirmation_camera_candidate=confirmation_camera_candidate,
        autoriser_reconstitution_oem=autoriser_reconstitution_oem,
        confirmation_envoi_mot_de_passe=confirmation_envoi_mot_de_passe)
    for key in ('cache_oem_avant','appels_http_oem','mot_de_passe_envoye'):
        if key in status:base[key]=status[key]
    if status.get('etat')!='six_commandes_kcp_structure_validee':
        return {**base,'etat':status.get('etat','bootstrap_capture_non_valide')}
    profile,_=_current_auth_profile(coordinator,config_dir=config_dir,nom_capture=nom_capture,ip_station=ip_station)
    return {**base,**profile,'diagnostic':'aosu_audit_auth_kcp_c9_b130'}
