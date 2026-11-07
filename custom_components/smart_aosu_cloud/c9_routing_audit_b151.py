"""B151: strict offline camera-routing comparison against two owned C9/H1L captures.

The service NEVER opens LAN connections, fetches RTC, refreshes OEM, sends
video/PTZ, writes captures, or outputs cryptographic values/identifiers/hash
fingerprints. Optional captures are ONLY for this development audit; the video
engine has never depended on this module. Both are expected under
<HA config>/smart_aosu_traces/ and are NOT bundled in public releases.

If a captured *media* key is absent (as with an offer missed by a PCAP), a
station's Tuya localKey cannot replace it. No speculative decryption occurs.
"""
from __future__ import annotations
import hmac
import struct
from pathlib import Path
from typing import Any
from .c9_captureless_b144 import _snapshot,_new_commands
from .c9_kcp_bootstrap_b128 import _client_first_six_kcp
from .c9_kcp_auth_rtc_b133 import _unique_meta
from .c9_kcp_video_start_b137 import _reconstruct_post_auth
from .c9_kcp_command_fields_b136 import _decrypt_six
from .c9_video_preflight_b123 import _authenticated_transcript
from .tuya_channel0_probe import _parse_answer_key
from .h1l_local_probe_b103 import _validate_target

_CAPTURES={1:'c9_camera_1_reference.pcap',
           2:'c9_camera_2_reference.pcap'}
_MAX_BYTES=32*1024*1024
_EXPECTED_LENGTHS=[364,92,156,156,156,156]


def _safe_capture(config_dir: str|Path,numero:int)->Path|None:
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    name=_CAPTURES[numero]
    path=(root/name).resolve()
    if path.parent!=root or not path.is_file():return None
    if not 24<=path.stat().st_size<=_MAX_BYTES:return None
    return path


def _flag_summary(commands:tuple[bytes,...]|list[bytes])->list[dict]:
    """Protocol flag offsets and tiny enum values only; no ID-like bytes."""
    result=[]
    for i,cmd in enumerate(commands,1):
        if i==1:search=range(20,24)
        elif i==2:search=range(52,len(cmd))
        else:search=range(52,len(cmd))
        nz=[j-20 for j in search if cmd[j]]
        result.append({'commande':i,'nombre_octets_drapeaux_non_nuls':len(nz),
           'drapeau_offset_payload':(nz[0] if len(nz)==1 else None),
           'drapeau_valeur':(cmd[20+nz[0]] if len(nz)==1 and cmd[20+nz[0]]<=128 else None)})
    return result


def _capture_readonly(path:Path,ip:str,key:bytes,sid:str,cid:str,devices:dict,meta:str)->dict:
    out={'capture_presente':True,'six_kcp_initiaux':0,
         'tailles_kcp_capture':[],'sequence_kcp_valide':False,
         'offre_sdp_capture_exploitable':False,'auth_kcp_verifiee':False,
         'auth_station_identite_confirmee':False,'auth_camera_identite_confirmee':False,
         'commandes_capture_verifiees':0,'comparaison_sans_pcap_possible':False,
         'donnees_dechiffrees_retournees':False,'identifiants_retournes':False,
         'secrets_retournes':False,'lecture_reseau':False,'pcap_modifie':False}
    try:
        packets=_client_first_six_kcp(path,ip)
        out['six_kcp_initiaux']=len(packets)
        out['tailles_kcp_capture']=[len(x) for x in packets]
        out['sequence_kcp_valide']=(len(packets)==6 and
                                   [len(x) for x in packets]==_EXPECTED_LENGTHS)
        if not out['sequence_kcp_valide']:
            out['etat']='six_messages_kcp_absents_ou_tailles_inattendues';return out
    except (ValueError,OSError,KeyError,IndexError,struct.error,TypeError):
        out['etat']='pcap_structure_non_exploitable';return out
    try:
        offer,_,_=_authenticated_transcript(path,ip,key)
        media_key=(_parse_answer_key(offer.get('msg',{}).get('sdp'))
                   if isinstance(offer,dict) and isinstance(offer.get('msg'),dict) else None)
        # A valid encrypted offer is not enough: bind it to THIS H1L session.
        header=offer.get('header') if isinstance(offer,dict) else None
        if not isinstance(header,dict) or header.get('to')!=sid or header.get('type')!='offer':
            out['etat']='offre_capture_cible_station_non_confirmee';return out
        if not isinstance(media_key,bytes) or len(media_key)!=16:
            out['etat']='offre_sdp_absente_ou_cle_media_indisponible';return out
        out['offre_sdp_capture_exploitable']=True
    except (ValueError,OSError,KeyError,IndexError,struct.error,TypeError,UnicodeError):
        out['etat']='offre_sdp_absente_ou_non_authentifiable';return out
    try:
        plains=_decrypt_six(packets,media_key)
        out['auth_kcp_verifiee']=True
        checks,matched=_unique_meta(plains[0],sid,cid,devices)
        out['auth_station_identite_confirmee']=bool(checks.get('auth_bloc_station_conforme'))
        out['auth_camera_identite_confirmee']=bool(checks.get('auth_bloc_camera_conforme'))
        if matched is None or not hmac.compare_digest(matched,meta):
            out['etat']='capture_et_inventaire_oem_different';return out
        verified=_reconstruct_post_auth(plains,meta)
        out['commandes_capture_verifiees']=len(verified)
        fresh=_new_commands(meta)
        matches=[hmac.compare_digest(x,y) for x,y in zip(verified,fresh)]
        out['comparaison_sans_pcap_possible']=True
        out['concordance_cinq_commandes']=matches
        out['commandes_identiques']=sum(matches)
        out['drapeaux_capture']=_flag_summary(verified)
        out['drapeaux_sans_pcap']=_flag_summary(fresh)
        out['drapeau_premiere_commande_different']=not matches[0]
        out['etat']='profil_capture_verifie_et_compare'
    except (ValueError,OSError,KeyError,IndexError,struct.error,UnicodeError,TypeError):
        out['etat']='auth_ou_commandes_kcp_non_validables'
    return out


def _order_check(client:Any,data:dict)->dict:
    """Detect string vs numeric sort bug in B144; report only category."""
    index=getattr(client,'_device_sn_index',None)
    cams=[k for k,v in data.items() if isinstance(v,dict) and
          v.get('model')=='C9C3CA11' and v.get('is_camera') is True]
    result={'tri_serie_index_disponible':False,'tri_lexicographique_different':False,
            'tri_numerique_comparable':False}
    if not isinstance(index,dict) or len(cams)!=2 or not all(k in index for k in cams):return result
    values=[]
    for k in cams:
        rec=index[k]
        if not isinstance(rec,(tuple,list)) or not rec: return result
        values.append(rec[0])
    result['tri_serie_index_disponible']=True
    if not all(type(v) is int for v in values):return result
    result['tri_numerique_comparable']=True
    result['tri_lexicographique_different']=(sorted(cams,key=lambda k:str(index[k][0]))!=
                                              sorted(cams,key=lambda k:index[k][0]))
    return result


def audit_routage_station_c9_b151(coordinator:Any,*,config_dir:str|Path,
        ip_station:str,confirmation_captures_personnelles:bool=False)->dict:
    """Audit cached OEM + optionally available pair of operator-supplied PCAPs.

    Zero network, zero filesystem mutation. The omitted-PCAP path still audits
    the current 2-camera routing and explicitly labels missing crypto proof.
    """
    out={'diagnostic':'aosu_audit_routage_station_c9_b151',
        'analyse_hors_ligne':True,'appels_reseau':0,'requetes_rtc':0,
        'commandes_video_envoyees':0,'commandes_ptz_envoyees':0,
        'reconstitution_oem_lancee':False,'captures_modifiees':False,
        'captures_rejouees':False,'secrets_retournes':False,
        'identifiants_retournes':False,'contenu_video_retourne':False,
        'audit_developpement_facultatif':True,
        'direct_c9_sans_pcap_conserve':True}
    if confirmation_captures_personnelles is not True:
        return {**out,'etat':'confirmation_captures_personnelles_requise'}
    try:ip=_validate_target(ip_station)
    except (ValueError,TypeError):return {**out,'etat':'ip_h1l_invalide'}
    try:
        one=_snapshot(coordinator,1,ip);two=_snapshot(coordinator,2,ip)
        sid,cid1,devices,meta1=one
        sid2,cid2,_,meta2=two
        if sid!=sid2 or cid1==cid2 or meta1==meta2:
            return {**out,'etat':'routage_camera_non_unique'}
        local=devices[sid].get('localKey')
        if not isinstance(local,str) or len(local.encode('utf-8'))!=16:
            return {**out,'etat':'cle_station_h1l_absente'}
        out['inventaire_oem']={'station_commune':True,
             'identifiants_c9_distincts':True,'references_c9_20_octets_distinctes':True,
             'association_aosu_oem_univoque_par_nom':True,
             'correspondance_serie_cryptographique_confirmee':False,
             'tri_index':_order_check(getattr(coordinator,'client',None),
                       getattr(coordinator,'data',{}))}
        local_key=local.encode('utf-8')
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError) as err:
        # Error strings are only internal constant labels in the fail-closed mapper.
        safe=str(err)
        if safe not in ('inventaire_oem_absent','station_h1l_ambigue','deux_c9_h1l_introuvables',
          'nom_aosu_c9_absent','correspondance_oem_c9_ambigue','cle_station_h1l_absente',
          'cle_locale_c9_specifique_non_prise_en_charge','reference_oem_c9_20_octets_ambigue',
          'identifiant_station_format_invalide'):
            safe='inventaire_oem_non_exploitable'
        return {**out,'etat':safe}
    base=Path(config_dir)
    for n,meta,cid in ((1,meta1,cid1),(2,meta2,cid2)):
        item={'camera_numero':n}
        path=_safe_capture(base,n)
        if path is None:
            item['capture_presente']=False;item['etat']='pcap_de_developpement_absent'
        else:
            item.update(_capture_readonly(path,ip,local_key,sid,cid,devices,meta))
        out.setdefault('cameras',[]).append(item)
    compared=sum(c.get('comparaison_sans_pcap_possible') is True for c in out['cameras'])
    out['nombre_profils_cryptographiquement_compares']=compared
    out['etat']=('comparaison_authentifiee_deux_c9' if compared==2 else
                 'comparaison_authentifiee_partielle' if compared==1 else
                 'inventaire_valide_captures_non_dechiffrees')
    out['capture_camera_1_sans_sdp_ne_prouve_pas_protocole_different']=True
    out['comportement_actif_modifie']=False
    return out
