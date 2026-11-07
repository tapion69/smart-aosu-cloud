"""B147: optional offline comparison, without PCAP being required for live.

Use only the user's own already-available C9 #2 capture during development to
check whether B144 guesses exactly match the known successful B139 commands.
No video/IDs/secret/hash/raw payload is returned, no LAN packet is sent.
"""
from __future__ import annotations
from pathlib import Path
from .c9_kcp_direct_b141 import _prepare_profile, _ensure_inventory_b141
from .c9_captureless_b144 import _new_commands

CAPTURE='c9_camera_2_reference.pcap'

def comparer_profil_b147(coordinator,*,config_dir,ip_station,
    confirmation_capture_personnelle=False,confirmation_envoi_mot_de_passe=False,
    autoriser_reconstitution_oem=False)->dict:
    result={'diagnostic':'aosu_comparer_profil_video_b147',
      'analyse_hors_ligne':True,'pcap_requis_pour_direct':False,
      'tcp_envoyes':0,'kcp_envoyes':0,'ptz_envoyes':0,
      'secrets_retournes':False,'donnees_video_retournees':False}
    if confirmation_capture_personnelle is not True:
        return {**result,'etat':'confirmation_capture_requise'}
    path=(Path(config_dir)/'smart_aosu_traces'/CAPTURE)
    if not path.is_file():return {**result,'etat':'capture_de_developpement_absente'}
    if not _ensure_inventory_b141(coordinator,autoriser_reconstitution_oem,
                                   confirmation_envoi_mot_de_passe):
        return {**result,'etat':'inventaire_oem_absent'}
    try:
        _,sid,cid,dev,verified=_prepare_profile(coordinator,config_dir,CAPTURE,ip_station)
        # Derive the current 20-byte camera reference from the *verified*
        # reconstructed command (not from a new source of secrets).
        meta=verified[1][20:40].decode('ascii')
        guessed=_new_commands(meta)
        comparisons=[a==b for a,b in zip(verified,guessed)]
        result.update({'comparaison_cinq_commandes':comparisons,
            'commandes_identiques':sum(comparisons),
            'profil_sans_pcap_identique':all(comparisons),
            'analyse_effectuee':True,
            'etat':'profil_compare_sans_rejeu'})
        return result
    except (OSError,ValueError,TypeError,KeyError,IndexError,UnicodeError):
        return {**result,'etat':'comparaison_non_exploitable'}
    except Exception:
        return {**result,'etat':'erreur_interne_masquee'}
