"""B150 — small, privacy-preserving C9 direct attempt history.

Reconnection diagnostics must not overwrite the previous successful control
exchange. No raw KCP, account ID, station IP, session token or device key is
retained or returned by this module.
"""
from __future__ import annotations

_COUNT_FIELDS=(
    'offres_0x20_envoyees','candidats_0x20_envoyes',
    'reponses_0x20_authentifiees','kcp_auth_push_envoyes',
    'kcp_auth_ack_recus','commandes_video_envoyees',
    'kcp_reponses_controle_dechiffrables','kcp_media_authenticated_passif',
    'stun_reponses_hmac_valides','kcp_reponses_hmac_invalides',
)
_BOOL_FIELDS=('tcp_authentifie','reponse_sdp_recue','ice_paire_nommee',
              'connexion_media_interrompue')
_SAFE_STATES={
    'erreur_reseau_ou_timeout','reponse_tuya_invalide',
    'cinq_commandes_video_envoyees_sans_media','medias_kcp_c9_recus_sans_jpeg',
    'images_c9_decodees','erreur_interne_sans_details',
    'erreur_interne_masquee','auth_kcp_reponse_authentifiee',
}
_SAFE_STAGES={
    'tcp_connexion_6668','tcp_challenge_attente','tcp_0x10_demande',
    'tcp_0x20_envoi','tcp_0x20_envoyee','erreur_reseau',
}
_SAFE_NET_ERRORS={'timeout','connexion_refusee','connexion_interrompue',
                  'reseau_injoignable','erreur_io'}
_SAFE_STRUCTURES={
    'entete_commande_classique','entete_avec_champ_3_non_nul',
    'longueur_non_conforme','champ_3_et_longueur_differents',
    'magic_invalide','taille_hors_profil','non_identifiee',
}


def _count(value):
    return value if type(value) is int and 0 <= value <= 10_000_000 else 0


def sanitized_attempt(result,ordinal):
    """Only explicit counts and coarse classifications, never arbitrary keys."""
    if not isinstance(result,dict):result={}
    out={'numero_essai':ordinal if type(ordinal) is int and ordinal>0 else 0,
         'etat':result.get('etat') if result.get('etat') in _SAFE_STATES else 'autre'}
    for key in _COUNT_FIELDS:out[key]=_count(result.get(key,0))
    for key in _BOOL_FIELDS:out[key]=result.get(key) is True
    stage=result.get('etape_echec')
    if stage in _SAFE_STAGES:out['etape_echec']=stage
    category=result.get('type_erreur_reseau')
    if category in _SAFE_NET_ERRORS:out['type_erreur_reseau']=category
    b149=result.get('analyse_reponses_kcp_b149')
    out['reponses_application_b149']=_count(b149.get('messages_reassembles',0)) if isinstance(b149,dict) else 0
    return out


def best_control_attempt(result,ordinal):
    """Keep only the last attempt with actual decrypted app-level replies."""
    if not isinstance(result,dict):return None
    obj=result.get('analyse_reponses_kcp_b149')
    if not isinstance(obj,dict) or _count(obj.get('messages_reassembles',0))==0:
        return None
    summary={'numero_essai':ordinal if type(ordinal) is int and ordinal>0 else 0,
             'messages_reassembles':_count(obj.get('messages_reassembles',0)),
             'reponses_avant_commandes':_count(obj.get('reponses_avant_commandes',0)),
             'reponses_apres_commandes':_count(obj.get('reponses_apres_commandes',0)),
             'champ_3_non_nul_nombre':_count(obj.get('champ_3_non_nul_nombre',0)),
             'longueurs_coherentes_nombre':_count(obj.get('longueurs_coherentes_nombre',0)),
             'type_sous_type_attendus_nombre':_count(obj.get('type_sous_type_attendus_nombre',0)),
             'reponses_structurelles':[]}
    for row in obj.get('reponses_structurelles',[])[:8]:
        if not isinstance(row,dict):continue
        item={}
        if row.get('phase') in ('avant_commandes','apres_commandes'):
            item['phase']=row['phase']
        if row.get('structure') in _SAFE_STRUCTURES:item['structure']=row['structure']
        associated=row.get('commande_associee')
        item['commande_associee']=associated if type(associated) is int and 1<=associated<=5 else None
        for b in ('magic_valide','type_et_sous_type_attendus','champ_3_nul',
                  'longueur_declaree_coherente'):
            item[b]=row.get(b) is True
        val=row.get('champ_3_valeur_candidate')
        item['champ_3_valeur_candidate']=val if type(val) is int and 0<=val<=31 else None
        summary['reponses_structurelles'].append(item)
    return summary
