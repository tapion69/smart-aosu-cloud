"""B149: distinguish C9 KCP reply headers from outbound command headers.

All information is derived only from current authenticated AES-KCP messages.
No PCAP, extra TCP/UDP packets, media recording or secret-bearing output.
An apparent reply/status field is *not* proof of application acceptance.
"""
from __future__ import annotations
import struct

_MAGIC=0x12345678
# (type, subtype): ordinal in known C9 command burst. Unknown types/subtypes
# are never output verbatim (they may contain identifiers).
_EXPECTED={
    (0,0x0a):1,
    (2,0x0c):2,
    (0x10004,0x13):3,
    (0x10003,0x10):4,
    (0x10005,0x40010):5,
}


def inspect_reply_b149(plain:bytes)->dict:
    out={'structure':'non_identifiee','commande_associee':None,
         'champ_3_interprete_comme_statut':False,
         'confirmation_authentification':False,
         'acceptation_video_prouvee':False,
         'contenu_restitue':False,'secret_restitue':False}
    if not isinstance(plain,bytes) or not 20<=len(plain)<=4096:
        out['structure']='taille_hors_profil';return out
    magic,kind,third,sub,n=struct.unpack_from('<IIIII',plain)
    if magic!=_MAGIC:
        out['structure']='magic_invalide';return out
    out['commande_associee']=_EXPECTED.get((kind,sub))
    actual=len(plain)-20
    # Never output opaque 32-bit fields, only numeric status candidates from
    # a small bounded range. An unknown large 32-bit value may be an ID.
    out.update({'magic_valide':True,
        'type_et_sous_type_attendus':out['commande_associee'] is not None,
        'champ_3_nul':third==0,
        'champ_3_petit':0<third<=255,
        'champ_3_valeur_candidate':third if third<=31 else None,
        'longueur_declaree_coherente':n==actual,
        'longueur_declaree_classe':('egale' if n==actual else
                                   'zero' if n==0 else 'superieure' if n>actual else 'inferieure'),
        'taille_payload_classe':('vide' if actual==0 else 'courte' if actual<=8 else
                                 'moyenne' if actual<=128 else 'longue'),
        'ecart_longueur_classe':('aucun' if n==actual else
                               'petit' if abs(n-actual)<=16 else 'important'),
    })
    if third==0 and n==actual:
        out['structure']='entete_commande_classique'
    elif third!=0 and n==actual:
        out['structure']='entete_avec_champ_3_non_nul'
    elif third==0:
        out['structure']='longueur_non_conforme'
    else:
        out['structure']='champ_3_et_longueur_differents'
    return out


class ControlAuditB149:
    def __init__(self):
        self.total=0;self.before=0;self.after=0;self.out=[]
        self.nonzero=0;self.correct=0;self.known=0
    def accept(self,plain:bytes,*,phase:str)->None:
        if phase not in ('avant_commandes','apres_commandes'):
            raise ValueError('phase_reponse_invalide')
        self.total+=1
        if phase=='avant_commandes':self.before+=1
        else:self.after+=1
        s=inspect_reply_b149(plain)
        if s.get('magic_valide') and not s.get('champ_3_nul'):self.nonzero+=1
        if s.get('longueur_declaree_coherente'):self.correct+=1
        if s.get('commande_associee') is not None:self.known+=1
        if len(self.out)<16:self.out.append({'phase':phase,**s})
    def summary(self)->dict:
        return {'diagnostic':'aosu_reponses_controle_b149',
          'messages_reassembles':self.total,
          'reponses_avant_commandes':self.before,
          'reponses_apres_commandes':self.after,
          'champ_3_non_nul_nombre':self.nonzero,
          'longueurs_coherentes_nombre':self.correct,
          'type_sous_type_attendus_nombre':self.known,
          'reponses_structurelles':list(self.out),
          'acceptation_auth_applicative_prouvee':False,
          'video_demarrage_accepte_prouve':False,
          'pcap_requis':False,
          'donnees_privees_retournees':False,
          'octets_clairs_retournes':False,
          'secrets_retournes':False}
