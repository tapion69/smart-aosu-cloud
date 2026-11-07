"""B147: privacy-preserving inspection of KCP control responses.

Called only on authenticated, decrypted, reassembled channel-0 messages;
never sends packets or exposes raw payloads, user IDs, keys or hashes.
A transport acknowledgment must not be reported as application acceptance.
"""
from __future__ import annotations
import struct

MAGIC=0x12345678
CATEGORIES={0:'systeme', 1:'authentification', 2:'commande_camera',
            0x10003:'commande_flux',0x10004:'commande_flux',0x10005:'commande_flux'}
# Only known Tuya control subtypes can be displayed; unknown codes/values are not leaked.
SAFE_SUB={0x0A,0x0C,0x10,0x13,0x40010,0x02,0x06,0x09,0x15}

def summarize_control(plain:bytes)->dict:
    """Return structural evidence, not interpreted authorization or arbitrary bytes."""
    out={'structure':'inconnue','reponse_auth_confirmee':False,
         'contenu_restitue':False,'secret_restitue':False}
    if not isinstance(plain,bytes) or len(plain)<8 or len(plain)>65536:
        return out
    if struct.unpack_from('<I',plain)[0]!=MAGIC:
        return {**out,'structure':'sans_magic_tuya'}
    kind=struct.unpack_from('<I',plain,4)[0]
    out['categorie_type']=CATEGORIES.get(kind,'autre_type')
    out['taille_classe']=('courte' if len(plain)<=32 else
                         'moyenne' if len(plain)<=128 else 'longue')
    if len(plain)<20:
        return {**out,'structure':'entete_court'}
    _,_,reserved,sub,n=struct.unpack_from('<IIIII',plain)
    out['structure']='commande_tuya' if reserved==0 and n==len(plain)-20 else 'entete_non_conforme'
    if out['structure']!='commande_tuya':return out
    out['sous_type_connu']=sub in SAFE_SUB
    out['sous_type']=f'0x{sub:08x}' if sub in SAFE_SUB else 'non_reconnu'
    data=plain[20:]
    out['payload_vide']=len(data)==0
    out['payload_tout_zero']=bool(data) and not any(data)
    out['payload_taille']=len(data)
    # Zero, small scalar, and generic data are *shape* labels only. A raw
    # scalar might be an identifier, so no scalar values leave this function.
    out['payload_forme']=('vide' if not data else 'nuls' if not any(data) else
                         'scalaire_u32' if len(data)==4 else
                         'blocs_32' if len(data)%32==0 else 'structure_variable')
    return out

class ControlAuditB147:
    def __init__(self):
        self.messages=0;self.invalides=0;self.replies=[]
    def accept(self,plain:bytes)->None:
        self.messages+=1
        summary=summarize_control(plain)
        if summary.get('structure')!='commande_tuya':self.invalides+=1
        if len(self.replies)<12:self.replies.append(summary)
    def summary(self)->dict:
        return {'messages_reassembles':self.messages,
                'structures_non_conformes':self.invalides,
                'reponses_structurelles':list(self.replies),
                'acceptation_auth_applicative_prouvee':False,
                'octets_clairs_retournes':False,
                'secrets_retournes':False}
