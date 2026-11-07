"""B148: sanitized control response chronology for C9 LAN.

Never interpret KCP ACK as application authorization. Never return payloads,
opaque values, secrets or identifiers. Distinguish responses before and after
video startup, which helps identify C9 handshake variations without a PCAP.
"""
from __future__ import annotations
from .c9_control_response_b147 import summarize_control

class ControlAuditB148:
    def __init__(self):
        self.total=0
        self.invalides=0
        self.avant=0
        self.apres=0
        self.messages=[]
    def accept(self,plain:bytes,*,phase:str)->None:
        if phase not in ('avant_commandes','apres_commandes'):
            raise ValueError('phase_reponse_invalide')
        self.total+=1
        if phase=='avant_commandes':self.avant+=1
        else:self.apres+=1
        s=summarize_control(plain)
        if s.get('structure')!='commande_tuya': self.invalides+=1
        if len(self.messages)<16:
            self.messages.append({'phase':phase,**s})
    def summary(self)->dict:
        return {'diagnostic':'aosu_reponses_controle_b148',
                'messages_reassembles':self.total,
                'reponses_avant_commandes':self.avant,
                'reponses_apres_commandes':self.apres,
                'structures_non_conformes':self.invalides,
                'reponses_structurelles':list(self.messages),
                'acceptation_auth_applicative_prouvee':False,
                'donnees_privees_retournees':False,
                'octets_clairs_retournes':False,
                'secrets_retournes':False}

def continuer_udp_apres_tcp_incomplet(*,cause:str,post_commandes:bool,
        sdp_valide:bool,ice_nomme:bool,auth_ack:bool)->bool:
    """Allow continued UDP receive only for nonfatal partial TCP after valid ICE.

    No unverified TCP frame can be accepted or parsed after this decision.
    """
    return (cause=='trame_incomplete' and post_commandes is True and
            sdp_valide is True and ice_nomme is True and auth_ack is True)
