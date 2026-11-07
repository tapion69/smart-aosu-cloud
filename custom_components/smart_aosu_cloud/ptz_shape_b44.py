"""b44: privacy-safe shape audit of Tuya C5L device.get response.

One previously authorized OEM read; no camera writes, SDK emulation, raw DP
values, raw keys, credentials or identifiers in returned output. The summary
only differentiates runtime datapoints from a documented writable schema.
"""
from __future__ import annotations
import json

_CODES=('ptz_control','ptz_stop')
_KNOWN_SECTIONS=('datapoints','functions','function','schema','schemaInfo',
                 'properties','property','status','dps','dpCodes','skills',
                 'productBean','thingModel','capabilities')
_FIELD_NAMES=('code','dpCode','identifier','dpId','id','type','dpType',
              'valueType','datatype','dataType','permission','readWrite',
              'access','accessMode','mode','writable','editable','schema',
              'schemaInfo','schemaProperty','property','properties',
              'range','valueRange','values','typeSpec','value','dpValue')
_SCHEMA_MARKERS={'type','dpType','valueType','datatype','dataType',
                 'permission','readWrite','access','accessMode','mode',
                 'writable','editable','schema','schemaInfo',
                 'schemaProperty','property','properties','range',
                 'valueRange','values','typeSpec'}
_PRESENCE_MARKERS={'value','dpValue'}


def _kind(v):
    if v is None:return 'null'
    if type(v) is bool:return 'booleen'
    if type(v) is int:return 'entier'
    if type(v) is float:return 'decimal'
    if isinstance(v,dict):return 'objet'
    if isinstance(v,(list,tuple)):return 'liste'
    if isinstance(v,str):
        if len(v)<32768 and v.lstrip().startswith(('{','[')):
            try:
                parsed=json.loads(v)
                if isinstance(parsed,(dict,list)):
                    return 'json_dans_chaine'
            except (ValueError,TypeError):pass
        return 'chaine'
    return 'autre'


def _parse_struct(v):
    if isinstance(v,str) and _kind(v)=='json_dans_chaine':
        try:return json.loads(v)
        except (ValueError,TypeError):pass
    return v


def _outline(value,source,mode):
    """Never include dynamic user/server data, just structural classifications."""
    value=_parse_struct(value)
    keys=set(value).intersection(_FIELD_NAMES) if isinstance(value,dict) else set()
    schema=bool(keys & _SCHEMA_MARKERS)
    # Scalar DP responses are often current values or booleans indicating support.
    if not isinstance(value,dict):
        verdict='valeur_ou_indicateur_sans_schema'
    elif schema:
        verdict='metadonnees_schema_presentes_non_validees'
    elif keys & _PRESENCE_MARKERS:
        verdict='valeur_courante_sans_schema'
    else:
        verdict='objet_sans_metadonnees_schema'
    return {'source':source,'mode_detection':mode,'forme':_kind(value),
            'champs_schema_ou_valeur_presents':sorted(keys)[:24],
            'classement':verdict}


def summarize_ptz_oem_shape(response:object)->dict:
    """Only fixed vocabulary returned. Bound traversal to resist oversized input."""
    out={'diagnostic':'aosu_structure_ptz_b44','lecture_seule':True,
         'format_racine':_kind(response),'sections_racine_reconnues':[],
         'ptz_control':{'formes_observees':[],'total_occurrences':0},
         'ptz_stop':{'formes_observees':[],'total_occurrences':0},
         'identifiants_retournes':False,'valeurs_dp_retournees':False,
         'noms_appareils_retournes':False,'donnees_brutes_conservees':False,
         'commandes_directionnelles_envoyees':0,'commandes_arret_envoyees':0,
         'mouvement_autorise':False,'schema_ecriture_confirme':False,
         'transport_publication_confirme':False}
    if not isinstance(response,dict):
        out['conclusion']='reponse_non_structurable'
        return out
    out['sections_racine_reconnues']=[k for k in _KNOWN_SECTIONS if k in response]
    q=[(response,'racine',0)]
    visited=0
    while q and visited<500:
        node,source,depth=q.pop()
        node=_parse_struct(node)
        if depth>8 or not isinstance(node,(dict,list)):continue
        visited+=1
        if isinstance(node,list):
            for x in node[:80]:
                if isinstance(x,(dict,list)):q.append((x,source,depth+1))
            continue
        marker=next((node[k] for k in ('code','dpCode','identifier','name')
                     if isinstance(node.get(k),str) and node[k] in _CODES),None)
        if marker is not None:
            _append(out,marker,node,source,'champ_code')
        for k,v in list(node.items())[:90]:
            if not isinstance(k,str):continue
            if k in _CODES:
                _append(out,k,v,source,'cle_directe')
            if k in _KNOWN_SECTIONS and isinstance(_parse_struct(v),(dict,list)):
                q.append((v,k,depth+1))
            # Additional vendor nesting may contain schema; never output its key.
            elif isinstance(v,(dict,list)):
                q.append((v,'autre',depth+1))
    counts=[out[c]['total_occurrences'] for c in _CODES]
    if not any(counts):out['conclusion']='aucun_code_ptz_dans_fiche'
    elif any(any(x['classement']=='metadonnees_schema_presentes_non_validees'
                      for x in out[c]['formes_observees']) for c in _CODES):
        out['conclusion']='metadonnees_reperables_a_interpreter_sans_publication'
    else:out['conclusion']='codes_ptz_reperes_mais_pas_de_schema_dans_les_noeuds_associes'
    return out


def _append(out,code,value,source,mode):
    if code not in _CODES:return
    group=out[code]
    group['total_occurrences']=min(100,group['total_occurrences']+1)
    observation=_outline(value,source,mode)
    if observation not in group['formes_observees'] and len(group['formes_observees'])<8:
        group['formes_observees'].append(observation)
