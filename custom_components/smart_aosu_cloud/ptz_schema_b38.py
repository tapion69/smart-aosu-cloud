"""Privacy-preserving inspection of known Tuya PTZ schema, without PTZ writes.

Tuya/AOSU C5L is not yet linked by an exact OEM identifier, so this diagnostic
only summarizes the single name-matched device from a *fresh* cache. No raw
identifiers, arbitrary strings, DP values or credentials leave the module.
"""
from __future__ import annotations
import json

KNOWN_DPS = ('ptz_control', 'ptz_stop')
TOKEN_TO_DP = {'119': 'ptz_control', '116': 'ptz_stop'}
SCHEMA_KEYS = frozenset(('schema','property','properties','values','range','valueRange',
                         'type','dpType','valueType','datatype','dataType','mode',
                         'readWrite','permission','access','accessMode','writable','editable',
                         'dpId','id','code','dpCode','identifier','name','func','functions',
                         'schemaInfo','schemaProperty','typeSpec'))
OBJECT_KEYS = ('code','dpCode','identifier','name')
TYPES = {'enum':'enum','boolean':'bool','bool':'bool','integer':'integer',
         'int':'integer','value':'integer','string':'string','raw':'raw'}
SOURCE_KINDS = {'functions':'fonctions','function':'fonctions','schema':'schema',
                'status':'statut','dps':'datapoints','dpCodes':'datapoints',
                'properties':'proprietes','property':'proprietes',
                'skills':'capacites','data':'donnees','productBean':'produit'}


def _decode_schema(value):
    if isinstance(value, str) and len(value) < 32768 and value.lstrip().startswith(('{','[')):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            pass
    return value


def _enum_range(value):
    """Only recognized numeric direction codes: never return vendor strings."""
    value = _decode_schema(value)
    if isinstance(value, dict):
        value = value.get('range', value.get('values', value.get('enum')))
    if isinstance(value, str):
        value = [part.strip() for part in value.split(',')]
    if not isinstance(value, (list, tuple)) or len(value) > 24:
        return []
    output = []
    for item in value:
        if type(item) is int and 0 <= item <= 7:
            output.append(str(item))
        elif isinstance(item, str) and item in ('0','1','2','3','4','5','6','7'):
            output.append(item)
        else:
            return []
    return sorted(set(output), key=int)


def _candidate_metadata(node):
    """Inspect only key names in a candidate schema, not raw device data."""
    typ = 'inconnu'
    permission = 'non_documentee'
    is_writable = False
    dp_id = None
    allowed = []
    queue = [(node,0)]
    seen = set()
    while queue:
        value, depth = queue.pop()
        value = _decode_schema(value)
        if not isinstance(value,(dict,list)) or id(value) in seen or depth > 4:
            continue
        seen.add(id(value))
        if isinstance(value, list):
            for x in value[:20]:
                if isinstance(x,(dict,list,str)):
                    queue.append((x,depth+1))
            continue
        for name,entry in value.items():
            if name not in SCHEMA_KEYS:
                continue
            if name in ('type','dpType','valueType','datatype','dataType') and isinstance(entry,str):
                t=TYPES.get(entry.strip().lower())
                if t: typ=t
            if name in ('readWrite','permission','access','accessMode','mode') and isinstance(entry,str):
                p=entry.strip().lower()
                if p in ('rw','wr','readwrite','write','w','read','r','ro'):
                    permission='ecriture_annoncee' if p in ('rw','wr','readwrite','write','w') else 'lecture_seule_annoncee'
                    if permission == 'ecriture_annoncee':is_writable=True
            if name in ('writable','editable') and type(entry) is bool:
                is_writable|=entry
                if entry:permission='ecriture_annoncee'
            if name in ('dpId','id') and type(entry) is int and entry in (116,119):
                dp_id=entry
            if name in ('range','valueRange','values'):
                allowed = allowed or _enum_range(entry)
            if name in ('schema','property','properties','schemaInfo','schemaProperty','typeSpec','values') and isinstance(entry,(dict,list,str)):
                queue.append((entry,depth+1))
    return {'type_declare':typ,'autorisation_ecriture_declaree':permission,
            'ecriture_annoncee':is_writable,'id_dp_standard_detecte':dp_id,
            'valeurs_enum_chiffrees':allowed}


def inspect_ptz_schema(row: object) -> dict:
    """Read a single anonymized device. Never call a gateway or mutate input."""
    out={'diagnostic':'aosu_schema_ptz_b38', 'fiche_selectionnee':isinstance(row,dict),
         'nombre_definitions_examinees':0,'commandes_emises':0,'appels_reseau':0,
         'identifiants_retournes':False,'valeurs_dp_actuelles_retournees':False,
         'direction_effective_confirmee':False,'arret_moteur_valide':False,
         'transport_publication_valide':False,'mouvement_autorise':False,
         'datapoints':{x:{'reference_reconnue':False,'emplacements':[],
                          'type_declare':'inconnu','autorisation_ecriture_declaree':'non_documentee',
                          'ecriture_annoncee':False,'id_dp_standard_detecte':None,
                          'valeurs_enum_chiffrees':[]} for x in KNOWN_DPS}}
    if not isinstance(row,dict):
        out['verdict']='aucune_fiche_selectionnee'
        return out
    queue=[(row,(),0)]
    visited=0
    while queue and visited<400:
        node,path,depth=queue.pop()
        if depth>7: continue
        if isinstance(node,dict):
            visited+=1
            dp=None
            for k in OBJECT_KEYS:
                v=node.get(k)
                if v in KNOWN_DPS if isinstance(v,str) else False:
                    dp=v;break
            if dp is None:
                for k in ('dpId','id'):
                    v=node.get(k)
                    if type(v) is int and v in (119,116):
                        dp=TOKEN_TO_DP[str(v)]
                        break
            if dp:
                _add(out,dp,node,path)
            for k,v in list(node.items())[:100]:
                if isinstance(k,str) and k in KNOWN_DPS:
                    _add(out,k,v,path+('direct',))
                if isinstance(k,str) and k in TOKEN_TO_DP:
                    _add(out,TOKEN_TO_DP[k],v,path+('dp_num',))
                if isinstance(v,(dict,list)) and depth<7:
                    queue.append((v,path+(SOURCE_KINDS.get(k,'autre'),),depth+1))
        elif isinstance(node,list):
            visited+=1
            for v in node[:100]:
                if isinstance(v,(dict,list)):
                    queue.append((v,path,depth+1))
    out['nombre_definitions_examinees']=visited
    if all(out['datapoints'][x]['reference_reconnue'] for x in KNOWN_DPS):
        dir=out['datapoints']['ptz_control'];stop=out['datapoints']['ptz_stop']
        out['verdict']=('codes_detectes_et_schema_partiel'
                        if dir['type_declare'] != 'inconnu' or stop['type_declare']!='inconnu'
                        else 'codes_detectes_sans_schema_de_valeurs')
    else:
        out['verdict']='codes_non_retrouves_dans_la_fiche'
    return out


def _add(out, dp, node, path):
    out_dp=out['datapoints'][dp]
    out_dp['reference_reconnue']=True
    for p in path:
        if p in SOURCE_KINDS.values() and p not in out_dp['emplacements']:
            out_dp['emplacements'].append(p)
    meta=_candidate_metadata(node)
    for key in ('type_declare','autorisation_ecriture_declaree','id_dp_standard_detecte'):
        if out_dp[key] in ('inconnu','non_documentee',None) and meta[key] not in ('inconnu','non_documentee',None):
            out_dp[key]=meta[key]
    if not out_dp['valeurs_enum_chiffrees'] and meta['valeurs_enum_chiffrees']:
        out_dp['valeurs_enum_chiffrees']=meta['valeurs_enum_chiffrees']
    if meta['ecriture_annoncee']:out_dp['ecriture_annoncee']=True
    out_dp['emplacements']=sorted(out_dp['emplacements'])[:8]
