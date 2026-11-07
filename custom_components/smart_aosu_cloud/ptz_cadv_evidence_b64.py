"""b64: read-only, non-identifying CADV evidence from one selected OEM row/detail.

No public identifiers, keys, unknown fields, or raw response values are returned.
Never publishes a DP, touches video, or makes a network request itself.
"""
from __future__ import annotations
import json
import re
from typing import Any

_CADV = re.compile(r"^(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)\.(0|[1-9][0-9]?)$")


def inspect_cadv(payload: Any) -> dict:
    """Report only SDK branch evidence, or explicitly state it is unavailable."""
    stack=[(payload,0)]
    seen=set()
    values=set()
    examined=0
    malformed=False
    matched_fields=set()
    malformed_fields=set()
    while stack and examined<500:
        node,depth=stack.pop()
        if depth>8:continue
        if isinstance(node,str) and len(node)<=32768 and node.lstrip().startswith(('{','[')):
            try:node=json.loads(node)
            except (ValueError,TypeError,RecursionError):continue
        if not isinstance(node,(dict,list)) or id(node) in seen:continue
        seen.add(id(node));examined+=1
        if isinstance(node,dict):
            # APK classes7.dex DeviceRespBean.getGatewayVerCAD() reads
            # gatewayVerCAD. classes4.dex devRespWrap() transfers this to
            # DeviceBean.setCadv(), then sendCommand uses DeviceBean.getCadv().
            # Existing b64 fields remain supported for backward compatibility.
            for field in ('gatewayVerCAD','cadv','cAdv'):
                if field in node:
                    matched_fields.add(field)
                    raw=node[field]
                    if isinstance(raw,str) and _CADV.fullmatch(raw.strip()):
                        parts=tuple(int(x) for x in raw.strip().split('.'))
                        values.add(parts)
                    else:
                        malformed=True
                        malformed_fields.add(field)
            children=list(node.values())[:64]
        else:children=node[:64]
        for item in children:
            if isinstance(item,(dict,list)) or isinstance(item,str) and len(item)<=32768 and item.lstrip().startswith(('{','[')):
                stack.append((item,depth+1))
    evidence={'cadv_trouve':bool(values), 'champ_invalide_present':malformed,
              'noeuds_examines':examined,'branche_sdk':'indeterminee',
              'champ_sdk_gatewayVerCAD_present':'gatewayVerCAD' in matched_fields,
              'champs_versions_reperes':sorted(matched_fields),
              'champs_versions_invalides':sorted(malformed_fields),
              'valeur_confirmee':None, 'plusieurs_valeurs_contradictoires':len(values)>1,
              'secrets_retournes':False, 'identifiants_retournes':False}
    if len(values)==1 and not malformed:
        version=next(iter(values))
        evidence['valeur_confirmee']='.'.join(map(str,version))
        evidence['branche_sdk']='compact_si_device_non_virtuel' if version>=(1,0,2) else 'ancienne_ou_conditionnelle'
    return evidence
