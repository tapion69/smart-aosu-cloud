"""B142: resolve the intended C9 by exact capture-auth OEM identity, not by list order.

The capture is inspected locally, never sent. Fail closed if the same camera is
not uniquely present in today's two-C9, one-station OEM inventory.
"""
from .c9_rtc_candidate_b101 import _candidate
from .c9_kcp_auth_audit_b131 import _record_first_auth
from .c9_kcp_auth_rtc_b133 import _unique_meta

def capture_camera_id_b142(data,client,devices,capture,ip,station_id,station_key):
    if not isinstance(data,dict) or not isinstance(devices,dict):
        raise ValueError('inventaire_camera_invalide')
    candidates=[]
    for n in (1,2):
        candidate,_=_candidate(data,client,n)
        if not isinstance(candidate,str) or candidate not in devices or candidate in candidates:
            raise ValueError('inventaire_camera_invalide')
        candidates.append(candidate)
    plain=_record_first_auth(capture,ip,station_key,station_id)
    if plain is None:raise ValueError('auth_capture_invalide')
    matches=[]
    for did in candidates:
        checks,meta=_unique_meta(plain,station_id,did,devices)
        if meta is not None and checks.get('auth_schema_reconstructible') is True:
            matches.append(did)
    if len(matches)!=1:
        raise ValueError('identite_camera_capture_non_concordante')
    return matches[0]
