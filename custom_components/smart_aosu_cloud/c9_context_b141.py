"""B141: exact, per-camera H1L identity from owned PCAP and CURRENT OEM inventory.
Only the two expressly allowed personal captures are accepted. No PCAP credentials are sent.
"""
from pathlib import Path
from .c9_kcp_auth_rtc_b133 import _context as _old_context
from .c9_kcp_auth_audit_b131 import _record_first_auth
from .c9_h1l_identity_structure_b99 import _match_name
from .c9_capture_selector_b142 import capture_camera_id_b142
from .h1l_local_probe_b103 import _validate_target

CAPTURES={1:'c9_camera_1_reference.pcap',2:'c9_camera_2_reference.pcap'}

def camera_from_capture(name):
    if type(name) is not str:raise ValueError('nom_capture_c9_invalide')
    for number,filename in CAPTURES.items():
        if name==filename:return number
    raise ValueError('nom_capture_c9_invalide')

def _context_b141(coordinator,config_dir,nom_capture,ip_station):
    number=camera_from_capture(nom_capture)
    ip=_validate_target(ip_station)
    root=(Path(config_dir)/'smart_aosu_traces').resolve()
    capture=(root/nom_capture).resolve()
    if capture.parent!=root or not capture.is_file() or capture.stat().st_size>32*1024*1024:
        raise ValueError('capture_absente')
    client=getattr(coordinator,'client',None)
    cache=getattr(client,'_tuya_oem_inventory_cache',{})
    devices=cache.get('devices',{}) if isinstance(cache,dict) else {}
    data=getattr(coordinator,'data',None)
    if not isinstance(devices,dict) or not isinstance(data,dict):raise ValueError('inventaire_absent')
    rows=[item for item in data.values() if isinstance(item,dict)
          and item.get('model')=='H1L' and item.get('is_camera') is False]
    if len(rows)!=1:raise ValueError('station_ambigue')
    matches=[(did,dev) for did,dev in devices.items() if isinstance(dev,dict)
             and _match_name(dev,rows[0].get('name'))]
    if len(matches)!=1:raise ValueError('station_ambigue')
    station_id,station=matches[0]
    key=station.get('localKey')
    if not isinstance(key,str) or len(key.encode('utf-8'))!=16:raise ValueError('cle_station_absente')
    # Match the captured camera reference to one CURRENT, authenticated OEM
    # camera identity. This avoids dependence on ambiguous list sorting.
    camera_id=capture_camera_id_b142(data,client,devices,capture,ip,
                                    station_id,key.encode('utf-8'))
    plain=_record_first_auth(capture,ip,key.encode('utf-8'),station_id)
    if plain is None:raise ValueError('auth_capture_invalide')
    return plain,station_id,camera_id,devices
