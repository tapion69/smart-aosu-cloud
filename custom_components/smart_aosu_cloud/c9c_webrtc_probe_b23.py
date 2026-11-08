"""Offline comparison of alternate Tuya WebRTC metadata. No secret exported."""
from __future__ import annotations
import re
from typing import Any

_MSID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def _nodes(raw: Any) -> list[dict]:
    if not isinstance(raw,dict):
        return []
    roots=[raw]
    for name in ("data","result"):
        obj=raw.get(name)
        if isinstance(obj,dict):
            roots.append(obj)
            for sub in ("data","result"):
                inner=obj.get(sub)
                if isinstance(inner,dict):
                    roots.append(inner)
    nodes=[]
    for root in roots[:9]:
        nodes.append(root)
        for name in ("p2pConfig","webrtcConfig","mqttConfig","rtcConfig"):
            container=root.get(name)
            if isinstance(container,dict):
                nodes.append(container)
                sess=container.get("session")
                if isinstance(sess,dict):
                    nodes.append(sess)
    return nodes[:48]


def inspect_webrtc_hints(rtc: Any, device: Any) -> tuple[dict,str|None]:
    """Return an anonymous public report and an in-memory explicit msid."""
    msids=set()
    auth=False
    moto=False
    support=set()
    aes_kcp=False
    for node in _nodes(rtc):
        for key in ("msid","mSid","mqttSessionId"):
            val=node.get(key)
            if isinstance(val,str) and _MSID.fullmatch(val):
                msids.add(val)
        for key in ("auth","authToken"):
            val=node.get(key)
            auth |= isinstance(val,str) and 4<=len(val)<=4096
        for key in ("motoId","moto_id","motoID"):
            val=node.get(key)
            moto |= (isinstance(val,str) and 1<=len(val)<=128
                     and all(32<ord(c)<127 for c in val))
        for key in ("supportsWebrtc","supportWebrtc"):
            val=node.get(key)
            if type(val) is bool:
                support.add(val)
        sess=node.get("session")
        aes_kcp |= isinstance(sess,dict) and isinstance(sess.get("aesKey"),str)
    if isinstance(device,dict):
        for key in ("supportsWebrtc","supportWebrtc"):
            val=device.get(key)
            if type(val) is bool:
                support.add(val)
    msid=next(iter(msids)) if len(msids)==1 else None
    report={
        "lecture_seule":True,"source_rtc":"ipc_v4",
        "moto_id_present":moto,"auth_webrtc_present":auth,
        "msid_explicite_present":msid is not None,
        "msid_ambigu":len(msids)>1,
        "webrtc_declare_oui":support=={True},
        "webrtc_declare_non":support=={False},
        "webrtc_declaration_ambigue":len(support)>1,
        "ipc_aes_kcp_present":aes_kcp,
        "offre_webrtc_preparee":False,
        "signalisation_webrtc_confirmee":False,
        "abonnement_mqtt_possible":msid is not None,
        "offres_envoyees":0,"commandes_camera":0,"commandes_ptz":0,
        "video_lancee":False,"identifiants_retournes":False,
        "secrets_retournes":False,
    }
    return report,msid
