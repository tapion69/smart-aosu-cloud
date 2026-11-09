"""Unofficial AOSU cloud client. No commands, stream API or raw response logging.

Only intended for personal use with an APK supplied by its owner.
"""
from __future__ import annotations
import hashlib
import json
import time
import re
import threading
from pathlib import Path
from typing import Any
import requests
from .const import APK_PATH, PROFILE_PATH
from .profile_bootstrap import ensure_profile
from . import protocol_060 as proto
from .transport_audit import platform_from_support, tuya_reference_status
from .semantics import parse_cover_event_time
from .oem_identity import extract_login_hints, inspect_login_hints, public_report
from .event_feed import get_recent_event_feed
from .provider_audit import summarize_getlist_provider
from .c9c_cp_reference_b32 import extract_c9c_cp_reference

class AosuCloudError(Exception):
    """Protocol/network failure without potentially sensitive server contents."""


def load_profile(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise AosuCloudError("Profil Android absent ou illisible") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise AosuCloudError("Version du profil Android inconnue")
    p = data.get("android_properties")
    extra = data.get("additional_headers")
    if not isinstance(p,dict) or not isinstance(extra,dict):
        raise AosuCloudError("Profil Android incomplet")
    if set(p) != {"Gz-OsVer", "Gz-Brand", "Gz-Model", "Gz-FontSize"}:
        raise AosuCloudError("Quatre propriétés Android obligatoires")
    if set(extra) != {"Gz-Imei","Gz-Network","Gz-NotifyPermission"}:
        raise AosuCloudError("Trois en-têtes Android obligatoires")
    for v in list(p.values())+list(extra.values()):
        if not isinstance(v,str) or not v or len(v)>8192 or "\r" in v or "\n" in v:
            raise AosuCloudError("Champ de profil invalide")
    return data


def normalize_devices(payload: dict) -> dict[str,dict[str,Any]]:
    """Only expose safe attributes; SN used transiently to build hashed unique IDs."""
    if not isinstance(payload,dict) or payload.get("errno") != 0:
        raise AosuCloudError("Liste refusée par le service")
    response = payload.get("data")
    records = response.get("list") if isinstance(response,dict) else None
    if not isinstance(records,list) or len(records)>100:
        raise AosuCloudError("Format de liste non reconnu")
    cleaned={}
    serial_to_key={}
    for r in records:
        if not isinstance(r,dict):
            continue
        sn=r.get("sn")
        if not isinstance(sn,str) or not sn or len(sn)>256:
            continue
        key=hashlib.sha256(("aosu-device:"+sn).encode()).hexdigest()[:32]
        serial_to_key[sn]=key
        # Cache only a safe enum, never raw vendor metadata or private IDs.
        iot_branch, svc_status = platform_from_support(r.get("support"))
        cleaned[key]={"ptz_iot_platform":iot_branch,"ptz_svc_status":svc_status,
                     "ptz_tuya_reference_status":tuya_reference_status(r),
                     "key":key, "name":_safe_str(r.get("name")) or _safe_str(r.get("model")) or "AOSU",
                     "model": _safe_str(r.get("model")) or _safe_str(r.get("modelAlias")) or "AOSU",
                     "online":_number_or_none(r.get("online")),
                     "device_type":_number_or_none(r.get("devType")),
                     "electricity":None,"wifi_signal":None,"power_mode":None,"via_device":None,
                     "is_camera":(_safe_str(r.get("model")) or "").upper() != "H1L",
                     "has_image_ref":False,"image_revision":None}
        # 0.7.5: last event *timestamp* supplied by the already fetched
        # inventory, not an independently verified motion/person detection.
        # No snapshot URL is stored and no new request is made.
        cover = r.get("coverInfo")
        cleaned[key]["cover_event_time"] = (
            parse_cover_event_time(cover.get("eventTime"))
            if isinstance(cover, dict) else None
        )
        cleaned[key]["has_image_ref"] = bool(
            isinstance(cover, dict) and isinstance(cover.get("imageUrl"), str)
            and cover.get("imageUrl") and cleaned[key]["is_camera"]
        )
        # A private digest (not the signed URL) lets always_update=False
        # notify image entities when just the signed URL changes.
        if cleaned[key]["has_image_ref"]:
            cleaned[key]["image_revision"] = hashlib.sha256(
                cover["imageUrl"].encode("utf-8")
            ).hexdigest()[:24]
        x=r.get("extend")
        if isinstance(x,dict):
            cleaned[key]["electricity"]=_number_or_none(x.get("electricity"))
            cleaned[key]["wifi_signal"]=_number_or_none(x.get("wifi_signal"))
            cleaned[key]["power_mode"]=_safe_str(x.get("power_mode"))
    for r in records:
        if not isinstance(r,dict):
            continue
        sn,base=r.get("sn"),r.get("baseSn")
        child=serial_to_key.get(sn) if isinstance(sn,str) else None
        parent=serial_to_key.get(base) if isinstance(base,str) else None
        if child and parent and child != parent:
            cleaned[child]["via_device"]=parent
    return cleaned


def _safe_str(v):
    return v[:100] if isinstance(v,str) and v.strip() else None


def _number_or_none(v):
    if type(v) in (int,float) and abs(v)<100000000:
        return v
    return None


class AosuCloudClient:
    def __init__(self,email:str,password:str,apk_path=APK_PATH,profile_path=PROFILE_PATH):
        self.email=email;self.password=password
        self.apk_path=Path(apk_path);self.profile_path=Path(profile_path)
        self.session=requests.Session()
        self.session.headers.clear()
        self.session.trust_env=False
        self._material=None;self._suffix=None;self._profile=None
        self._sid=None;self._uid=None;self._login_headers=None
        self._oem_identity_hints=None  # RAM only; never log/export
        self._oem_login_flags=None  # safe booleans from last successful AOSU login
        self._last_login_attempt=0.0
        self._dp_lock=threading.Lock()
        self._last_dp_probe=0.0
        self._device_sn_index=[]  # RAM only; never log or store on disk
        self._camera_sn_index=[]  # 3 cameras, excluding the H1L base
        self._standalone_c9c_sn=None  # RAM only; candidate for explicit VIDEO test
        self._standalone_c9c_coop_id=None  # RAM only, never published
        self._standalone_c9c_cp_source='absente'  # safe enum, not an ID
        self._c5l_sn=None  # private RAM-only target for manual discovery
        self._c5l_coop_present=False
        self._c5l_coop_id=None  # private RAM-only, never exposed in diagnostics
        self._c5l_name=None  # private RAM-only, for non-authoritative name comparison
        self._last_identity_probe=0.0
        self._last_mqtt_auth_probe=0.0  # opt-in AOSU video signaling preparation only
        self._image_urls={}  # private image URLs in RAM only, keyed by stable device hash
        self._cover_time_by_sn={}  # private raw times for optional read-only event diagnostics
        self._recent_events={}  # safe timestamp and raw type only; never images or IDs
        self._last_recent_poll=0.0
        self._recent_missing_cursor=0  # fair rotation if all 3 cameras absent from grouped list
        self._cached_metadata=None  # only sanitized structure, no raw server values
        self._provider_snapshot=None  # non-sensitive provider field presence only
        self._metadata_updated_monotonic=None

    def _prepare(self):
        if self._material is not None:
            return
        try:
            ensure_profile(self.profile_path)
        except OSError as exc:
            raise AosuCloudError("Impossible de creer le profil Android local") from exc
        self._profile=load_profile(self.profile_path)
        try:
            native,dex=proto.read_apk_parts(self.apk_path)
            material=native[proto.KEY_OFFSET:proto.KEY_OFFSET+16]
            suffix=proto.get_sign_suffix(dex)
            if proto.check_vectors(material)!=(4,4):
                raise AosuCloudError("Vérification cryptographique en échec")
        except (OSError,ValueError,KeyError,IndexError) as exc:
            raise AosuCloudError("Bundle APK incorrect ou incomplet") from exc
        self._material=material;self._suffix=suffix

    def _post(self,target,params,data,headers,limit):
        try:
            res=self.session.post(target,params=params,data=data,headers=headers,
                                  timeout=(8,20),allow_redirects=False,verify=True)
            if res.status_code!=200 or len(res.content)>limit:
                raise AosuCloudError("Réponse HTTP inattendue")
            payload=res.json()
        except (requests.RequestException,ValueError) as exc:
            raise AosuCloudError("Échec réseau ou JSON") from exc
        if not isinstance(payload,dict) or type(payload.get("errno")) is not int:
            raise AosuCloudError("Réponse AOSU mal formée")
        if payload["errno"] != 0:
            raise AosuCloudError("Refus AOSU (code applicatif non nul)")
        return payload

    def _login(self):
        # Avoid login storms if an account/session is refused, including after reloads
        now=time.monotonic()
        if self._last_login_attempt and now-self._last_login_attempt<3600:
            raise AosuCloudError("Nouvelle connexion limitée à une par heure")
        self._last_login_attempt=now
        # Old UID hints must never outlive an attempted replacement login.
        self._oem_identity_hints=None
        self._oem_login_flags=None
        p=self._profile
        params,form,headers=proto.build_request_values(
            self._material,self._suffix,self.email,self.password,
            android_properties=p["android_properties"],additional_headers=p["additional_headers"])
        payload=self._post(proto.TARGET,params,form,headers,65536)
        details=payload.get("data")
        if not isinstance(details,dict) or not isinstance(details.get("sid"),str) or not details["sid"]:
            raise AosuCloudError("SID absent dans la réponse AOSU")
        if not isinstance(details.get("uid"),(str,int)) or not str(details["uid"]):
            raise AosuCloudError("UID absent")
        self._sid=details["sid"];self._uid=str(details["uid"])
        self._oem_identity_hints=extract_login_hints(details)
        self._oem_login_flags=inspect_login_hints(details)
        self._login_headers=headers

    def refresh(self):
        self._prepare()
        if not self._sid:
            self._login()
        params,headers=proto.build_device_list_request(self._suffix,self._login_headers,self._sid,self._uid)
        try:
            data=self._post(proto.DEVICE_LIST_TARGET,params,b"",headers,262144)
            normalized=normalize_devices(data)
            records=data.get("data",{}).get("list",[])
            # Schema derived from the authenticated inventory response already fetched.
            # Never cache any raw nested values, identifiers, account data or image URLs.
            self._cached_metadata=summarize_cached_metadata(records)
            self._provider_snapshot=summarize_getlist_provider(records)
            self._metadata_updated_monotonic=time.monotonic()
            # Thumbnail URLs are private and must not enter coordinator.data, HA
            # state attributes, diagnostic output or logs. Keep transiently in RAM.
            private_urls = {}
            private_cover_times = {}
            cameras = []
            for item in records:
                if not isinstance(item, dict):
                    continue
                sn = item.get("sn")
                if not isinstance(sn, str) or not sn or len(sn)>256:
                    continue
                key = hashlib.sha256(("aosu-device:"+sn).encode()).hexdigest()[:32]
                if key not in normalized or not normalized[key]["is_camera"]:
                    continue
                cameras.append(sn)
                cover = item.get("coverInfo")
                if isinstance(cover, dict):
                    when = cover.get("eventTime")
                    if parse_cover_event_time(when) is not None:
                        private_cover_times[sn] = when
                    url = cover.get("imageUrl")
                    if isinstance(url, str) and url:
                        private_urls[key] = url
            self._image_urls = private_urls
            self._cover_time_by_sn = private_cover_times
            self._camera_sn_index = cameras[:10]
            # Single autonomous C9C: never treat it as the C5L or an H1L child.
            # Retain exact identifiers only in RAM for a manually confirmed
            # video-only P2P experiment; never expose them in HA entities.
            standalone = [r for r in records if isinstance(r,dict)
                and str(r.get('model') or '').strip().upper() == 'C9C'
                and isinstance(r.get('sn'),str) and r['sn'] in cameras]
            if len(cameras)==1 and len(standalone)==1 and not any(
                    isinstance(r,dict) and str(r.get('model') or '').strip().upper()=='H1L'
                    for r in records):
                self._standalone_c9c_sn=standalone[0]['sn']
                # The Android SDK maps coopUUID to GzDeviceInfo.cpDeviceId.
                # Use only this SN-matched AOSU record, never guessed IDs.
                private_cp,cp_source=extract_c9c_cp_reference(standalone[0])
                self._standalone_c9c_coop_id=private_cp
                self._standalone_c9c_cp_source=cp_source
            else:
                self._standalone_c9c_sn=None
                self._standalone_c9c_coop_id=None
                self._standalone_c9c_cp_source='absente'
            # One private target for the opt-in read-only identity audit.
            # APK conversion path: UUIDInfoWebDataItem.coopUUID -> GzDeviceInfo.cpDeviceId.
            c5l = [r for r in records if isinstance(r,dict) and r.get('model')=='C5L'
                   and isinstance(r.get('sn'),str) and r.get('sn') in cameras]
            self._c5l_sn = c5l[0]['sn'] if len(c5l)==1 else None
            self._c5l_coop_present = bool(self._c5l_sn and isinstance(c5l[0].get('coopUUID'),str)
                                          and c5l[0]['coopUUID'].strip())
            self._c5l_coop_id = c5l[0]['coopUUID'] if self._c5l_coop_present else None
            self._c5l_name = c5l[0].get('name') if len(c5l)==1 and isinstance(c5l[0].get('name'),str) else None
            # v0.8.4: grouped list first, then query ALL missing cameras
            # individually in the same window. Real AOSU responses confirmed
            # sn[] filtering. Bound event POSTs to <=3 per 5 min
            # (one grouped + at most two targeted), never after other failures.
            # Inventory and thumbnails continue even if the event API fails.
            now = time.monotonic()
            if not self._last_recent_poll or now - self._last_recent_poll >= 300:
                self._last_recent_poll = now
                with self._dp_lock:
                    try:
                        recent = get_recent_event_feed(self, self._camera_sn_index)
                    except Exception:
                        recent = None
                    if recent is not None:
                        for key, value in recent.items():
                            old = self._recent_events.get(key)
                            if old is None or value['recent_event_time'] >= old['recent_event_time']:
                                self._recent_events[key] = value
                        # The first 10 records may all belong to one camera.
                        # Query the remaining cameras independently *now*,
                        # rather than rotating one missing camera every 5 min.
                        missing = [sn for sn in self._camera_sn_index if
                                   hashlib.sha256(('aosu-device:' + sn).encode()).hexdigest()[:32]
                                   not in recent]
                        # Hard cap total event POSTs at 3 per window even
                        # when unexpected devices appear in the inventory.
                        if len(missing) > 2:
                            # A valid but empty grouped list must not starve the
                            # third camera forever: rotate the pair we probe.
                            offset = self._recent_missing_cursor % len(missing)
                            selected = [missing[(offset + i) % len(missing)] for i in range(2)]
                            self._recent_missing_cursor = (offset + 2) % len(missing)
                        else:
                            selected = missing
                        for sn in selected:
                            try:
                                targeted = get_recent_event_feed(self, [sn])
                            except Exception:
                                targeted = None
                            if targeted:
                                for key, value in targeted.items():
                                    old = self._recent_events.get(key)
                                    if old is None or value['recent_event_time'] >= old['recent_event_time']:
                                        self._recent_events[key] = value
            # Add ONLY sanitized values; the coordinator contains no event IDs,
            # serials, private image URLs or customer AI payloads.
            for key, device in normalized.items():
                if device.get('is_camera'):
                    info = self._recent_events.get(key)
                    device['recent_event_time'] = info.get('recent_event_time') if info else None
                    device['recent_event_type'] = info.get('recent_event_type') if info else None
            # Only retain opaque SNs in RAM for explicit, manual read-only DP diagnostics.
            self._device_sn_index=[r["sn"] for r in records if isinstance(r,dict) and isinstance(r.get("sn"),str) and 0 < len(r["sn"]) <= 256][:10]
            return normalized
        except AosuCloudError:
            # Never immediately relogin/retry: protects account from bursts.
            self._sid=None;self._uid=None;self._login_headers=None
            self._oem_identity_hints=None
            self._oem_login_flags=None
            raise

    def inspect_oem_uid_status(self):
        """No network; no UID/user/password/token ever exposed."""
        return public_report(self._oem_login_flags)

    def get_image_url(self, key):
        """Internal-only lookup; never expose result through entity attributes."""
        return self._image_urls.get(key)

    def close(self):
        self._provider_snapshot=None
        self._image_urls.clear()
        self._cover_time_by_sn.clear()
        self._camera_sn_index.clear()
        self._standalone_c9c_sn=None
        self._standalone_c9c_coop_id=None
        self._standalone_c9c_cp_source='absente'
        self._c5l_sn=None
        self._c5l_coop_present=False
        self._c5l_coop_id=None  # private RAM-only, never exposed in diagnostics
        self._c5l_name=None  # private RAM-only, for non-authoritative name comparison
        self._oem_identity_hints=None
        self._oem_login_flags=None
        self._recent_events.clear()
        self.session.close()
        self._sid=None;self._uid=None


# The current /v1/dp/getValues experiment returns errno=0 with data={} for the
# the configured devices. Rather than adding speculative DP requests, inspect only
# already received /v1/dev/getList metadata. No additional network activity.
# Keys below are literals verified in the real inventory schema; NEVER return
# arbitrary keys or raw values from an AOSU response.
_METADATA_FIELDS = {
    "appSetting": ("snooze",),
    "coverInfo": ("aiVision", "eventTime", "imageUrl", "levelInfo", "videoInfo"),
    "extend": ("electricity", "online_time", "power_mode", "sub_online_time", "upgrade_status", "wifi_signal"),
    "support": ("contractInfo", "baseSvcType", "cloudType", "svcType"),
}


def _limited_shape(value):
    """Describe container shape, never value, unknown name or identifier."""
    if isinstance(value, dict):
        categories={"objet":0,"liste":0,"texte":0,"nombre":0,"booleen":0,"nul":0,"autre":0}
        for subval in value.values():
            categories[_shape_kind(subval)] += 1
        return {"type":"objet", "nombre":min(len(value),10000),
                "types_enfants":{k:v for k,v in categories.items() if v}}
    if isinstance(value,list):
        counts={}
        for v in value[:50]:
            k=_shape_kind(v)
            counts[k]=counts.get(k,0)+1
        return {"type":"liste", "nombre":min(len(value),10000),
                "types_des_50_premiers":counts}
    return {"type":_shape_kind(value)}


def _shape_kind(value):
    if value is None: return "nul"
    if isinstance(value,bool): return "booleen"
    if type(value) in (int,float): return "nombre"
    if isinstance(value,str): return "texte"
    if isinstance(value,dict): return "objet"
    if isinstance(value,list): return "liste"
    return "autre"


def _event_time_format(value):
    # Classification of timestamp representation, never the timestamp itself.
    if type(value) not in (int,float) or value <= 0:
        return "absent_ou_inconnu"
    if 1_000_000_000 <= value <= 30_000_000_000:
        return "probablement_secondes_unix"
    if 1_000_000_000_000 <= value <= 30_000_000_000_000:
        return "probablement_millisecondes_unix"
    return "format_non_reconnu"


def summarize_cached_metadata(records):
    """Summarize getList safely. No SN, name, URL, tokens or values are returned."""
    if not isinstance(records,list):
        raise AosuCloudError("Inventaire indisponible")
    reports=[]
    for i, item in enumerate(records[:20],1):
        if not isinstance(item,dict):
            continue
        info={"numero_temporaire":i,"groupes":{}}
        for group, allowed in _METADATA_FIELDS.items():
            raw=item.get(group)
            if not isinstance(raw,dict):
                continue
            group_info={}
            for field in allowed:
                if field not in raw:
                    continue
                # Only predefined path names, types and container sizes are exposed.
                group_info[field]=_limited_shape(raw[field])
            info["groupes"][group]=group_info
        cover=item.get("coverInfo")
        if isinstance(cover,dict):
            info["evenement_format"]=_event_time_format(cover.get("eventTime"))
            info["miniature_reference_presente"]=bool(isinstance(cover.get("imageUrl"),str) and cover["imageUrl"])
        reports.append(info)
    return {"resultat":"structure_cachee","source":"/v1/dev/getList",
            "aucun_appel_http_supplementaire":True,
            "nombre_appareils":len(records),"appareils":reports}


def _inspect_cached_metadata(self):
    # Cached summary is *already sanitized* when saved during polling.
    if self._cached_metadata is None or self._metadata_updated_monotonic is None:
        raise AosuCloudError("Inventaire non disponible : attendre la prochaine actualisation")
    import copy
    result=copy.deepcopy(self._cached_metadata)
    result["age_secondes"]=max(0,int(time.monotonic()-self._metadata_updated_monotonic))
    return result

AosuCloudClient.inspect_cached_metadata = _inspect_cached_metadata

# Experimental diagnostic, manual only; IoT API uses a different interceptor stack.
# No camera commands are ever sent. Response values and opaque identifiers never leave RAM.
_DP_NAME = re.compile(r"(?:[A-Za-z][A-Za-z0-9_]{0,39}|[0-9]{1,4})\Z")
_DP_DENY = frozenset({"sn", "sid", "uid", "password", "token", "email", "name", "url", "ip", "imei", "deviceid", "secret", "key"})

def _kind(value):
    if value is None: return "null"
    if isinstance(value, bool): return "bool"
    if type(value) in (int,float): return "number"
    if isinstance(value, str): return "string"
    if isinstance(value, list): return "array"
    if isinstance(value, dict): return "object"
    return "other"


def _safe_dp_name(value):
    if isinstance(value, (str,int)) and not isinstance(value, bool):
        name=str(value)
        if _DP_NAME.fullmatch(name) and name.lower() not in _DP_DENY:
            return name
    return None


# Names below are source-code literals, never names copied from an HTTP response.
# Unknown keys may contain serial numbers, camera names, addresses or session data.
_SAFE_STRUCTURE_KEYS = frozenset({
    "data", "list", "values", "dps", "dpValues", "dpData", "dpList", "dpMap",
    "items", "records", "result", "results", "devices", "deviceList",
    "params", "settings", "fields", "fieldValues", "dp", "dpId", "dpCode",
    "code", "value", "type", "status", "success", "online", "id"
})


def _safe_structure(raw, device_serials):
    """Summarize JSON *shape* only. Never return actual dynamic keys or values.

    Explore just the first two array items, five levels, max 50 nodes.
    Devices are numbered by an internal index, not by their serial numbers.
    """
    serial_positions = {sn: i + 1 for i, sn in enumerate(device_serials)
                        if isinstance(sn, str)}
    nodes = []

    def walk(obj, path, depth):
        if len(nodes) >= 50:
            return
        kind = _kind(obj)
        node = {"chemin": path, "type": kind}
        if isinstance(obj, (dict, list)):
            node["nombre_elements"] = min(len(obj), 10000)
            if isinstance(obj, dict):
                counts = {"objet":0, "liste":0, "texte":0, "nombre":0,
                          "booleen":0, "nul":0, "autre":0}
                translations = {"object":"objet", "array":"liste",
                                "string":"texte", "number":"nombre",
                                "bool":"booleen", "null":"nul"}
                for child in obj.values():
                    t = translations.get(_kind(child), "autre")
                    counts[t] += 1
                node["types_enfants"] = {k: v for k, v in counts.items() if v}
        nodes.append(node)
        if depth >= 5 or len(nodes) >= 50:
            return
        if isinstance(obj, dict):
            masked = 0
            for key, child in list(obj.items())[:25]:
                if len(nodes) >= 50:
                    break
                if isinstance(key, str) and key in serial_positions:
                    name = f"appareil_{serial_positions[key]}"
                elif isinstance(key, str) and key in _SAFE_STRUCTURE_KEYS:
                    name = key
                else:
                    masked += 1
                    name = f"cle_masquee_{masked}"
                walk(child, path + "." + name, depth + 1)
        elif isinstance(obj, list):
            for i, child in enumerate(obj[:2]):
                if len(nodes) >= 50:
                    break
                walk(child, f"{path}[{i}]", depth + 1)

    walk(raw, "$.data", 0)
    return nodes


def sanitized_dp_schema(payload, device_serials):
    """Only whitelisted *field names* and value types, not serials or values."""
    if not isinstance(payload, dict) or payload.get("errno") != 0:
        raise AosuCloudError("Service de lecture DP refuse par AOSU")
    raw=payload.get("data")
    if not isinstance(raw,(dict,list)):
        return {"resultat":"structure_inconnue", "type_data":_kind(raw), "noms_dp":[]}
    result=[]
    def add(name,v):
        safe=_safe_dp_name(name)
        if safe and len(result) < 80:
            result.append((safe, _kind(v)))
    def parse_dp_records(container):
        if isinstance(container,list):
            for record in container[:160]:
                if isinstance(record,dict):
                    for field in ("dp", "dpId", "dpCode", "code"):
                        if field in record:
                            # An explicit DP code is allowed only when it cannot be
                            # mistaken for an opaque camera serial from this session.
                            if record[field] not in device_serials:
                                add(record[field], record.get("value"))
                            break
        elif isinstance(container,dict):
            # Unknown dictionary keys may be serials, account labels, or IDs.
            # Never echo free-form string keys as DP names. Numeric DP IDs only.
            for field, val in list(container.items())[:160]:
                if (isinstance(field, (str, int)) and not isinstance(field, bool)
                        and re.fullmatch(r"[0-9]{1,4}", str(field))
                        and str(field) not in device_serials):
                    add(field, val)
    if isinstance(raw,dict):
        for serial in device_serials:
            if serial in raw:
                parse_dp_records(raw[serial])
        if not result:
            # AOSU may send a list nested under a generic key.
            for common in ("list","values","dps","data","dpValues"):
                if common in raw:
                    parse_dp_records(raw[common])
        if not result:
            # For an unknown schema, never expose its dynamic dictionary keys.
            return {"resultat":"structure_a_etudier", "type_data":"object", "noms_dp":[],
                    "structure": _safe_structure(raw, device_serials)}
    else:
        parse_dp_records(raw)
    result=sorted(set(result))[:80]
    return {"resultat":"lecture_reussie", "type_data":_kind(raw),
            "noms_dp":[{"dp":x,"type":y} for x,y in result],
            "nombre_noms":len(result)}


def _diagnostic_dp(self):
    """Exactly ONE signed HTTPS POST after a manually invoked HA action."""
    with self._dp_lock:
        now=time.monotonic()
        if self._last_dp_probe and now-self._last_dp_probe < 3600:
            raise AosuCloudError("Diagnostic DP limite a une tentative par heure")
        if not self._sid or not self._uid or not self._login_headers or not self._device_sn_index:
            raise AosuCloudError("Session ou liste d'appareils absente")
        # Enforced even if the server refuses: do not encourage repetitive tests.
        self._last_dp_probe=now
        params,headers=proto.build_device_list_request(self._suffix,self._login_headers,self._sid,self._uid)
        # Same domain proven for the business cloud. IoT channel may use another
        # host; therefore this call is an explicit experiment, not automatic.
        target="https://api-eu.aosulife.com/v1/dp/getValues"
        headers=dict(headers)
        headers["Content-Type"]="application/x-www-form-urlencoded"
        form=[("sn[]",sn) for sn in self._device_sn_index]
        try:
            response=self.session.post(target,params=params,data=form,headers=headers,
                                       timeout=(8,20),allow_redirects=False,verify=True)
            if response.status_code!=200 or len(response.content)>262144:
                raise AosuCloudError("Reponse HTTP inattendue du service IoT")
            payload=response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AosuCloudError("Lecture DP impossible (HTTP ou JSON)") from exc
        return sanitized_dp_schema(payload,self._device_sn_index)

AosuCloudClient.inspect_dp_schema = _diagnostic_dp
