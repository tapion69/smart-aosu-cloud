"""Explicit one-shot AOSU MQTT authorization *preparation* probe.

APK 5.10.12 classes16.dex, GzMqttAuthSdk.OooOOO ->
AuthWebService.OooO0O0 -> IService.OooO0O0(String, List).
The auth wrapper loads the exact literal string 'aws' before invoking IService;
this is POST /v1/sts/getMultiMqttInfo (type, sn[]).

The AOSU Gz MQTT authorization is NOT a Tuya OEM login, and does not establish
any video/PTZ session for C5L. Never log or return IDs, URLs, or credentials.
"""
from __future__ import annotations

import json
import time
import requests
from . import protocol_060 as proto

_ENDPOINT = "https://api-eu.aosulife.com/v1/sts/getMultiMqttInfo"
_AUTH_TYPE = "aws"  # Verified literal from official AOSU APK 5.10.12, classes16.dex
_MAX_REPLY = 131072
_MIN_INTERVAL = 3600
# These exact field *names* only may appear in the output. No dynamic key names.
_KEY_GROUPS = {
    "jeton_present": ("token", "mqttToken", "accessToken", "authToken", "sessionToken"),
    "hote_mqtt_present": ("mqttHost", "mqttServer", "mqttUrl", "mqttDomain", "mqttsUrl", "endpoint", "mqttEndpoint"),
    "canaux_presents": ("channelList", "channels", "mqttInfoList", "topicList", "mqttList"),
    "identifiant_rtm_present": ("rtmId", "rtmUid"),
}
# Field names are a fixed allowlist; arbitrary server keys must not be exposed.
_AUDITED_FIELDS = (
    "mqttInfoList", "mqttList", "topicList", "channelList", "channels",
    "token", "mqttToken", "clientId", "mqttHost", "mqttServer", "endpoint",
    "region", "list", "data", "url", "status", "code", "success", "expire",
)


def _kind(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "objet"
    if isinstance(value, list):
        return "liste"
    if isinstance(value, str):
        return "chaine"
    if type(value) is bool:
        return "booleen"
    if type(value) in (int, float):
        return "nombre"
    return "autre"


def inspect_safe_shape(data: object) -> dict[str, object]:
    """Bounded structure-only inspection. Never return user or server values.

    Detects both a truly empty response and an unrecognized but nonempty shape.
    Key names shown in the output come only from a hardcoded allowlist.
    """
    seen = {name: False for name in _KEY_GROUPS}
    recognized: set[str] = set()
    nodes = 0
    containers = 0
    fields = 0
    scalar_values = 0
    nonempty_scalars = 0
    stack = [(data, 0)]
    while stack and nodes < 160:
        node, depth = stack.pop()
        nodes += 1
        if isinstance(node, dict):
            containers += 1
            entries = list(node.items())[:50]
            fields += len(entries)
            for key, value in entries:
                if key in _AUDITED_FIELDS:
                    recognized.add(key)
                for name, keys in _KEY_GROUPS.items():
                    if key in keys and bool(value):
                        seen[name] = True
                if depth < 5 and isinstance(value, (dict, list)):
                    stack.append((value, depth + 1))
                elif not isinstance(value, (dict, list)):
                    scalar_values += 1
                    nonempty_scalars += bool(value)
        elif isinstance(node, list):
            containers += 1
            if depth < 5:
                stack.extend((value, depth + 1) for value in node[:30])
        else:
            scalar_values += 1
            nonempty_scalars += bool(node)
    shape = "vide" if data is None or data == {} or data == [] else "non_vide"
    return {
        "type_donnees": _kind(data),
        "structure": shape,
        "racine_elements": min(len(data), 1000) if isinstance(data, (dict, list)) else 0,
        "conteneurs_examines": containers,
        "champs_examines": fields,
        "scalaires_examines": scalar_values,
        "scalaires_non_vides": nonempty_scalars,
        "champs_reconnus": sorted(recognized),
        "indices": seen,
        "inspection_limitee": bool(stack),
    }


def run_mqtt_auth_probe(client: object) -> dict[str, object]:
    """Exactly zero or one signed POST, manually triggered in Home Assistant."""
    common = {
        "diagnostic": "aosu_mqtt_authorisation_0_8_9b5",
        "type_apk": _AUTH_TYPE,
        "type_confirme_par_bytecode_apk": True,
        "c5l_plateforme_p2p_attendue": "Ty",
        "appel_reseau": 0,
        "connexion_oem_tuya_authentifiee": False,
        "session_video_creee": False,
        "commande_camera": 0,
        "secrets_retournes": False,
    }
    with client._dp_lock:
        now = time.monotonic()
        last = getattr(client, "_last_mqtt_auth_probe", 0.0)
        if last and now - last < _MIN_INTERVAL:
            return {**common, "etat": "limite_une_fois_par_heure"}
        sn = getattr(client, "_c5l_sn", None)
        if not isinstance(sn, str) or not 0 < len(sn) <= 256:
            return {**common, "etat": "c5l_absente_du_cache"}
        if (not getattr(client, "_sid", None) or not getattr(client, "_uid", None)
                or not getattr(client, "_login_headers", None)
                or not getattr(client, "_suffix", None)):
            return {**common, "etat": "session_aosu_indisponible"}
        client._last_mqtt_auth_probe = now
        try:
            params, headers = proto.build_device_list_request(
                client._suffix, client._login_headers, client._sid, client._uid
            )
            headers = dict(headers)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            form = [("type", _AUTH_TYPE), ("sn[]", sn)]
            with client.session.post(
                _ENDPOINT, params=params, data=form, headers=headers,
                timeout=(8, 15), allow_redirects=False, verify=True, stream=True
            ) as response:
                status = response.status_code
                if type(status) is not int or status != 200:
                    return {**common, "appel_reseau": 1, "etat": "http_non_200",
                            "statut_http": status if type(status) is int and 100 <= status <= 599 else None}
                raw = response.raw.read(_MAX_REPLY + 1, decode_content=True)
                if len(raw) > _MAX_REPLY:
                    return {**common, "appel_reseau": 1, "etat": "reponse_trop_grande"}
                result = json.loads(raw)
        except (requests.RequestException, OSError, ValueError, TypeError, AttributeError):
            return {**common, "appel_reseau": 1, "etat": "erreur_reseau_ou_format"}
        if not isinstance(result, dict) or type(result.get("errno")) is not int:
            return {**common, "appel_reseau": 1, "etat": "reponse_non_reconnue"}
        errno = result["errno"]
        safe_errno = errno if -999999 <= errno <= 999999 else None
        if errno != 0:
            return {**common, "appel_reseau": 1, "etat": "refus_aosu", "errno": safe_errno,
                    "note": "Parametre aws verifie dans le code de l'application; refus de la requete."}
        return {**common, "appel_reseau": 1, "etat": "reponse_aosu_acceptee", "errno": 0,
                "resultat": inspect_safe_shape(result.get("data")),
                "note": "Le type aws est confirme par l'APK, mais ce canal Gz/AWS n'est pas un login Tuya OEM."}
