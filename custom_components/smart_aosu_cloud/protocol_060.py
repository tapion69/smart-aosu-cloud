#!/usr/bin/env python3
"""Smart AOSU v0.6.0: diagnostic de reponse et requete de connexion de test, a usage personnel.

Aucune connexion par defaut. Une unique requete optionnelle apres accord explicite.
La bibliotheque, les parametres AES et le materiel de signature proviennent
exclusivement du bundle AOSU personnel passe par l'utilisateur.
Ne stocke ni mot de passe, ni jeton, ni reponse serveur.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
from io import BytesIO
from pathlib import Path
import re
import sys
import time
import uuid
import zipfile

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

LIB_SHA256 = '24caa3df3500d81106a65beda2703702494eb60a6af758b866585cbb577bfd68'
KEY_OFFSET = 0x18BC4
TARGET = 'https://api-eu.aosulife.com/v1/user/login'
SIGN_SEPARATOR = ':'  # Valeur verifiee dans ConfigPath.PATH_SEPARATOR de classes5.dex.
VECTORS = (
    ('A', 'aa32c6a93339abf8615c0dda37254282a533c75917bdcb26aa5463c34b1f738f'),
    ('Smart AOSU - test fictif 2026', 'ca09ad02f8c8a924f3a3ab3569af121aa28301b699bc8fe0943003162c5117eb'),
    ('Test de compatibilit\u00e9 \u00e8\u00e0 \u20ac 2026', '1be6710b6dc8be7e7bb6a7d944423ba5fe13dcb43a8923efb3101e65c55ed433'),
    ('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'ba55208d04755f5a736b20fc6f1cc388b7145bc9add5caf7343815be785f71f2'),
)


def read_apk_parts(path: Path) -> tuple[bytes, bytes]:
    """Ne traiter que le bundle reel avec base APK et split ARM64."""
    if not path.is_file():
        raise ValueError('Bundle introuvable. Glisse le fichier AOSU .apks.apk sur le BAT.')
    with zipfile.ZipFile(path) as bundle:
        names = set(bundle.namelist())
        if 'base.apk' not in names or 'split_config.arm64_v8a.apk' not in names:
            raise ValueError('Bundle AOSU complet requis (base.apk + split_config.arm64_v8a.apk).')
        with zipfile.ZipFile(BytesIO(bundle.read('base.apk'))) as base:
            dex = base.read('classes11.dex')
        with zipfile.ZipFile(BytesIO(bundle.read('split_config.arm64_v8a.apk'))) as split:
            binary = split.read('lib/arm64-v8a/libglazero-security.so')
    if hashlib.sha256(binary).hexdigest() != LIB_SHA256:
        raise ValueError('Binaire glazero-security different de la version 5.10.12 etudiee.')
    if b'api.aosulife.com' not in dex or b'Gz-Sign' not in dex:
        raise ValueError('Le module HTTP AOSU attendu est absent.')
    return binary, dex


def get_sign_suffix(dex: bytes) -> bytes:
    """Recupere la constante de signature de CET APK, sans la redistribuer."""
    # Le DEX garde les constantes String inline et terminees par 0.
    candidates = set(re.findall(rb'&s[^\x00\x0a\x0d]{30}\x00', dex))
    accepted = [v[:-1] for v in candidates if len(v) == 33 and b'^' in v and b'**' in v]
    if len(accepted) != 1:
        raise ValueError('Constante de signature non reconnue dans cet APK.')
    return accepted[0]


def encrypt_password(data: bytes, material: bytes) -> str:
    p = padding.PKCS7(128).padder()
    padded = p.update(data) + p.finalize()
    c = Cipher(algorithms.AES(material), modes.CBC(material)).encryptor()
    encrypted = c.update(padded) + c.finalize()
    return base64.b64encode(encrypted).decode('ascii')


def check_vectors(material: bytes) -> tuple[int, int]:
    passed = 0
    for plain, expected in VECTORS:
        out = encrypt_password(plain.encode('utf-8'), material)
        actual = hashlib.sha256(base64.b64decode(out)).hexdigest()
        passed += actual == expected
    return passed, len(VECTORS)


def build_signature(request_id: str, milliseconds: str, suffix: bytes) -> str:
    content = f'uuid:{request_id}:t:{milliseconds}{SIGN_SEPARATOR}'.encode('utf-8') + suffix
    return hashlib.md5(content).hexdigest()


def local_timezone_offset() -> str:
    """Offset d Europe/Paris a l instant present, pas lu sur Android."""
    from datetime import datetime
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    try:
        value = datetime.now(ZoneInfo('Europe/Paris')).strftime('%z')
    except ZoneInfoNotFoundError as exc:
        raise ValueError('Donnees horaires absentes : lance INSTALLER_DEPENDANCES.bat (tzdata).') from exc
    if not re.fullmatch(r'[+-]\d{4}', value):
        raise ValueError('Decalage horaire Paris non reconnu.')
    return value[:3] + ':' + value[3:]


def safe_adb_properties() -> dict[str, str]:
    """Lectures ADB facultatives, non sensibles: SDK, marque, modele, echelle police.

    Jamais d Android ID, de numero de serie ou de preferences AOSU.
    Aucun resultat affiche ni sauvegarde; seulement utilise lors d un POST confirme.
    """
    import shutil
    import subprocess
    exe = shutil.which('adb')
    if exe is None:
        print('[ADB] Introuvable. Aucune donnee Android lue.')
        return {}

    def command(*args: str) -> str:
        try:
            proc = subprocess.run([exe, *args], capture_output=True,
                                  text=True, timeout=6, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return ''
        if proc.returncode != 0:
            return ''
        return proc.stdout.strip()

    raw = command('devices')
    devices = [ln for ln in raw.splitlines()[1:] if ln.strip().endswith('\tdevice')]
    if len(devices) != 1:
        print('[ADB] Il faut un seul appareil USB autorise; profil ignore.')
        return {}
    source = {
        'Gz-OsVer': command('-s', devices[0].split('\t')[0], 'shell', 'getprop', 'ro.build.version.sdk'),
        'Gz-Brand': command('-s', devices[0].split('\t')[0], 'shell', 'getprop', 'ro.product.brand'),
        'Gz-Model': command('-s', devices[0].split('\t')[0], 'shell', 'getprop', 'ro.product.model'),
        'Gz-FontSize': command('-s', devices[0].split('\t')[0], 'shell', 'settings', 'get', 'system', 'font_scale'),
    }
    # Ne pas afficher de valeurs, meme les plus anodines ; rester conservateur.
    profile = {}
    sdk = source['Gz-OsVer']
    if sdk.isdigit() and 16 <= int(sdk) <= 100:
        profile['Gz-OsVer'] = sdk
    for key in ('Gz-Brand', 'Gz-Model'):
        value = source[key]
        if value and len(value) <= 80 and re.fullmatch(r'[A-Za-z0-9_ .+\-/()]+', value):
            profile[key] = value
    raw_scale = source['Gz-FontSize']
    try:
        val = float(raw_scale)
        if 0.5 <= val <= 3.0:
            profile['Gz-FontSize'] = str(val)
    except (ValueError, TypeError):
        pass
    print('[ADB] Champs environnement Android lus : ' + str(len(profile)) +
          ' (valeurs non affichees, non enregistrees).')
    return profile



# === EN-TETES ANDROID EXPERIMENTAUX ===
# Le format des Maps vient du bytecode AOSU 5.10.12. Les valeurs sont
# des estimations explicites, PAS celles confirmees de l'app officielle.
# Aucun identifiant Android / IMEI / token n'est lu par ADB.


def java_boolean(val: bool) -> str:
    return 'true' if val else 'false'


def java_map(mapping: dict) -> str:
    """Java LinkedHashMap.toString(): ordre preserve, booleens minuscules."""
    def v(item):
        if isinstance(item, dict):
            return java_map(item)
        if type(item) is bool:
            return java_boolean(item)
        return 'null' if item is None else str(item)
    return '{' + ', '.join(str(k) + '=' + v(value) for k, value in mapping.items()) + '}'


def simulated_network(ip: str, wifi: bool, vpn: bool, available: bool) -> str:
    """NetworkUtils.OooO00o(): vpn, wifi=bool+InetAddress, available."""
    import ipaddress
    if wifi:
        address = str(ipaddress.IPv4Address(ip))
        inet = '/' + address  # InetAddress.toString() sans nom d'hote
    else:
        inet = 'null'  # Valeur a confirmer selon le telephone et les transports
    return java_map({
        'vpn': vpn,
        'wifi': java_boolean(wifi) + inet,
        'available': available,
    })


def simulated_notifications(filter_mode: str, channels: dict, groups: dict,
                            enabled: bool, paused: bool, bubbles: bool) -> str:
    """SystemNotificationUtils: structure des six cles ; valeurs estimees."""
    from urllib.parse import quote_plus
    if filter_mode not in ('ALL', 'PRIORITY', 'NONE', 'ALARMS', 'UNKNOWN'):
        raise ValueError('Filtre notification non reconnu.')
    names = {quote_plus(str(k), encoding='utf-8'): int(v) for k, v in channels.items()}
    group_names = {quote_plus(str(k), encoding='utf-8'): bool(v) for k, v in groups.items()}
    return java_map({
        'filter': filter_mode,
        'channels': names,
        'channelGroups': group_names,
        'enabled': java_boolean(enabled),
        'paused': java_boolean(paused),
        'BubblesAllowed': java_boolean(bubbles),
    })


def get_or_create_local_id() -> str:
    """Identifiant ALEATOIRE stable propre a ce client, jamais celui de AOSU."""
    import secrets
    import os
    path = Path(__file__).resolve().parent / '.smart_aosu_local_client_id'
    if path.exists():
        val = path.read_text(encoding='ascii').strip()
        if not re.fullmatch('[a-f0-9]{16}', val):
            raise ValueError('Fichier identifiant local invalide : supprimer ou reparer localement.')
        return val
    val = secrets.token_hex(8)
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w', encoding='ascii') as f:
        f.write(val + '\n')
    return val


def safe_phone_environment() -> dict:
    """ADB uniquement metadonnees reseau non secrètes, jamais ID/jeton."""
    import shutil
    import subprocess
    exe = shutil.which('adb')
    if exe is None:
        print('[ANDROID] ADB absent : impossible de lire le reseau du telephone.')
        return {}
    def run(*args):
        try:
            p = subprocess.run([exe, *args], capture_output=True, text=True,
                               timeout=8, check=False)
            return p.stdout.strip() if p.returncode == 0 else ''
        except (OSError, subprocess.TimeoutExpired):
            return ''
    raw = run('devices')
    devices = [ln.split('\t')[0] for ln in raw.splitlines()[1:] if ln.endswith('\tdevice')]
    if len(devices) != 1:
        print('[ANDROID] Un seul telephone autorise est necessaire.')
        return {}
    serial = devices[0]  # Jamais affiche/sauvegarde
    def shell(*args): return run('-s', serial, 'shell', *args)
    # Ne fait aucun appel Internet ; interroge la configuration locale du Wi-Fi.
    ip_info = shell('ip', '-4', 'addr', 'show', 'dev', 'wlan0')
    match = re.search(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d{1,2}', ip_info)
    ip = match.group(1) if match else ''
    if ip:
        import ipaddress
        try: ipaddress.IPv4Address(ip)
        except ValueError: ip = ''
    zen = shell('settings', 'get', 'global', 'zen_mode')
    filters = {'0':'ALL', '1':'PRIORITY', '2':'NONE', '3':'ALARMS'}
    print('[ANDROID] Wi-Fi IPv4 detecte :', 'oui' if ip else 'non')
    print('[ANDROID] Mode Ne pas deranger lu :', 'oui' if zen in filters else 'non')
    return {'ip': ip, 'filter': filters.get(zen, 'UNKNOWN')}


def ask_local_bool(label: str, default: bool | None = None) -> bool | None:
    suffix = '[o/N]' if default is False else ('[O/n]' if default is True else '[o/n]')
    value = input(label + ' ' + suffix + ' : ').strip().lower()
    if value in ('o', 'oui'): return True
    if value in ('n', 'non'): return False
    return default


def make_experimental_headers() -> dict | None:
    """Toutes les hypotheses sont consenties localement avant construction."""
    print('\n[ATTENTION] Profils experimentaux ; pas une copie des valeurs AOSU.')
    env = safe_phone_environment()
    if not env.get('ip'):
        print('[ARRET] IP Wi-Fi absente. Ne pas fabriquer la valeur Gz-Network.')
        return None
    vpn = ask_local_bool('VPN/Tailscale actif actuellement sur le Xiaomi ?', None)
    if vpn is None:
        print('[ARRET] Etat VPN inconnu.')
        return None
    enabled = ask_local_bool('Notifications AOSU autorisees actuellement ?', None)
    if enabled is None:
        print('[ARRET] Autorisation de notifications inconnue.')
        return None
    paused = ask_local_bool('Notifications AOSU mises en pause ?', False)
    bubbles = ask_local_bool('Bulles de notifications AOSU autorisees ?', False)
    if paused is None or bubbles is None:
        print('[ARRET] Information de notification inconnue.')
        return None
    filt = env['filter']
    print('[INCERTITUDE] Les canaux et groupes AOSU ne sont PAS lisibles de facon fiable.')
    print('[INCERTITUDE] channels={} et channelGroups={} sont des approximations.')
    print('[INCERTITUDE] available=true est estime car une IPv4 Wi-Fi existe.')
    print('[INCERTITUDE] paused/BubblesAllowed sont des indications saisies, non verifiees.')
    return {
        'Gz-Imei': get_or_create_local_id(),
        'Gz-Network': simulated_network(env['ip'], wifi=True, vpn=vpn, available=True),
        'Gz-NotifyPermission': simulated_notifications(filt, {}, {}, enabled, paused, bubbles),
    }


def build_request_values(material: bytes, suffix: bytes, email: str, password: str,
                         country_code: str = '33', country_abbr: str = 'FR',
                         android_properties: dict[str, str] | None = None,
                         additional_headers: dict[str, str] | None = None) -> tuple[dict, dict, dict]:
    """Reconstitution PARTIELLE ; ne jamais inventer l empreinte du telephone."""
    now = str(int(time.time() * 1000))
    req_id = str(uuid.uuid4())
    params = {'uuid': req_id, 't': now}
    form = {
        'region': 'EU', 'countryCode': country_code, 'countryAbbr': country_abbr,
        'type': '1', 'email': email.strip().lower(),
        'password': encrypt_password(password.encode('utf-8'), material),
        'pwType': '2',
    }
    headers = {
        'Gz-Pid': 'glazero',
        'Gz-OsType': 'android',
        'Gz-OsLang': 'fr-FR',  # Exemple FR, voir README
        'Gz-Lang': 'fr',      # Corrige d apres GzRegionUtils
        'Gz-Timezone': local_timezone_offset(),
        'Gz-TimezoneID': 'Europe/Paris',  # Exemple FR, voir README
        'Gz-AppId': 'com.glazero.android',
        'Gz-AppVer': '5.10.12',
        'Gz-BuildType': 'release',
        'Gz-Channel': 'appstore',
        'Gz-Uid': '',
        'Gz-Sid': '',
        'Gz-Sign': build_signature(req_id, now, suffix),
        'Content-Type': 'application/x-www-form-urlencoded',
        # En-tetes automatiques d OkHttp 5.0.0-alpha.12 (APK classes6.dex :
        # okhttp3/internal/http/BridgeInterceptor.intercept).
        # Sur requests, les expliciter et supprimer le Accept: */* implicite.
        'User-Agent': 'okhttp/5.0.0-alpha.12',
        'Accept-Encoding': 'gzip',
        'Connection': 'Keep-Alive',
    }
    if android_properties:
        for key in ('Gz-OsVer', 'Gz-Brand', 'Gz-Model', 'Gz-FontSize'):
            if key in android_properties:
                headers[key] = android_properties[key]
    # Trois en-tetes experimentaux uniquement sur demande explicite.
    if additional_headers:
        for key in MISSING_DEVICE_HEADERS:
            if key in additional_headers:
                headers[key] = additional_headers[key]
    return params, form, headers


MISSING_DEVICE_HEADERS = ('Gz-Imei', 'Gz-NotifyPermission', 'Gz-Network')


def print_offline(material: bytes, suffix: bytes):
    passed, total = check_vectors(material)
    print(f'[AES] Tests compares au JNI : {passed}/{total}')
    if passed != total:
        raise ValueError('Le chiffrement ne correspond pas aux references JNI.')
    if build_signature('00000000-0000-4000-8000-000000000001',
                       '1790000000000', suffix) != '27c454babbf48718bf70f085d0f9cd54':
        raise ValueError('Signature MD5 differente du vecteur de controle.')
    params, form, headers = build_request_values(material, suffix,
                                                 'test@example.invalid', 'Mot de passe fictif 2026')
    assert list(form) == ['region', 'countryCode', 'countryAbbr', 'type', 'email', 'password', 'pwType']
    assert form['region'] == 'EU' and form['countryCode'] == '33' and form['countryAbbr'] == 'FR'
    assert list(params) == ['uuid', 't']
    assert headers['Gz-Lang'] == 'fr' and headers['Gz-OsLang'] == 'fr-FR'
    assert headers['Gz-TimezoneID'] == 'Europe/Paris'
    assert headers['User-Agent'] == 'okhttp/5.0.0-alpha.12'
    assert headers['Accept-Encoding'] == 'gzip'
    assert headers['Connection'] == 'Keep-Alive'
    assert re.fullmatch(r'[+-]\d{2}:\d{2}', headers['Gz-Timezone'])
    for name in ('Gz-Pid', 'Gz-Channel', 'Gz-Uid', 'Gz-Sid'):
        assert name in headers
    for name in MISSING_DEVICE_HEADERS:
        assert name not in headers
    print('[SIGNATURE] MD5 reference : OK')
    print('[FORMULAIRE] 7 champs : OK ; Gz-Lang=fr : OK')
    print('[EN-TETES] Entetes OkHttp User-Agent / gzip / Keep-Alive : OK')
    try:
        import requests
        session_check = requests.Session()
        session_check.headers.clear() # Pas de Accept: */* automatique, absent de BridgeInterceptor.
        prepared = session_check.prepare_request(requests.Request('POST', TARGET, params=params, data=form, headers=headers))
        assert prepared.headers['User-Agent'] == 'okhttp/5.0.0-alpha.12'
        assert prepared.headers['Accept-Encoding'] == 'gzip'
        assert prepared.headers['Connection'] == 'Keep-Alive'
        assert 'Accept' not in prepared.headers
        assert 'Content-Length' in prepared.headers
        assert prepared.body is not None
        session_check.close()
        print('[HTTP PREPARE] Requete Python sans Accept supplementaire : OK')
    except ImportError:
        print('[HTTP PREPARE] Module requests absent : comparaison complete non executee.')
    assert java_map({'a': True, 'b': {'c': False}}) == '{a=true, b={c=false}}'
    assert simulated_network('192.0.2.10', True, False, True) == '{vpn=false, wifi=true/192.0.2.10, available=true}'
    assert simulated_notifications('ALL', {'Mouvement AOSU': 4}, {}, True, False, False) == ('{filter=ALL, channels={Mouvement+AOSU=4}, channelGroups={}, enabled=true, paused=false, BubblesAllowed=false}')
    print('[ANDROIDS] Trois formats d en-tetes verifies hors ligne ; valeurs reelles non confirmees.')
    print('[REGION] Pays France (liste APK) : EU / 33 / FR : OK. Autres regions non prises en charge.')
    print('[RESEAU] Aucun appel realise pendant le pre-controle.')


# Seuls les noms de champs sont affiches ; aucune valeur textuelle libre
# d'une reponse de serveur n'est jamais recopiee.
SAFE_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,39}\Z')
STATUS_FIELDS = {'errno', 'code', 'errorCode', 'error_code', 'errCode', 'err_code', 'status', 'success', 'ok', 'resultCode'}
MESSAGE_FIELDS = {'errmsg', 'msg', 'message', 'error', 'errorMsg', 'errorMessage', 'description', 'detail'}
SESSION_FIELDS = {'sid', 'uid', 'tuyaUsername', 'tuyaUid'}


def data_type(value):
    if isinstance(value, dict): return 'objet'
    if isinstance(value, list): return 'liste'
    if value is None: return 'null'
    if type(value) is bool: return 'booleen'
    if type(value) in (int, float): return 'nombre'
    if isinstance(value, str): return 'texte'
    return 'autre'


def status_value(value):
    # Jamais d'affichage de chaine opaque (potentiellement un jeton).
    if type(value) is bool:
        return str(value)
    if type(value) is int and abs(value) < 1_000_000_000:
        return str(value)
    if type(value) is str and re.fullmatch(r'-?[0-9]{1,8}', value):
        return value
    if type(value) is str and value.lower() in {'ok', 'success', 'error', 'failed', 'fail', 'true', 'false'}:
        return value.lower()
    return '[MASQUE]'


def message_category(value):
    if not isinstance(value, str) or not value:
        return None
    s = value.lower()[:1000]
    for words, category in (
        (('sign', 'signature', 'checksum'), 'signature'),
        (('password', 'credential', 'passwd', 'account', 'mot de passe'), 'compte/identifiants'),
        (('region', 'country', 'pays'), 'region/pays'),
        (('timestamp', 'expired', 'timeout'), 'horodatage/expiration'),
        (('device', 'imei', 'pid', 'app id'), 'identite application/appareil'),
        (('param', 'invalid request', 'bad request', 'missing', 'required'), 'parametres de requete'),
        (('frequen', 'too many', 'rate limit'), 'limitation des requetes'),
    ):
        if any(word in s for word in words):
            return category
    return 'message present, non affiche'


def response_diagnostic(payload):
    """Diagnostic strictement metadonnees: aucune valeur sensible divulguee."""
    print('[REPONSE] Structure JSON :', data_type(payload))
    if not isinstance(payload, dict):
        print('[CONCLUSION] Format non conforme au resultat de connexion attendu.')
        return
    # Explorer uniquement les objets, profondeur max 3, nombre limite de champs.
    queue = [('$', payload, 0)]
    found_code = False
    found_msg = False
    errno_seen = False
    errno_value = None
    seen_sessions = {f: False for f in SESSION_FIELDS}
    count = 0
    while queue and count < 18:
        path, current, depth = queue.pop(0)
        if not isinstance(current, dict):
            continue
        count += 1
        keys = [k for k in current.keys() if isinstance(k, str) and SAFE_NAME.fullmatch(k)]
        printed = keys[:25]
        suffix = ', ...' if len(keys) > 25 else ''
        print(f'[STRUCTURE] {path}: {{{", ".join(printed)}{suffix}}}')
        for key, value in current.items():
            if not isinstance(key, str) or not SAFE_NAME.fullmatch(key):
                continue
            if key in STATUS_FIELDS:
                print(f'[CODE_APPLICATIF] {path}.{key} = {status_value(value)}')
                found_code = True
                if path == '$' and key == 'errno':
                    errno_seen = True
                    # Seulement les entiers et chaines numeriques courtes peuvent etre interpretes.
                    if type(value) is int:
                        errno_value = value
                    elif type(value) is str and re.fullmatch(r'-?[0-9]{1,8}', value):
                        errno_value = int(value)
            if key in MESSAGE_FIELDS and isinstance(value, str) and value:
                print(f'[MESSAGE] {path}.{key} : {message_category(value)}')
                found_msg = True
            if key in SESSION_FIELDS:
                seen_sessions[key] |= bool(value) and isinstance(value, str)
            if depth < 3 and isinstance(value, dict):
                queue.append((f'{path}.{key}', value, depth + 1))
            elif depth < 2 and isinstance(value, list) and value and isinstance(value[0], dict):
                queue.append((f'{path}.{key}[0]', value[0], depth + 1))
    if not found_code:
        print('[CODE_APPLICATIF] Aucun champ de statut reconnu dans les niveaux inspectes.')
    if not found_msg:
        print('[MESSAGE] Aucun champ de message texte reconnu dans les niveaux inspectes.')
    print('[CHAMPS_SESSION] ' + ' '.join(f'{f}_present={seen_sessions[f]}' for f in sorted(SESSION_FIELDS)))
    if errno_seen and errno_value is not None and errno_value != 0:
        print('[CONCLUSION] Erreur applicative AOSU (errno non nul) : connexion non validee.')
    elif errno_seen and errno_value == 0:
        if seen_sessions['sid']:
            print('[CONCLUSION] errno=0 et sid present : reponse potentiellement positive, connexion non verifiee.')
        else:
            print('[CONCLUSION] errno=0 mais aucun sid present : authentification non confirmee.')
    else:
        print('[CONCLUSION] Une reponse HTTP 200 ne confirme pas une connexion valide.')
    print('[CONFIDENTIALITE] Aucune valeur de session, message brut ou cookie affiche.')



# === VERIFICATION DE SESSION : UN SEUL APPEL EN LECTURE SEULE ===
# Source: APK classes15.dex, com.glazero.data.device.service.DeviceWebService$IService
# methode OooOOo, annotation Retrofit POST("/v1/dev/getList"), zero parametre,
# appelee par DeviceWebService via GzWebServerBiz (meme pile que le login).
DEVICE_LIST_TARGET = 'https://api-eu.aosulife.com/v1/dev/getList'


def build_device_list_request(suffix: bytes, login_headers: dict,
                              sid: str, uid: str) -> tuple[dict, dict]:
    """Conserver les en-tetes de la connexion, signer une NOUVELLE requete.

    Aucun mot de passe, aucun formulaire ; sid/uid servent uniquement en memoire.
    """
    if not sid or not uid or not isinstance(sid, str) or not isinstance(uid, str):
        raise ValueError('Session AOSU incomplete : sid ou uid absent.')
    now = str(int(time.time() * 1000))
    req_uuid = str(uuid.uuid4())
    params = {'uuid': req_uuid, 't': now}
    headers = dict(login_headers)
    headers['Gz-Sid'] = sid
    headers['Gz-Uid'] = uid
    headers['Gz-Sign'] = build_signature(req_uuid, now, suffix)
    # POST Retrofit sans @FormUrlEncoded et sans @Body: corps vide,
    # pas de Content-Type obligatoire ; RequestBody de 0 octet.
    headers.pop('Content-Type', None)
    return params, headers


# === INVENTAIRE DE STRUCTURE, SANS VALEURS DE CAMERAS ===
# Aucune donnee recue du serveur n'est imprimee, excepte le code errno (nombre).
# On ne sort que des noms de champs raisonnables, des TYPES de valeurs et des
# nombres d'occurrences ; jamais les valeurs, identifiants, noms ou liens.


def _schema_type(value):
    if value is None:
        return 'null'
    if type(value) is bool:
        return 'booleen'
    if isinstance(value, dict):
        return 'objet'
    if isinstance(value, list):
        return 'liste'
    if isinstance(value, str):
        return 'texte'
    if type(value) in (int, float):
        return 'nombre'
    return 'autre'


def _print_common_fields(records, prefix, limit=32):
    from collections import Counter, defaultdict
    counts = Counter()
    types = defaultdict(set)
    for record in records:
        if not isinstance(record, dict):
            continue
        # Ne jamais afficher de cle issue de donnees indexees par un ID dynamique.
        for key, value in record.items():
            if not isinstance(key, str) or not SAFE_NAME.fullmatch(key):
                continue
            counts[key] += 1
            types[key].add(_schema_type(value))
    minimum = 2 if len(records) > 1 else 1
    printed = 0
    for key in sorted(counts):
        if counts[key] < minimum:
            continue
        print(f'[SCHEMA] {prefix}.{key}: {"/".join(sorted(types[key]))} ({counts[key]}/{len(records)})')
        printed += 1
        if printed >= limit:
            print('[SCHEMA] Autres champs omis (limite de securite).')
            break
    if printed == 0:
        print('[SCHEMA] Aucun champ commun de forme sure a afficher.')


def print_device_schema(payload) -> None:
    """Uniquement noms de champs et types, jamais le contenu textuel ni les IDs."""
    if not isinstance(payload, dict) or payload.get('errno') != 0:
        return
    data = payload.get('data')
    if isinstance(data, list):
        entries = data
        path = '$.data'
    elif isinstance(data, dict):
        entries = None
        path = ''
        for candidate in ('list', 'devices', 'deviceList', 'device_list'):
            if isinstance(data.get(candidate), list):
                entries = data[candidate]
                path = '$.data.' + candidate
                break
        if entries is None:
            print('[SCHEMA] Structure inconnue : aucune liste inspectee.')
            return
    else:
        print('[SCHEMA] Pas de liste exploitable.')
        return
    # Le chemin n'est qu'une constante programme, jamais une valeur du serveur.
    print('[SCHEMA] Chemin de la liste :', path)
    print('[SCHEMA] Nombre d entrees dans la liste :', len(entries))
    if len(entries) > 50:
        print('[SCHEMA] Liste trop longue ; schema non inspecte.')
        return
    if not entries or not all(isinstance(record, dict) for record in entries):
        print('[SCHEMA] Entrees heterogenes ou absentes ; aucun champ affiche.')
        return
    _print_common_fields(entries, 'appareil')
    # Les objets imbriques sont utiles a l'integration HA, mais on s'arrete a
    # un seul niveau pour ne pas explorer des structures de donnees privees.
    from collections import Counter
    object_counts = Counter(k for record in entries for k, v in record.items()
                            if isinstance(k, str) and SAFE_NAME.fullmatch(k)
                            and isinstance(v, dict))
    threshold = 2 if len(entries) > 1 else 1
    for key in sorted(k for k, n in object_counts.items() if n >= threshold)[:4]:
        subset = [record[key] for record in entries if isinstance(record.get(key), dict)]
        _print_common_fields(subset, 'appareil.' + key, limit=10)
    print('[CONFIDENTIALITE] Structure seulement : aucune valeur de camera affichee ou enregistree.')



# === DIAGNOSTIC INDIVIDUEL SANS IDENTIFIANTS, NE SAUVE RIEN ===
# Une position 1..N n'est PAS un identifiant stable Home Assistant.
# Les valeurs numeriques restent brutes: pas de conversion arbitraire en SOC/dBm.

KNOWN_MODELS = ('C9C3CA11', 'C5L', 'H1L')


def _known_model(record: dict) -> str:
    """Liste blanche: aucun champ texte libre recu du serveur n'est affiche."""
    for key in ('model', 'ori_model', 'modelAlias'):
        value = record.get(key)
        if not isinstance(value, str):
            continue
        upper = value.upper()
        for model in KNOWN_MODELS:
            if re.search(r'(?<![A-Z0-9])' + re.escape(model) + r'(?![A-Z0-9])', upper):
                return model
    return 'non_identifie'


def _bounded_integer(value, low: int, high: int) -> str:
    if type(value) is int and low <= value <= high:
        return str(value)
    return 'non_interpretable'


def _bounded_measure(value, low: float, high: float) -> str:
    if type(value) in (int, float) and low <= value <= high:
        return str(round(float(value), 2))
    return 'non_interpretable'


def print_device_summary(payload) -> None:
    """Diagnostics numeriques bornes, aucun SN, ID, nom ni lien imprime."""
    if not isinstance(payload, dict) or payload.get('errno') != 0:
        return
    data = payload.get('data')
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get('list')
    else:
        return
    if not isinstance(records, list) or len(records) > 50 or not all(isinstance(r, dict) for r in records):
        print('[INVENTAIRE] Format non reconnu, valeurs ignorees.')
        return
    print('[INVENTAIRE] Analyse de', len(records), 'entrees en memoire, sans sauvegarde.')
    for idx, record in enumerate(records, 1):
        extended = record.get('extend')
        extended = extended if isinstance(extended, dict) else {}
        print(f'[APPAREIL {idx}] modele_connu={_known_model(record)}'
              f' devType_brut={_bounded_integer(record.get("devType"), -1000, 100000)}'
              f' online_brut={_bounded_integer(record.get("online"), -10, 10)}'
              f' baseSn_present={bool(record.get("baseSn"))}'
              f' energie_presente={"electricity" in extended and extended["electricity"] is not None}'
              f' wifi_present={"wifi_signal" in extended and extended["wifi_signal"] is not None}'
              f' mode_alimentation_present={bool(extended.get("power_mode"))}')
        if 'electricity' in extended and extended['electricity'] is not None:
            print(f'[VALEURS {idx}] electricity_brut_0a100={_bounded_measure(extended["electricity"], 0, 100)}'
                  ' (unite et semantique non verifiees)')
        if 'wifi_signal' in extended and extended['wifi_signal'] is not None:
            print(f'[VALEURS {idx}] wifi_signal_brut={_bounded_measure(extended["wifi_signal"], -150, 150)}'
                  ' (unite non verifiee)')
    # Effectuer seulement des comparaisons en memoire, jamais afficher les SN.
    serial_to_positions = {}
    for idx, record in enumerate(records, 1):
        sn = record.get('sn')
        if isinstance(sn, str) and sn:
            serial_to_positions.setdefault(sn, []).append(idx)
    for idx, record in enumerate(records, 1):
        base = record.get('baseSn')
        if not isinstance(base, str) or not base:
            continue
        matches = [pos for pos in serial_to_positions.get(base, ()) if pos != idx]
        if len(matches) == 1:
            print(f'[LIEN_BASE] appareil_{idx} -> appareil_{matches[0]} (correspondance baseSn/sn)')
        else:
            print(f'[LIEN_BASE] appareil_{idx} : base non identifiee dans cette liste')
    print('[CONFIDENTIALITE] Numeros de serie, UID, noms, URLs, donnees de compte et jetons masques.')
    print('[PRUDENCE] Les numeros d ordre ne sont pas des identifiants persistants.')
    print('[PRUDENCE] Les valeurs online, electricity et wifi_signal ne sont pas encore converties en etats HA.')


def validate_device_list_response(response) -> None:
    """Afficher seulement une confirmation et, si accessible, un compte d'appareils."""
    print('[APPAREILS_HTTP] Statut :', response.status_code)
    if 300 <= response.status_code < 400:
        print('[APPAREILS] Redirection refusee.')
        return
    if response.status_code != 200:
        print('[APPAREILS] Statut HTTP non valide.')
        return
    if len(response.content) > 262144:
        print('[APPAREILS] Reponse trop volumineuse : non analysee.')
        return
    try:
        payload = response.json()
    except ValueError:
        print('[APPAREILS] Reponse non JSON ; contenu masque.')
        return
    if not isinstance(payload, dict):
        print('[APPAREILS] Format de reponse inattendu.')
        return
    errno = payload.get('errno')
    if type(errno) not in (int, float):
        print('[APPAREILS] Code de reponse non numerique.')
        return
    print('[APPAREILS_CODE] errno =', errno)
    if errno != 0:
        print('[SESSION] Lecture des appareils refusee, ou requete a ajuster.')
        return
    print('[SESSION] Authentification confirmee par une seconde API protegee.')
    data = payload.get('data')
    if isinstance(data, list):
        print('[APPAREILS] Nombre :', len(data))
    elif isinstance(data, dict):
        for key in ('list', 'devices', 'deviceList', 'device_list'):
            if isinstance(data.get(key), list):
                print('[APPAREILS] Nombre :', len(data[key]))
                break
        else:
            print('[APPAREILS] Reponse acceptee ; structure de liste non reconnue.')
    else:
        print('[APPAREILS] Reponse acceptee ; aucune liste exploitable identifiee.')
    print('[CONFIDENTIALITE] Aucun SID, UID, identifiant, nom ou adresse de camera affiche.')
    print_device_schema(payload)
    print_device_summary(payload)


def offer_device_list_request(session, suffix: bytes, login_headers: dict, payload: dict) -> None:
    data = payload.get('data')
    if not isinstance(data, dict):
        print('[APPAREILS] Aucune session exploitable en memoire.')
        return
    sid, uid = data.get('sid'), data.get('uid')
    if not isinstance(sid, str) or not sid or not isinstance(uid, (str, int)) or not str(uid):
        print('[APPAREILS] sid / uid absents ou invalides : appel annule.')
        return
    print('\n[SESSION] Connexion acceptee, sid temporairement en memoire uniquement.')
    print('[APPAREILS] Verification facultative, en lecture seule : POST /v1/dev/getList.')
    print('[APPAREILS] Aucune commande envoyee aux cameras. Un seul POST supplementaire.')
    print('[APPAREILS] Schema et diagnostic par appareil (metadonnees limitees ; aucun identifiant).')
    if input('Autoriser CE SECOND appel HTTPS ? Tape LIRE (sinon Annuler) : ').strip() != 'LIRE':
        print('[APPAREILS] Lecture annulee. Connexion deja realisee.')
        return
    try:
        params, headers = build_device_list_request(suffix, login_headers, sid, str(uid))
        # Session requests identique ; aucun cookie ou jeton ne va sur disque.
        response = session.post(DEVICE_LIST_TARGET, params=params, data=b'', headers=headers,
                                timeout=(8, 20), allow_redirects=False, verify=True)
        validate_device_list_response(response)
    except ValueError:
        print('[APPAREILS] Requete non preparee : session incomplete.')
    except Exception as exc:
        # Ne jamais afficher str(exc) qui peut contenir des URLs ou des donnees.
        print('[APPAREILS] Erreur reseau ou autre :', type(exc).__name__)

def run_one_request(material: bytes, suffix: bytes) -> None:
    try:
        import requests
    except ImportError:
        print('[DEPENDANCE] requests absent. Lance INSTALLER_DEPENDANCES.bat.')
        return

    print('\n[AVERTISSEMENT] Essai EXPERIMENTAL non officiel, un seul POST HTTPS.')
    print('[DESTINATION] https://api-eu.aosulife.com/v1/user/login')
    print('[LIMITE] En-tetes supplementaires construits depuis profil ESTIME.')
    print('[LIMITE] Canaux AOSU et identifiant officiel non accessibles.')
    print('[CONFIDENTIALITE] Saisie locale; rien n est enregistre sur disque.')
    print('[RISQUE] Le serveur peut compter cet essai dans ses limites de connexion.')
    print('[ATTENTION] Pour le code, le compte est suppose europeen (EU / 33 / FR).')
    print('[ENVIRONNEMENT] Option ADB : SDK, marque, modele et echelle de police uniquement.')
    print('                 Jamais android_id, numero de serie, cookie ou jeton.')
    adb_data = {}
    if input('Lire les 4 champs non sensibles du telephone par ADB si disponible ? [o/N] : ').strip().lower() == 'o':
        adb_data = safe_adb_properties()
    extras = make_experimental_headers()
    if extras is None:
        print('[ANNULE] Aucun POST HTTPS.')
        return
    print('[CONFIRMATION] Une seule tentative HTTP avec des valeurs PARTIELLEMENT ESTIMEES.')
    if input('Pour confirmer la comprehension du risque, tape EXPERIMENTAL : ').strip() != 'EXPERIMENTAL':
        print('[ANNULE] Aucun POST HTTPS.')
        return
    if input('Pour autoriser UN envoi, tape ENVOYER : ').strip() != 'ENVOYER':
        print('[ANNULE] Aucun appel reseau.')
        return
    email = input('E-mail AOSU (saisie locale uniquement) : ').strip()
    if not email or '@' not in email or len(email) > 254:
        print('[ANNULE] E-mail non valide.')
        return
    password = getpass.getpass('Mot de passe AOSU (masque et non enregistre) : ')
    if not password:
        print('[ANNULE] Mot de passe vide.')
        return
    params, form, headers = build_request_values(material, suffix, email, password,
                                                 android_properties=adb_data,
                                                 additional_headers=extras)
    # Efface les references directes sans promettre d effacement memoire securise.
    password = ''
    email = ''
    print('[EN-TETES] Total envoyes par le script :', len(headers))
    print('[EN-TETES] Trois en-tetes Android experimentaux ajoutes : oui')
    print('[PREPARATION] 1 connexion ; lecture facultative seulement apres accord distinct.')
    session = requests.Session()
    session.headers.clear()  # Supprime le Accept, UA, gzip implicites de Requests.
    session.trust_env = False  # Pas de proxy issu de variables environnement
    try:
        response = session.post(TARGET, params=params, data=form, headers=headers,
                                timeout=(8, 20), allow_redirects=False, verify=True)
        print('[HTTP] Statut :', response.status_code)
        if 300 <= response.status_code < 400:
            print('[REDIRECTION] Non suivie.')
            return
        if len(response.content) > 65536:
            print('[REPONSE] Plus de 64 Kio : non inspectee.')
            return
        ct = response.headers.get('content-type', '').split(';')[0].strip().lower()
        print('[FORMAT] JSON :' , 'oui' if ct in ('application/json', 'text/json', 'application/problem+json') or ct.endswith('+json') else 'non annonce')
        try:
            payload = response.json()
        except ValueError:
            print('[REPONSE] Format non JSON, contenu masque.')
            return
        response_diagnostic(payload)
        # Ne jamais afficher les cookies, sid, uid ou la reponse complete.
        if isinstance(payload, dict) and payload.get('errno') != 0:
            message = payload.get('errmsg')
            if isinstance(message, str) and message:
                print('[MESSAGE] Le contenu exact de errmsg reste masque.')
                print('[PARTAGE] Tu peux copier les lignes de diagnostic ci-dessus.')
                print('          Si necessaire, regarde errmsg localement sans le partager en entier.')
                if input('Afficher errmsg localement malgre un possible contenu prive ? [o/N] : ').strip().lower() == 'o':
                    # Limiter aux premieres lignes pour eviter tout contenu massif.
                    print('[ERRMSG_SENSIBLE_A_NE_PAS_COPIER] ' + repr(message[:300]))
        if (response.status_code == 200 and isinstance(payload, dict)
                and payload.get('errno') == 0):
            offer_device_list_request(session, suffix, headers, payload)
    except requests.exceptions.SSLError:
        print('[TLS] Erreur de certificat HTTPS : pas de contournement.')
    except requests.exceptions.Timeout:
        print('[TIMEOUT] Le serveur ne repond pas dans les delais.')
    except requests.exceptions.RequestException as exc:
        print('[RESEAU] Erreur type :', type(exc).__name__)
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(description='Smart AOSU 0.6.0 - UN essai HTTP optionnel, sans envoi par defaut')
    parser.add_argument('apk', type=Path, nargs='?', help='Bundle AOSU complet .apks.apk')
    parser.add_argument('--offline', action='store_true', help='Verifier hors ligne sans menu')
    parser.add_argument('--selftest', action='store_true', help='Diagnostiquer des exemples fictifs, sans reseau et sans APK')
    args = parser.parse_args()
    if args.selftest:
        assert simulated_network('192.0.2.10', True, False, True) == '{vpn=false, wifi=true/192.0.2.10, available=true}'
        print('[SELFTEST] Reponse fictive avec erreur :')
        response_diagnostic({'errno': 10014, 'errmsg': 'Invalid signature provided', 'data': {}})
        print('\n[SELFTEST] Reponse fictive de connexion AOSU avec donnees de session :')
        response_diagnostic({'errno': 0, 'errmsg': 'success', 'data': {'sid': 'SECRET_A_NE_JAMAIS_AFFICHER', 'tuyaUsername': 'SECRET2'}})
        import contextlib
        from io import StringIO
        example = {'errno': 0, 'data': {'list': [
            {'sn': 'PRIVE_SN_BASE', 'model': 'H1L', 'devType': 1, 'online': 1, 'extend': {}},
            {'sn': 'PRIVE_SN_ENFANT_1', 'baseSn': 'PRIVE_SN_BASE', 'model': 'C9C3CA11',
             'name': 'NOM PRIVE CAMERA', 'devType': 2, 'online': 0,
             'extend': {'electricity': 76, 'wifi_signal': -48, 'power_mode': 'PRIVE_MODE'}},
            {'sn': 'PRIVE_SN_ENFANT_2', 'baseSn': 'PRIVE_SN_BASE', 'model': 'inconnu',
             'devType': 2, 'online': 1, 'extend': {'electricity': 52}},
            {'sn': 'PRIVE_SN_DIRECT', 'modelAlias': 'C5L', 'devType': 3, 'online': 1,
             'extend': {'wifi_signal': 80}}
        ]}}
        capture = StringIO()
        with contextlib.redirect_stdout(capture):
            print_device_summary(example)
        report = capture.getvalue()
        for private in ('PRIVE_SN_BASE', 'PRIVE_SN_ENFANT_1', 'PRIVE_SN_ENFANT_2',
                        'PRIVE_SN_DIRECT', 'NOM PRIVE CAMERA', 'PRIVE_MODE'):
            assert private not in report, 'Fuite d information de test'
        assert '[APPAREIL 1] modele_connu=H1L' in report
        assert '[APPAREIL 2] modele_connu=C9C3CA11' in report
        assert '[LIEN_BASE] appareil_2 -> appareil_1' in report
        assert '[LIEN_BASE] appareil_3 -> appareil_1' in report
        print('[SELFTEST] 4 appareils fictifs : diagnostics et masquage des donnees prives OK.')
        return 0
    print('\nSMART AOSU - Test authentification v0.6.0\n')
    if args.apk is None:
        parser.error('Il faut fournir ton APK pour le diagnostic reel, ou utiliser --selftest.')
    try:
        binary, dex = read_apk_parts(args.apk)
        material = binary[KEY_OFFSET:KEY_OFFSET + 16]
        if len(material) != 16:
            raise ValueError('Material cryptographique incomplet.')
        suffix = get_sign_suffix(dex)
        print('[APK] AOSU 5.10.12 verifie : OK')
        print_offline(material, suffix)
        if args.offline:
            return 0
        print('\nMENU : 1 = Terminer (aucun reseau) ; 2 = Essai HTTPS experimental')
        choice = input('Ton choix [1] : ').strip() or '1'
        if choice == '2':
            run_one_request(material, suffix)
        else:
            print('[TERMINE] Aucun appel reseau.')
        return 0
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        print('[ERREUR]', exc)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\n[ANNULE]')
        return 1


if __name__ == '__main__':
    sys.exit(main())
