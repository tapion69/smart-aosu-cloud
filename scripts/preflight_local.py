#!/usr/bin/env python3
"""Contrôle local, hors réseau et sans affichage de valeurs privées.

Usage: python preflight_local.py /config
N'exécute aucun code de l'intégration ; ne déclenche aucune connexion.
"""
from __future__ import annotations
import json
import hashlib
import sys
from pathlib import Path
from io import BytesIO
from zipfile import ZipFile, BadZipFile

EXPECTED_LIB_SHA256 = "24caa3df3500d81106a65beda2703702494eb60a6af758b866585cbb577bfd68"
PROFILE_FIELDS = {"Gz-OsVer", "Gz-Brand", "Gz-Model", "Gz-FontSize"}
EXTRA_FIELDS = {"Gz-Imei", "Gz-Network", "Gz-NotifyPermission"}


def valid_fields(obj, fields):
    return isinstance(obj, dict) and set(obj) == fields and all(
        isinstance(v, str) and 0 < len(v) <= 8192 and "\r" not in v and "\n" not in v
        for v in obj.values())


def profile_ok(path):
    if not path.is_file(): return True, 'profil_absent_generation_automatique_au_premier_demarrage'
    try:
        obj = json.loads(path.read_text(encoding='utf-8'))
        ok = (isinstance(obj, dict) and obj.get('version') == 1
              and valid_fields(obj.get('android_properties'), PROFILE_FIELDS)
              and valid_fields(obj.get('additional_headers'), EXTRA_FIELDS))
        return ok, 'profil_structure_valide' if ok else 'profil_structure_invalide'
    except (OSError, UnicodeError, ValueError):
        return False, 'profil_inaccessible_ou_json_invalide'


def apk_ok(path):
    if not path.is_file(): return False, 'apk_absente'
    try:
        with ZipFile(path) as bundle:
            names=set(bundle.namelist())
            if not {'base.apk', 'split_config.arm64_v8a.apk'} <= names:
                return False,'bundle_apk_structure_incompatible'
            if bundle.getinfo('base.apk').file_size > 450_000_000 or bundle.getinfo('split_config.arm64_v8a.apk').file_size > 200_000_000:
                return False,'bundle_apk_trop_volumineux_pour_le_controle'
            with ZipFile(BytesIO(bundle.read('base.apk'))) as base:
                if base.getinfo('classes11.dex').file_size > 80_000_000:
                    return False,'dex_trop_volumineux'
                dex=base.read('classes11.dex')
            with ZipFile(BytesIO(bundle.read('split_config.arm64_v8a.apk'))) as split:
                with split.open('lib/arm64-v8a/libglazero-security.so') as library:
                    digest=hashlib.sha256()
                    while part := library.read(1024*1024):digest.update(part)
            valid=digest.hexdigest()==EXPECTED_LIB_SHA256 and b'Gz-Sign' in dex and b'api.aosulife.com' in dex
            return valid, 'apk_5_10_12_bibliotheque_compatible' if valid else 'apk_contenu_incompatible'
    except (OSError, BadZipFile, ValueError, KeyError, RuntimeError):
        return False,'bundle_apk_invalide_ou_incomplet'


LITE_SHA = "6a3692aa0dc2385f9d988ffbcf7a703249d426b022f78857d2b380748e790be1"
FULL_SHA = "ec176ce3bdd000cd514371137fff6d8b2141bbde061c3fb2ab3892d7a72b52d7"
SIDECAR_HASHES = {
    "AndroidManifest.xml": "bdf13c6ae42ea6acde2749f07fb93be0d9988d7f883181f4dd25483ad6e2bbab",
    "t_s.bmp": "56b0e2032b6540400a56f8230a032fb9b927612a7865fa94601f1077faeabcdf",
    "fixed_key.bmp": "536eeb953d9549e6e868f3c7c7c25fa0305141e6ffd55f59177f6837927741c0",
    "certificate.der": "5d5117645482ccd8b79fac6382d0e8f0dce75538f4578beac8ebd0c09da6ef2e",
    "libthing_security_algorithm.so": "f842bdc9c575e8c5aeeb7c939ef7dfc8be5f1bc8e2aaec3d41d3facfc85c705a",
}

def local_oem_ok(path):
    if not path.is_file():return False,"complement_oem_absent_pour_apk_allegee"
    try:
        if path.stat().st_size > 1_048_576:return False,"complement_oem_trop_volumineux"
        with ZipFile(path) as z:
            if set(z.namelist()) != set(SIDECAR_HASHES):return False,"complement_oem_structure_invalide"
            for name, expected in SIDECAR_HASHES.items():
                if z.getinfo(name).file_size > 100_000:return False,"complement_oem_invalide"
                if hashlib.sha256(z.read(name)).hexdigest() != expected:
                    return False,"complement_oem_empreinte_invalide"
        return True,"complement_oem_5_10_12_valide"
    except (BadZipFile, OSError, RuntimeError, ValueError, KeyError):
        return False,"complement_oem_invalide"


def integration_ok(path):
    needed=['manifest.json','__init__.py','config_flow.py','camera.py',
            'frontend/ptz-hold-b84.js','frontend/c9-live-b146.js',
            'translations/fr.json','translations/en.json']
    if not all((path/p).is_file() for p in needed):return False,'integration_fichiers_manquants'
    try:
        manifest=json.loads((path/'manifest.json').read_text(encoding='utf-8'))
        return (manifest.get('domain')=='smart_aosu_cloud' and manifest.get('version')=='0.8.11-beta1',
                'integration_0_8_11_beta_presente' if manifest.get('version')=='0.8.11-beta1' else 'integration_version_inattendue')
    except (OSError,ValueError,UnicodeError):return False,'manifest_invalide'


def main():
    base=Path(sys.argv[1]) if len(sys.argv)==2 else Path('/config')
    local = base/'smart_aosu_cloud'
    apk = local/'aosu_vendor_app.apk'
    checks=[('Intégration',integration_ok(base/'custom_components'/'smart_aosu_cloud')),
            ('Profil',profile_ok(local/'profile.json')),
            ('APK',apk_ok(apk))]
    if apk.is_file():
        # For the pinned lite build only, companion resources are mandatory for
        # the OEM video/PTZ path. Original full package is self-contained.
        h=hashlib.sha256()
        with apk.open('rb') as f:
            for chunk in iter(lambda: f.read(1024*1024), b''):
                h.update(chunk)
        digest=h.hexdigest()
        if digest == LITE_SHA:
            checks.append(('Ressources OEM locales',local_oem_ok(local/'Aosu_5.10.12_OEM_resources.zip')))
        elif digest != FULL_SHA:
            checks.append(('Empreinte APK connue',(False,'apk_non_identique_a_reference_5_10_12')))
    for name,(ok,status) in checks:print(f'{name}: {"OK" if ok else "ÉCHEC"} ({status})')
    print('Aucune connexion réseau, aucun identifiant ou secret affiché.')
    if not all(ok for _,(ok,_) in checks):
        print('Ne pas démarrer le test externe avant de régler les prérequis.')
        return 1
    print('Structure locale cohérente ; profil généré au premier démarrage s’il est absent ; authentification et vidéo NON testées.')
    return 0

if __name__=='__main__':raise SystemExit(main())
