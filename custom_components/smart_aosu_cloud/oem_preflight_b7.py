#!/usr/bin/env python3
"""Smart AOSU OEM preflight; local-only by default. No OEM secrets persisted.

This tool never claims to authenticate without a verified signing vector. Its
optional network operation performs at most ONE read-only UID token request.
"""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import struct
import sys
import time
from urllib.parse import urlparse
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
import zipfile


def _u16(data: bytes, pos: int) -> int:
    return struct.unpack_from('<H',data,pos)[0]

def _u32(data: bytes, pos: int) -> int:
    return struct.unpack_from('<I',data,pos)[0]

def _u64(data: bytes, pos: int) -> int:
    return struct.unpack_from('<Q',data,pos)[0]

def _l8(b: bytes, pos: int) -> tuple[int, int]:
    v=b[pos];pos+=1
    if v&128:
        v=((v&127)<<8)|b[pos];pos+=1
    return v,pos

def _l16(b: bytes, pos: int) -> tuple[int, int]:
    v=_u16(b,pos);pos+=2
    if v & 32768:
        v=((v & 32767)<<16)|_u16(b,pos);pos+=2
    return v,pos


def parse_manifest_metadata(b: bytes) -> dict[str, str]:
    if _u16(b,0) != 3:
        raise ValueError('invalid_binary_manifest')
    items: list[str]=[]
    metadata: dict[str,str]={}
    package=''
    off=8
    while off+8<=len(b):
        kind, hdr, sz = _u16(b,off),_u16(b,off+2),_u32(b,off+4)
        if sz<8 or off+sz>len(b): raise ValueError('invalid_manifest_chunk')
        if kind==1:
            count, flags, start=_u32(b,off+8),_u32(b,off+16),_u32(b,off+20)
            if count>100000: raise ValueError('invalid_manifest_strings')
            for i in range(count):
                p=off+start+_u32(b,off+hdr+4*i)
                if flags&0x100:
                    _,p=_l8(b,p);n,p=_l8(b,p)
                    items.append(b[p:p+n].decode('utf8'))
                else:
                    n,p=_l16(b,p)
                    items.append(b[p:p+2*n].decode('utf-16-le'))
        elif kind==0x0102:
            name_i=_u32(b,off+20)
            if name_i>=len(items):raise ValueError('invalid_element_name')
            name=items[name_i]; att_start,att_size,att_count=_u16(b,off+24),_u16(b,off+26),_u16(b,off+28)
            if att_count>1000:raise ValueError('invalid_attributes')
            a={}
            for i in range(att_count):
                p=off+16+att_start+att_size*i
                attr_i, raw, typ, val = _u32(b,p+4), _u32(b,p+8), b[p+15],_u32(b,p+16)
                key=items[attr_i] if attr_i<len(items) else ''
                if raw != 0xFFFFFFFF and raw<len(items):
                    value=items[raw]
                elif typ==3 and val<len(items):
                    value=items[val]
                else:
                    value=''
                a[key]=value
            if name=='manifest':package=a.get('package','')
            if name=='meta-data' and a.get('name','').startswith('THING_SMART_'):
                metadata[a['name']]=a.get('value','')
        off+=sz
    metadata['package']=package
    return metadata


def prefixed(b: bytes, p: int) -> tuple[bytes,int]:
    if p+4>len(b): raise ValueError('invalid_signature_block')
    n=_u32(b,p)
    if n>len(b)-p-4:raise ValueError('invalid_signature_length')
    return b[p+4:p+4+n],p+4+n


def apk_v2_certificate(base_apk:bytes)->bytes:
    eocd=base_apk.rfind(b'PK\x05\x06')
    if eocd<0:raise ValueError('missing_eocd')
    cd=_u32(base_apk,eocd+16)
    if base_apk[cd-16:cd]!=b'APK Sig Block 42': raise ValueError('missing_apk_v2_block')
    size=_u64(base_apk,cd-24);start=cd-(size+8)
    if start<0 or _u64(base_apk,start)!=size:raise ValueError('invalid_apk_signing_block')
    p=start+8
    while p<cd-24:
        n=_u64(base_apk,p)
        if n<4 or p+8+n>cd-24:raise ValueError('invalid_apk_signing_pair')
        kind=_u32(base_apk,p+8)
        payload=base_apk[p+12:p+8+n]
        p+=8+n
        if kind==0x7109871A:  # APK Signature Scheme v2
            signers,_=prefixed(payload,0)
            signer,_=prefixed(signers,0)
            signed_data,_=prefixed(signer,0)
            _,offset=prefixed(signed_data,0) # digests
            certs,_=prefixed(signed_data,offset)
            der,_=prefixed(certs,0)
            if not der or der[0]!=0x30:raise ValueError('invalid_signing_certificate')
            return der
    raise ValueError('missing_v2_signer')


@dataclass(repr=False)
class APKIdentity:
    app_id:str=field(repr=False)
    app_secret:str=field(repr=False)
    cert_hash:str=field(repr=False)
    package:str
    t_s_bmp:bytes=field(repr=False)
    fixed_key_bmp:bytes=field(repr=False)

    def __repr__(self)->str:return 'APKIdentity(<redacted>)'


def load_identity(apks_path:Path)->APKIdentity:
    """Works with original *.apks.apk bundle or the inner base.apk."""
    with zipfile.ZipFile(apks_path) as z:
        if 'base.apk' in z.namelist():
            raw=z.read('base.apk')
        elif 'AndroidManifest.xml' in z.namelist():
            raw=apks_path.read_bytes()
        else:raise ValueError('missing_base_apk')
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        meta=parse_manifest_metadata(z.read('AndroidManifest.xml'))
        bmp=z.read('assets/t_s.bmp')
        fixed=z.read('assets/fixed_key.bmp')
    cert=apk_v2_certificate(raw)
    app_id=meta.get('THING_SMART_APPKEY','')
    secret=meta.get('THING_SMART_SECRET','')
    if len(app_id)!=20 or len(secret)!=32:
        raise ValueError('invalid_oem_identity_lengths')
    if meta['package']!='com.glazero.android':
        raise ValueError('unexpected_package')
    return APKIdentity(app_id,secret,hashlib.sha256(cert).hexdigest(),meta['package'],bmp,fixed)


def bmp_legacy_format_compatible(app_id:str,bmp:bytes)->bool:
    """Checks only header counters of an obsolete community algorithm.

    This function does not extract and must not be used as an app-key decoder.
    """
    if len(bmp)<54 or bmp[:2]!=b'BM':return False
    start=_u32(bmp,10)
    if start>=len(bmp):return False
    pix=bmp[start:]
    n=len(pix)
    h=0
    for c in app_id.encode('ascii'):
        h=(31*h+c)&0xffffffff
    if h&0x80000000:h=(~h+1)&0xffffffff
    off=(h % n)//2
    keys=pix[(off+1)%n]
    coefficients=pix[(off+2)%n]
    return 1<=keys<=4 and 1<=coefficients<=12


def inspect_native_bmp_v2(app_id: str, bmp: bytes) -> dict[str, object]:
    """Decode v2 low-bit header/coordinate structure, NEVER return key material.

    Algorithm guided by disassembly of the locally supplied ARM64
    libthing_security_algorithm.so (read_keys_from_content / parse branch 2).
    The final native `transform` phase is not yet reproduced.
    """
    from fractions import Fraction
    state={"format_v2_reconnu":False,"coordonnees_decodables":False,
           "intermediaire_32_octets":False,"transformation_native_reproduite":False}
    if len(bmp)<54 or bmp[:2]!=b'BM':return state
    start=_u32(bmp,10)
    if start<54 or start>=len(bmp):return state
    pixels=bmp[start:];n=len(pixels)
    h=0
    for c in app_id.encode('ascii'):
        h=(31*h+c)&0xffffffff
    if h&0x80000000:h=(0x100000000-h)&0xffffffff
    offset=(h%n)//2
    state['format_v2_reconnu']=pixels[offset]==2
    if not state['format_v2_reconnu']:return state
    offset=(offset+1)%n
    def read_byte()->int:
        nonlocal offset
        v=0
        for bit in range(8):
            v|=(pixels[(offset+bit)%n]&1)<<bit
        offset=(offset+8)%n
        return v
    key_count=read_byte();coefficients=read_byte()
    if not (key_count==1 and 2<=coefficients<=5):return state
    offset=(offset+32)%n  # native parse() skips 32 carrier bytes
    pairs=[]
    for _ in range(key_count*coefficients):
        n1=read_byte()
        if n1 not in (4,6,8):return state
        x=bytes(read_byte() for _ in range(n1))
        n2=read_byte()
        if n2 not in (20,24,32):return state
        y=bytes(read_byte() for _ in range(n2))
        pairs.append((int.from_bytes(x,'big'),int.from_bytes(y,'big')))
    state['coordonnees_decodables']=True
    nrows=len(pairs)
    m=[[Fraction(x**degree) for degree in range(nrows-1,-1,-1)]+[Fraction(y)] for x,y in pairs]
    for i in range(nrows):
        if m[i][i]==0:
            j=next((j for j in range(i+1,nrows) if m[j][i]),None)
            if j is None:return state
            m[j],m[i]=m[i],m[j]
        for j in range(i+1,nrows):
            if m[j][i]:
                ratio=m[j][i]/m[i][i]
                for k in range(i,nrows+1):m[j][k]-=ratio*m[i][k]
    result=m[-1][-1]/m[-1][-2]
    if result.denominator!=1 or result.numerator<0:return state
    # Intermediate stays in volatile local memory only. Native transform still needed.
    length=(result.numerator.bit_length()+7)//8
    state['intermediaire_32_octets']=length==32
    return state

def _colon_hex(h:str)->str:
    h=h.replace(':','').upper()
    if len(h)!=64 or any(c not in '0123456789ABCDEF' for c in h):
        raise ValueError('invalid_certificate_sha256')
    return ':'.join(h[i:i+2] for i in range(0,64,2))


class TuyaSigner:
    """tuya-mobile compatible candidate algorithm; requires a genuine reference."""
    def __init__(self, identity: APKIdentity, embedded_key:str):
        if not 10<=len(embedded_key)<=256 or not embedded_key.isascii():
            raise ValueError('invalid_embedded_key')
        self._id=identity
        self._key=embedded_key

    def material(self)->str:
        a=self._id
        return f'{a.package}_{_colon_hex(a.cert_hash)}_{self._key}_{a.app_secret}'

    def channel_key(self)->str:
        a=self._id
        msg=f'{a.package}_{_colon_hex(a.cert_hash)}'
        return hmac.new(a.app_id.encode(),msg.encode(),hashlib.sha256).hexdigest()[8:16]

    def derive_key(self,request_id:str,ecode:str|None=None)->bytes:
        s=self.material()+(('_'+ecode) if ecode else '')
        return hmac.new(request_id.encode(),s.encode(),hashlib.sha256).hexdigest()[:16].encode()

    def sign_candidate(self,canonical:str,mode:str)->str:
        if mode=='sha256_material':k=hashlib.sha256(self.material().encode()).digest()
        elif mode=='raw_material':k=self.material().encode()
        else: raise ValueError('invalid_signing_mode')
        return hmac.new(k,canonical.encode(),hashlib.sha256).hexdigest()

    def verify_reference(self,canonical:str,expected:str)->str|None:
        if len(expected)!=64 or any(ch not in '0123456789abcdefABCDEF' for ch in expected):
            raise ValueError('invalid_reference_signature')
        for mode in ('sha256_material','raw_material'):
            if hmac.compare_digest(self.sign_candidate(canonical,mode),expected.lower()):
                return mode
        return None


def canonical_string(params:dict[str,str])->str:
    allowed={'a','v','lat','lon','lang','deviceId','appVersion','ttid','isH5','h5Token','os','clientId','postData','time','requestId','et','n4h5','sid','chKey','sp'}
    parts=[]
    for k in sorted(params):
        v=params[k]
        if not v or k not in allowed:continue
        if k=='postData':
            d=hashlib.md5(v.encode(),usedforsecurity=False).hexdigest()
            v=d[8:16]+d[:8]+d[24:]+d[16:24]
        parts.append(f'{k}={v}')
    return '||'.join(parts)


def sanitized_preflight(identity:APKIdentity)->dict[str,object]:
    return {
        'diagnostic':'smart_aosu_oem_preflight_b7',
        'package_verifie':identity.package=='com.glazero.android',
        'app_id_present':bool(identity.app_id),
        'app_secret_present':bool(identity.app_secret),
        'certificat_v2_sha256_present':len(identity.cert_hash)==64,
        'image_t_s_presente':identity.t_s_bmp[:2]==b'BM',
        'image_fixed_key_presente':identity.fixed_key_bmp[:2]==b'BM',
        'ancien_format_bmp_compatible':bmp_legacy_format_compatible(identity.app_id,identity.t_s_bmp),
        'inspecteur_natif_v2':inspect_native_bmp_v2(identity.app_id,identity.t_s_bmp),
        'cle_integree_dechiffree':False,
        'signature_oem_verifiee':False,
        'login_uid_tuya':False,
        'appel_reseau':0,
        'aucun_secret_affiche':True,
    }


def do_token_request(identity:APKIdentity, signer:TuyaSigner, mode:str, *, uid:str,country_code:str,ttid:str,device_id:str,endpoint:str)->dict[str,object]:
    # No password, no MQTT, no camera controls. Single network call.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from urllib.parse import urlencode
    if not country_code.isdigit() or len(country_code)>4 or not uid or len(uid)>256:
        raise ValueError('invalid_uid_parameters')
    if not ttid or len(ttid)>100:raise ValueError('missing_ttid')
    if not device_id or len(device_id)>128:raise ValueError('missing_real_installation_id')
    parsed=urlparse(endpoint)
    if parsed.scheme!='https' or parsed.hostname not in {'a1.tuyaeu.com','a1-eu.iotbing.com'} or parsed.path!='/api.json':
        raise ValueError('endpoint_not_allowlisted')
    action='thing.m.user.uid.token.create'
    request_id=secrets.token_hex(16)
    aes_key=signer.derive_key(request_id)
    nonce=secrets.token_bytes(12)
    blob=json.dumps({'countryCode':country_code,'uid':uid},separators=(',',':')).encode()
    postdata=base64.b64encode(nonce+AESGCM(aes_key).encrypt(nonce,blob,None)).decode('ascii')
    form={'a':action,'v':'1.0','clientId':identity.app_id,'os':'Android','appVersion':'5.10.12',
          'chKey':signer.channel_key(),'deviceId':device_id,
          'time':str(int(time.time())),'requestId':request_id,'et':'3',
          'lang':'fr','ttid':ttid,'postData':postdata}
    form['sign']=signer.sign_candidate(canonical_string(form),mode)
    r=urllib_request.Request(endpoint,data=urlencode(form).encode(),headers={'User-Agent':'TY/5.10.12','Content-Type':'application/x-www-form-urlencoded'},method='POST')
    try:
        with urllib_request.urlopen(r,timeout=15) as res:
            data=res.read(65536)
            status=res.status
        payload=json.loads(data)
        if not isinstance(payload,dict):raise ValueError('bad_response')
        encrypted=payload.get('result')
        decoded={}
        if isinstance(encrypted,str) and encrypted:
            raw=base64.b64decode(encrypted,validate=True)
            if len(raw)>28:
                decoded=json.loads(AESGCM(aes_key).decrypt(raw[:12],raw[12:],None))
        # Only booleans; no body/status details or IDs exposed.
        inner=decoded.get('result') if isinstance(decoded,dict) and isinstance(decoded.get('result'),dict) else decoded
        return {'appel_reseau':1,'http_ok':status==200,
                'serveur_accepte':payload.get('success') is True and not payload.get('errorCode'),
                'jeton_present':isinstance(inner,dict) and bool(inner.get('token')),
                'cle_publique_presente':isinstance(inner,dict) and bool(inner.get('publicKey')),
                'secrets_retournes':False}
    except HTTPError:
        return {'appel_reseau':1,'http_ok':False,'serveur_accepte':False,'secrets_retournes':False}
    except (URLError,ValueError,KeyError,TypeError):
        return {'appel_reseau':1,'http_ok':False,'serveur_accepte':False,'erreur':'connexion_ou_reponse_invalide','secrets_retournes':False}


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description='Smart AOSU OEM preflight, sans secrets en sortie')
    p.add_argument('apk',type=Path)
    p.add_argument('--reference-file',type=Path,help='Local JSON {canonical,signature}; never upload it')
    p.add_argument('--uid-token-test',action='store_true',help='At most 1 HTTPS read-only request, only if reference matches')
    p.add_argument('--endpoint',default='https://a1.tuyaeu.com/api.json')
    opt=p.parse_args(argv)
    try:
        identity=load_identity(opt.apk)
        report=sanitized_preflight(identity)
        key=os.environ.get('AOSU_TUYA_EMBEDDED_KEY','')
        mode=None
        if key and opt.reference_file:
            ref=json.loads(opt.reference_file.read_text(encoding='utf-8'))
            if not isinstance(ref,dict):raise ValueError('invalid_reference')
            mode=TuyaSigner(identity,key).verify_reference(ref['canonical'],ref['signature'])
            report['signature_oem_verifiee']=bool(mode)
        if opt.uid_token_test:
            if mode is None:
                report['etat']='bloque_signature_non_verifiee'
            elif not all(os.environ.get(k) for k in ('AOSU_TUYA_UID','AOSU_TUYA_TTID','AOSU_TUYA_DEVICE_ID')):
                report['etat']='bloque_parametres_uid_ttid_ou_installation_manquants'
            else:
                report.update(do_token_request(identity,TuyaSigner(identity,key),mode,
                    uid=os.environ['AOSU_TUYA_UID'],country_code=os.environ.get('AOSU_TUYA_COUNTRY','33'),
                    ttid=os.environ['AOSU_TUYA_TTID'],device_id=os.environ['AOSU_TUYA_DEVICE_ID'],endpoint=opt.endpoint))
                report['etat']='requete_effectuee'
        else:report['etat']='inspection_hors_ligne'
        print(json.dumps(report,ensure_ascii=False,indent=2));return 0
    except Exception as exc:
        # Generic error only: prevent accidental token/endpoint leakage.
        print(json.dumps({'diagnostic':'smart_aosu_oem_preflight_b7','etat':'erreur_locale',
                          'categorie':type(exc).__name__,'appel_reseau':0,
                          'aucun_secret_affiche':True},ensure_ascii=False,indent=2))
        return 2

if __name__=='__main__':raise SystemExit(main())
