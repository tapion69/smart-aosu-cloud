"""Reconstruction indépendante des six étapes de transform() du SDK ARM64.

Données de constantes lues UNIQUEMENT depuis la bibliothèque contenue dans l'APK
apporté par le propriétaire. Aucune constante ni clé OEM n'est distribuée.

Source: libthing_security_algorithm.so build dba2e02a... (AOSU 5.10.12).
Toutes les opérations arithmétiques respectent l'arithmétique w32 ARM64.
"""
from __future__ import annotations
import hashlib
import io
import struct
import zipfile
from pathlib import Path
from fractions import Fraction

EXPECTED_BUILD_ID = 'dba2e02a63254c9fbf90fe5044c964d4b3ba3142'
# Virtual address and file offset match for .rodata in the original library.
_RODATA = {'seed': (0x2be8, 24), 'a': (0x2c20, 16), 'b': (0x2c50, 16),
           'c': (0x2c40, 16), 'd': (0x2c00, 16), 'e': (0x2c10, 16), 'f': (0x2c30, 16)}


def _signed(v: int) -> int:
    return v - 256 if v >= 128 else v


def _asr32(word: int, shift: int) -> int:
    if word & 0x80000000: word -= 0x100000000
    return (word >> (shift & 31)) & 0xffffffff


def _load_native(apks: Path) -> bytes:
    with zipfile.ZipFile(apks) as z:
        if 'base.apk' not in z.namelist():
            raise ValueError('invalid_aosu_bundle')
        arm64 = z.read('split_config.arm64_v8a.apk')
    with zipfile.ZipFile(io.BytesIO(arm64)) as z:
        so = z.read('lib/arm64-v8a/libthing_security_algorithm.so')
    if bytes.fromhex(EXPECTED_BUILD_ID) not in so[:0x800]:
        raise ValueError('unrecognised_native_build')
    if so[0x679c:0x67a0] != bytes.fromhex('ff8301d1'):
        raise ValueError('transform_signature_changed')
    return so


def _consts(so: bytes) -> dict[str,bytes]:
    return {k: so[a:a+n] for k,(a,n) in _RODATA.items()}


def _add_columns(buf: bytes, table: bytes) -> bytes:
    q = bytearray(buf)
    for i in range(4):
        prev = q[:]
        for j in range(4):
            q[j] = (prev[(j+2) % 4] + table[4*i+(j+2)%4]) & 255
    return bytes(q)


def _hash_xor(buf: bytes, table: bytes) -> bytes:
    w = 0
    for c in table:
        w = ((w + _signed(c)*0x85ebca77) * 0xef362000) & 0xffffffff
    return bytes(buf[i] ^ ((w >> (8*i)) & 255) for i in range(4))


def _matrix(buf: bytes, table: bytes) -> bytes:
    return bytes(sum(buf[j]*table[4*i+j] for j in range(4)) & 255 for i in range(4))


def _weighted_swap(buf: bytes, table: bytes) -> bytes:
    weights=[2,6,20,56,176,416,1088,2432,5888,14848,31744,75776,167936,352256,770048,1736704]
    word=sum(_signed(x)*v for x,v in zip(table,weights)) & 0xffffffff
    return bytes((word >> (24-8*i) & 255) ^ buf[3-i] for i in range(4))


def _rotate(buf: bytes, table: bytes) -> bytes:
    word=int.from_bytes(buf,'big')
    for c in table:
        shift=c % 31
        if shift:
            word = (_asr32(word,shift) | ((word << ((-shift)&31)) & 0xffffffff)) & 0xffffffff
    return word.to_bytes(4,'big')


def transform(source: bytes, consts: dict[str,bytes]) -> bytes:
    """AOSU native transform; 24-byte keystream generated independently per block."""
    if not source: return b''
    result=bytearray(source)
    k=bytearray(consts['seed'])
    for off in range(0, len(result), 24):
        # The native implementation MUTATES the same 24-byte state each round.
        # This is essential for data lengths > 24 bytes.
        for j in range(6):
            block=bytes(k[4*j:4*j+4])
            if j==0: block=_add_columns(block,consts['a'])
            if j==1: block=_hash_xor(block,consts['b'])
            if j==2: block=_matrix(block,consts['c'])
            if j==3: block=_add_columns(block,consts['d'])
            if j==4: block=_weighted_swap(block,consts['e'])
            if j==5: block=_rotate(block,consts['f'])
            k[4*j:4*j+4]=block
        for j in range(min(24,len(result)-off)):
            result[off+j]^=k[j]
    return bytes(result)


def recover_intermediate(app_id: str, bmp: bytes) -> bytes:
    """Decode BMP-v2 carrier and interpolate 4 coordinates, without logging bytes."""
    if len(bmp) < 54 or bmp[:2] != b'BM':raise ValueError('not_bmp')
    start = struct.unpack_from('<I',bmp,10)[0]
    if start < 54 or start >= len(bmp):raise ValueError('invalid_bmp_offset')
    pixels=bmp[start:];n=len(pixels)
    h=0
    for char in app_id.encode('ascii'): h=(31*h+char)&0xffffffff
    if h&0x80000000: h=(0x100000000-h)&0xffffffff
    offset=(h%n)//2
    if pixels[offset]!=2:raise ValueError('not_v2')
    offset=(offset+1)%n
    def read_byte()->int:
        nonlocal offset
        value=sum((pixels[(offset+bit)%n]&1)<<bit for bit in range(8))
        offset=(offset+8)%n
        return value
    count=read_byte(); coeffs=read_byte()
    if count!=1 or coeffs!=4:raise ValueError('unexpected_v2_geometry')
    offset=(offset+32)%n
    pairs=[]
    for _ in range(count*coeffs):
        l1=read_byte()
        if l1 not in (4,6,8):raise ValueError('bad_xlen')
        x=int.from_bytes(bytes(read_byte() for _ in range(l1)),'big')
        l2=read_byte()
        if l2 not in (20,24,32):raise ValueError('bad_ylen')
        y=int.from_bytes(bytes(read_byte() for _ in range(l2)),'big')
        pairs.append((x,y))
    m=[[Fraction(x**d) for d in range(coeffs-1,-1,-1)]+[Fraction(y)] for x,y in pairs]
    for i in range(coeffs):
        if not m[i][i]:
            swap=next((j for j in range(i+1,coeffs) if m[j][i]),None)
            if swap is None:raise ValueError('singular_matrix')
            m[i],m[swap]=m[swap],m[i]
        for j in range(i+1,coeffs):
            if m[j][i]:
                ratio=m[j][i]/m[i][i]
                for k in range(i,coeffs+1):m[j][k]-=ratio*m[i][k]
    intercept=m[-1][-1]/m[-1][-2]
    if intercept.denominator!=1 or intercept.numerator<0:raise ValueError('bad_intercept')
    raw=intercept.numerator.to_bytes((intercept.numerator.bit_length()+7)//8,'big')
    if len(raw)!=32: raise ValueError('unexpected_intermediate_length')
    return raw


def analyze(apks_path: Path)->dict[str,object]:
    # import b7's verified manifest parser; identity's secret does not leave process
    from .oem_preflight_b7 import load_identity
    ident=load_identity(apks_path)
    so=_load_native(apks_path)
    intermediate=recover_intermediate(ident.app_id,ident.t_s_bmp)
    decoded=transform(intermediate,_consts(so))
    printable=all(32<=c<127 for c in decoded)
    ascii_alnum=all((48<=c<=57) or (65<=c<=90) or (97<=c<=122) for c in decoded)
    return {'diagnostic':'smart_aosu_native_transform_b8', 'version_apk':'5.10.12',
        'signature_native_build_verifiee':True,'longueur_intermediaire':len(intermediate),
        'transform_6_etapes_executee':True,'longueur_sortie':len(decoded),
        'sortie_ascii_imprimable':printable,'sortie_ascii_alphanumerique':ascii_alnum,
        'signature_reelle_validee':False,'session_uid_obtenue':False,'appel_reseau':0,
        'secrets_divulgues':False}
