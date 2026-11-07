"""Manual, consented, strictly local decode of the last AOSU media dump.

This service DOES NOT contact the cloud/camera, replay credentials or publish media.
Optionally stores one JPG with chmod 0600; no image in HA state/logs/response.
"""
from __future__ import annotations
import secrets
import shutil
import subprocess
from pathlib import Path
from .tuya_hevc_rtp import read_capture


def _jpeg_size(data:bytes) -> tuple[int,int] | None:
    if len(data)<4 or data[:2]!=b'\xff\xd8':return None
    i=2
    while i+4<=len(data):
        if data[i]!=0xff:
            i+=1;continue
        marker=data[i+1];i+=2
        if marker in (0xd8,0xd9) or 0xd0<=marker<=0xd7:continue
        if i+2>len(data):return None
        n=int.from_bytes(data[i:i+2],'big')
        if n<2 or i+n>len(data):return None
        if marker in (0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf) and n>=7:
            h=int.from_bytes(data[i+3:i+5],'big')
            w=int.from_bytes(data[i+5:i+7],'big')
            return (w,h) if 1<=w<=8192 and 1<=h<=8192 else None
        i+=n
    return None


def decode_latest_capture(directory:str, *, user_confirmed:bool=False,
                          save_private_preview:bool=False) -> dict:
    out={
        'diagnostic':'aosu_capture_hevc_decode_b28',
        'analyse_exclusivement_locale':True,
        'appels_reseau':0, 'commandes_camera':0,
        'apercu_prive_enregistre':False,
        'donnees_video_brutes_retournees':False,
        'secrets_retournes':False,
    }
    if not user_confirmed:
        return {**out,'etat':'confirmation_analyse_locale_requise'}
    root=Path(directory)
    if not root.is_dir():
        return {**out,'etat':'aucune_capture_locale'}
    try:
        candidates=sorted((p for p in root.glob('media_b27_*.aosudump')
                           if p.is_file() and not p.is_symlink()),
                          key=lambda p:p.stat().st_mtime_ns, reverse=True)
        if not candidates:
            return {**out,'etat':'aucune_capture_locale'}
        chosen=candidates[0]
        parser=read_capture(chosen)
        out['capture_trouvee']=True
        out['nom_capture_locale']=chosen.name
        out.update(parser.report())
        if not out['hevc_structure_complete']:
            return {**out,'etat':'structure_hevc_incomplete'}
        ffmpeg=shutil.which('ffmpeg')
        out['ffmpeg_disponible']=bool(ffmpeg)
        if ffmpeg is None:
            return {**out,'etat':'ffmpeg_absent'}
        command=[ffmpeg,'-hide_banner','-nostdin','-loglevel','error',
                 '-threads','2','-f','hevc','-i','pipe:0','-frames:v','1',
                 '-q:v','3','-f','image2pipe','-vcodec','mjpeg','pipe:1']
        try:
            proc=subprocess.run(command,input=parser.stream(),stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,timeout=15,check=False)
        except (subprocess.TimeoutExpired,OSError):
            return {**out,'etat':'echec_ou_timeout_ffmpeg'}
        jpeg=proc.stdout
        size=_jpeg_size(jpeg) if jpeg.startswith(b'\xff\xd8') and jpeg.endswith(b'\xff\xd9') else None
        out['jpeg_decode_avec_ffmpeg']=size is not None
        if size is None:
            return {**out,'etat':'pas_d_image_jpeg_decodable'}
        out['largeur_video']=size[0]
        out['hauteur_video']=size[1]
        if save_private_preview:
            if len(jpeg)>6*1024*1024:
                return {**out,'etat':'apercu_trop_volumineux'}
            filename='preview_b28_'+secrets.token_hex(8)+'.jpg'
            path=root/filename
            fd=__import__('os').open(path,__import__('os').O_CREAT|__import__('os').O_EXCL|__import__('os').O_WRONLY,0o600)
            with __import__('os').fdopen(fd,'wb') as stream:
                stream.write(jpeg)
            out['apercu_prive_enregistre']=True
            out['chemin_apercu_prive']=str(path)
        out['etat']='image_hevc_decodee_avec_succes'
        return out
    except (ValueError,OSError,PermissionError):
        return {**out,'etat':'capture_corrompue_ou_lecture_interdite'}
