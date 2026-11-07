"""Optional, explicitly consented short diagnostic capture of decrypted P2P media.

Never uploads data, writes credentials, or stores MQTT/SDP/control channel material.
Only the already authenticated / already decrypted video-conversation records
are stored, with an obvious data-at-rest privacy warning in documentation.

Binary format: magic AOSUMEDIA27\0, followed by (uint32 LE length, record bytes)*.
The records can contain actual views from a private camera: HIGHLY SENSITIVE.
"""
from __future__ import annotations
import os
import secrets
import struct
from pathlib import Path
from typing import Any

MAGIC=b'AOSUMEDIA27\x00'
MAX_FILE_BYTES=256*1024
MAX_RECORD_BYTES=128*1024
MAX_RECORDS=300

class LocalMediaCapture:
    def __init__(self, directory: str) -> None:
        self.directory=Path(directory)
        self.path: Path | None=None
        self.records=0
        self.bytes_video=0
        self.error=False
        self.limit_reached=False

    def feed(self, record: bytes) -> None:
        if self.error or self.limit_reached or not isinstance(record, bytes):
            return
        if len(record)==0 or len(record)>MAX_RECORD_BYTES:
            self.limit_reached=True
            return
        if self.records>=MAX_RECORDS or self.bytes_video+len(record)+4 > MAX_FILE_BYTES-len(MAGIC):
            self.limit_reached=True
            return
        try:
            if self.path is None:
                self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
                self.path=self.directory/('media_b27_'+secrets.token_hex(8)+'.aosudump')
                fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as out:
                    out.write(MAGIC)
            if self.path is None:
                self.error=True
                return
            # Separate append in a context manager guarantees close even if
            # an unrelated KCP/network exception interrupts the media probe.
            with self.path.open('ab') as out:
                out.write(struct.pack('<I',len(record)))
                out.write(record)
            self.records+=1
            self.bytes_video+=len(record)+4
        except OSError:
            self.error=True

    def result(self) -> dict[str,Any]:
        return {
            'diagnostic':'aosu_capture_media_locale_b27',
            'capture_explicite_autorisee':True,
            'fichier_cree':bool(self.path and self.records),
            'enregistrements_sauvegardes':self.records,
            'octets_sauvegardes':self.bytes_video + (len(MAGIC) if self.records else 0),
            'limite_atteinte':self.limit_reached,
            'erreur_ecriture':self.error,
            'chemin_local':str(self.path) if self.path and self.records else None,
            'contenu_potentiellement_prive':True,
            'envoi_reseau_des_donnees':False,
            'inclus_dans_diagnostics':False,
            'aucun_secret_ajoute_volontairement':True,
        }
