"""Privacy-first, bounded, public HTTPS thumbnail fetch from AOSU inventory.

AOSU may return an HTTPS redirect to a CDN. Follow at most two redirects,
validate each destination, and never send AOSU credentials or request bodies.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests

MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 2
_REDIRECT_CODES = (301, 302, 303, 307, 308)


def validate_image_url(url: str) -> bool:
    """Only accept public HTTPS DNS names, standard TLS port, no userinfo."""
    if not isinstance(url, str) or len(url) > 4096:
        return False
    try:
        part = urlsplit(url)
        if part.scheme.lower() != "https" or not part.hostname:
            return False
        if part.port not in (None, 443) or part.username or part.password:
            return False
        hostname = part.hostname.rstrip(".").lower()
        if (len(hostname) > 253 or "." not in hostname or
                any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in hostname)):
            return False
        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            pass
        ips = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
        if not ips:
            return False
        for row in ips:
            addr = ipaddress.ip_address(row[4][0])
            if not addr.is_global:
                return False
    except (ValueError, OSError, UnicodeError):
        return False
    return True


def fetch_thumbnail(url: str) -> tuple[bytes | None, str | None, str]:
    """Return image bytes/type and privacy-safe result code, never the URL.

    The result includes a sanitized HTTP status (e.g. http_403) when necessary.
    Redirect counts in successful results indicate when a CDN was involved.
    """
    if not url:
        return None, None, "reference_absente"
    session = requests.Session()
    session.trust_env = False
    target = url
    redirects = 0
    try:
        while True:
            if not validate_image_url(target):
                return None, None, "url_non_autorisee" if redirects == 0 else "redirection_non_autorisee"
            # AOSU session cookies must never cross over to a CDN destination.
            session.cookies.clear()
            with session.get(
                target, timeout=(5, 12), stream=True, allow_redirects=False,
                verify=True, headers={"Accept": "image/jpeg,image/png,image/webp"},
            ) as response:
                code = response.status_code
                if code in _REDIRECT_CODES:
                    if redirects >= MAX_REDIRECTS:
                        return None, None, "trop_de_redirections"
                    location = response.headers.get("Location")
                    if not location or len(location) > 4096:
                        return None, None, f"redirection_{code}_sans_destination"
                    target = urljoin(target, location)
                    redirects += 1
                    continue
                if code != 200:
                    # Do not read response bodies, headers, URLs or server messages.
                    return None, None, f"http_{code}" if type(code) is int and 100 <= code <= 599 else "http_inattendu"
                length = response.headers.get("Content-Length", "")
                if length.isdigit() and int(length) > MAX_IMAGE_BYTES:
                    return None, None, "image_trop_volumineuse"
                buffer = bytearray()
                for chunk in response.iter_content(chunk_size=32768):
                    buffer.extend(chunk)
                    if len(buffer) > MAX_IMAGE_BYTES:
                        return None, None, "image_trop_volumineuse"
                content = bytes(buffer)
                if content.startswith(b"\xff\xd8\xff"):
                    mime = "image/jpeg"
                elif content.startswith(b"\x89PNG\r\n\x1a\n"):
                    mime = "image/png"
                elif len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
                    mime = "image/webp"
                else:
                    return None, None, "format_image_non_reconnu"
                return content, mime, (f"image_valide_apres_{redirects}_redirection(s)" if redirects else "image_valide")
    except requests.RequestException:
        return None, None, "echec_reseau"
    finally:
        session.close()
