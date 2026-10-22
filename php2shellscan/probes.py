"""HTTP fingerprinting and safe active probes.

Design principle: php2shellscan never attempts exploitation. Triggering the
underlying bugs (CVE-2026-109618 / CVE-2026-109619) requires inducing an
out-of-memory abort in a PHP worker, which crashes/reuses worker memory.
Instead the scanner:

  1. Fingerprints the PHP version from headers/body (passive).
  2. Runs small, bounded, non-crashing probes to collect *configuration and
     behaviour signals* that determine how the attack surface applies:
       - Is the Session module reachable via the multipart upload-progress
         path? (required by the CVE-2026-109618 RCE chain)
       - Does the server expose PHP fatal/memory-limit error output?
       - Anomalous PHPSESSID cookie behaviour on multipart requests
         (baseline length check; the exploit path surfaces oversized,
          URL-encoded session cookies).
  3. Combines everything into a per-target verdict.
"""

from __future__ import annotations

import json
import re
import ssl
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from .versioning import VersionFinding, assess_version, parse_php_version

_GENERATOR_RE = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_PHPINFO_RE = re.compile(r"PHP Version\s*</?[^>]*>?\s*(\d+\.\d+(?:\.\d+)?)", re.I)
_COMPOSER_PHP_RE = re.compile(r'"php"\s*:\s*"[^"]*?(\d+\.\d+)(?:\.\d+)?')
_CREDITS_PATH = "/?=" + "PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000"  # PHP credits page (expose_php=On)
_PHPINFO_PATHS = ("/phpinfo.php", "/info.php", "/test.php", "/php.php")
_COMPOSER_PATHS = ("/composer.lock", "/composer.json")

_MAX_BODY = 512 * 1024
_TIMEOUT_DEFAULT = 8.0


@dataclass
class ProbeResult:
    url: str
    reachable: bool = False
    status: Optional[int] = None
    server: str = ""
    powered_by: str = ""
    cookies: List[str] = field(default_factory=list)
    generator: str = ""
    php_version_text: str = ""
    sapi_hint: str = ""
    signals: Dict[str, object] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    version: Optional[VersionFinding] = None


def _http(method: str, url: str, *, headers: Dict[str, str] = None,
          data: bytes = None, timeout: float = _TIMEOUT_DEFAULT):
    """Perform one request. Returns (status, headers, body_bytes)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urlrequest.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    req.add_header("User-Agent", "php2shellscan/1.0 (exposure assessment)")
    try:
        with urlrequest.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers), resp.read(_MAX_BODY)
    except HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(_MAX_BODY) if e.fp else b""


def _cookie_names(headers: Dict[str, str]):
    """Return (cookie names, raw Set-Cookie values) from response headers."""
    names, values = [], []
    for key, val in headers.items():
        if key.lower() == "set-cookie":
            values.append(val)
            names.append(val.split("=", 1)[0].strip())
    return names, values


def _multipart_body(fields: Dict[str, str], file_field: str = "f",
                    filename: str = "a.txt", content: bytes = b"a") -> tuple:
    boundary = "----php2shellscan" + uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
        )
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n".encode() + content + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    ctype = f"multipart/form-data; boundary={boundary}"
    return body, ctype


def normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/")


# --------------------------------------------------------------------------- probes

def _set_version(res: ProbeResult, evidence: List[str], source: str,
                 text: str) -> bool:
    """Record a version string if it parses; returns True when found."""
    if res.php_version_text:
        return True
    v = parse_php_version(text)
    if v:
        res.php_version_text = ".".join(map(str, v))
        evidence.append(f"{source}: {res.php_version_text} (from {text!r})")
        return True
    return False


def hunt_version_sources(base: str, res: ProbeResult, evidence: List[str],
                         timeout: float) -> None:
    """Layered version discovery for hosts that hide X-Powered-By.

    Ordered by signal quality; each layer is a single small GET:

      1. PHP credits page  /?=PHPB8B5F2A0-...  (served when expose_php=On,
         body contains e.g. "PHP Credits" + version string).
      2. Leftover phpinfo pages: /phpinfo.php, /info.php, /test.php,
         /php.php -- body contains "PHP Version x.y.z".
      3. Exposed composer.json / composer.lock -- the "require.php"
         platform constraint gives a minimum version (weaker signal, but
         usually a lower bound, not the running version).
      4. X-Powered-By / Server retried on /index.php (some proxies strip
         headers only on the cached "/" route).
    """
    def get(path: str):
        try:
            return _http("GET", base + path, timeout=timeout)
        except (URLError, OSError, ValueError):
            return None, None, b""

    # 1. credits page
    _, headers, body = get(_CREDITS_PATH)
    if headers:
        text = body.decode("utf-8", "replace")
        if "PHP Credits" in text or "php credits" in text.lower():
            _set_version(res, evidence, "credits-page", text)
            res.signals["php_credits_exposed"] = True
        # some builds still emit X-Powered-By only here
        if not res.php_version_text:
            _set_version(res, evidence, "credits-header",
                         headers.get("X-Powered-By", ""))
    if res.php_version_text:
        return

    # 2. leftover phpinfo pages
    for path in _PHPINFO_PATHS:
        status, headers, body = get(path)
        if status != 200 or not body:
            continue
        text = body.decode("utf-8", "replace")
        if "phpinfo()" in text or _PHPINFO_RE.search(text):
            if _set_version(res, evidence, f"phpinfo-page {path}", text):
                res.signals["phpinfo_page_exposed"] = path
                return

    # 3. composer files (lower bound only)
    for path in _COMPOSER_PATHS:
        status, headers, body = get(path)
        if status != 200 or not body:
            continue
        text = body.decode("utf-8", "replace")
        m = _COMPOSER_PHP_RE.search(text)
        if m and _set_version(res, evidence, f"composer {path}", m.group(1)):
            res.signals["composer_php_constraint_is_lower_bound"] = True
            return

    # 4. header retry on /index.php
    _, headers, _ = get("/index.php")
    if headers:
        _set_version(res, evidence, "index-header",
                     headers.get("X-Powered-By", "") + " " +
                     headers.get("Server", ""))


def scan_target(target: str, *, timeout: float = _TIMEOUT_DEFAULT,
                active: bool = True) -> ProbeResult:
    base = normalize_target(target)
    res = ProbeResult(url=base)
    evidence: List[str] = []

    # ---- passive fingerprint -------------------------------------------------
    try:
        status, headers, body = _http("GET", base + "/", timeout=timeout)
        res.reachable = True
        res.status = status
        res.server = headers.get("Server", "")
        res.powered_by = headers.get("X-Powered-By", "")
        names, raw_cookies = _cookie_names(headers)
        res.cookies = names
        m = _GENERATOR_RE.search(body.decode("utf-8", "replace"))
        if m:
            res.generator = m.group(1)

        for text in (res.powered_by, res.server):
            if "php" in text.lower():
                evidence.append(f"header: {text.strip()}")
        if res.php_version_text == "" and evidence:
            res.php_version_text = evidence[0].split(":", 1)[1].strip()
        if raw_cookies:
            res.signals["cookie_names"] = names
    except (URLError, OSError, ValueError) as e:
        res.errors.append(f"GET /: {e}")
        return res

    # Headers hidden (expose_php=Off)? Try layered non-header version sources.
    if not res.php_version_text:
        hunt_version_sources(base, res, evidence, timeout)

    res.version = assess_version(res.php_version_text or
                                 res.powered_by + " " + res.server)
    if not res.version.evidence and evidence:
        res.version.evidence = evidence

    # PHP present (cookie/header/behaviour) but exact version undiscoverable?
    php_confirmed = bool(res.php_version_text or "PHPSESSID" in res.cookies or
                         "php" in (res.powered_by + res.server).lower())
    if php_confirmed and res.version.status == "unknown":
        res.signals["php_detected_version_hidden"] = True

    # ---- SAPI hint: PHP2Shell applies to PHP-FPM / CGI / mod_php workers ----
    pb = (res.powered_by or "").lower()
    if "fpm" in pb or "fastcgi" in pb:
        res.sapi_hint = "FastCGI/FPM"
    elif "cgi" in pb:
        res.sapi_hint = "CGI"
    elif res.server.lower().find("apache") >= 0 and "php" in pb:
        res.sapi_hint = "mod_php (likely)"
    else:
        res.sapi_hint = "unknown"

    if not active:
        return res

    # ---- active probe 1: multipart + PHP_SESSION_UPLOAD_PROGRESS ------------
    # A *tiny* benign multipart request that names PHP_SESSION_UPLOAD_PROGRESS.
    # It exercises the same pre-init request path as the CVE-2026-109618
    # upload-progress chain without any oversized allocation. Signals:
    #   * PHPSESSID issued on a multipart request even though the app never
    #     calls session_start()  -> session module active on the vulnerable
    #     path (RCE chain precondition).
    try:
        body, ctype = _multipart_body({"PHP_SESSION_UPLOAD_PROGRESS": "p2s-probe"})
        status3, headers3, _ = _http(
            "POST", base + "/",
            headers={"Content-Type": ctype, "Content-Length": str(len(body))},
            data=body, timeout=timeout,
        )
        names3, raw3 = _cookie_names(headers3)
        sessid = next((c for c in raw3 if c.lower().startswith("phpsessid=")), None)
        res.signals["upload_progress_probe"] = {
            "status": status3,
            "session_cookie_issued": bool(sessid),
            "phpsessid_length": (len(sessid.split("=", 1)[1].split(";")[0])
                                 if sessid else None),
        }
        if sessid:
            res.signals["upload_progress_probe"]["note"] = (
                "session module engages on the multipart pre-init path; "
                "CVE-2026-109618 upload-progress chain precondition present"
            )
    except (URLError, OSError, ValueError) as e:
        res.errors.append(f"upload_progress probe: {e}")

    # ---- active probe 2: baseline PHPSESSID length (memory-disclosure signal)
    # The disclosed memory-leak primitive URL-encodes freed heap contents into
    # the PHPSESSID cookie. We record the normal cookie size so defenders can
    # alert on oversized values (typical id <= 64 chars).
    try:
        up = res.signals.get("upload_progress_probe", {})
        if up.get("phpsessid_length") is not None:
            length = up["phpsessid_length"]
            up["oversized_session_cookie"] = bool(length > 128)
            if length > 128:
                up["note"] = (up.get("note", "") +
                              " | oversized PHPSESSID: investigate for the "
                              "CVE-2026-109618 memory-disclosure primitive")
    except Exception:  # noqa: BLE001 - signal hardening only
        pass

    return res


def scan_targets(targets: List[str], *, timeout: float = _TIMEOUT_DEFAULT,
                 active: bool = True, concurrency: int = 8):
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        return list(pool.map(
            lambda t: scan_target(t, timeout=timeout, active=active), targets))
