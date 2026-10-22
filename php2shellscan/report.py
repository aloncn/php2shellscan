"""Per-target verdicts and report rendering (JSON / human table)."""

from __future__ import annotations

import json
from typing import Dict, List

from . import CVE_109618, CVE_109619
from .probes import ProbeResult

MITIGATIONS = {
    "upgrade": (
        "Patch PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (or apply the minimal "
        "source patch for 7.4/8.0/8.1). This is the only complete fix."
    ),
    "worker_recycle": (
        "Frequently recycle PHP-FPM/opcache worker processes "
        "(pm.max_requests low value) to bound cross-request state reuse."
    ),
    "memory_limit": (
        "Keep memory_limit low and enforced; monitor for memory-limit fatals."
    ),
    "waf": (
        "WAF vendors (Cloudflare/Fastly/Akamai/Imperva) shipped php2shell "
        "rules; enable multipart anomaly filtering and oversized-PHPSESSID "
        "blocking."
    ),
    "monitor": (
        "Alert on: multipart requests followed by memory-limit errors/HTTP "
        "500 bursts, oversized or URL-encoded PHPSESSID cookies, unexplained "
        "PHP worker churn."
    ),
}


def verdict(res: ProbeResult, *, assume_vulnerable: bool = False) -> Dict:
    """Combine version + signal findings into a per-target verdict."""
    v = res.version
    cves = [CVE_109618, CVE_109619]
    if not res.reachable:
        return {
            "target": res.url, "verdict": "unreachable", "severity": "none",
            "cves": [], "summary": "Target did not respond to HTTP GET /.",
            "recommendations": [],
        }

    if v is None or v.status == "unknown":
        php_hidden = bool(res.signals.get("php_detected_version_hidden"))
        if assume_vulnerable:
            how = ("PHP detected but version hidden" if php_hidden
                   else "PHP presence not remotely confirmable (headers "
                        "hidden, no leaking source)")
            return {
                "target": res.url, "verdict": "assumed_vulnerable",
                "severity": "critical (unconfirmed)", "cves": cves,
                "php_version": None,
                "summary": (f"{how}. Since every PHP >= 5.4 build released "
                            "before the 2026-10-21 advisory carries at least "
                            "one of the two bugs, policy treats it as "
                            "vulnerable until proven patched."),
                "recommendations": [MITIGATIONS["upgrade"],
                                    MITIGATIONS["monitor"]],
            }
        return {
            "target": res.url, "verdict": "unknown", "severity": "unknown",
            "cves": [],
            "php_version": None,
            "summary": ("PHP version not detected. Check manually "
                        "(expose_php off / hidden headers are common)."),
            "recommendations": [MITIGATIONS["upgrade"]],
        }

    if v.status == "patched":
        return {
            "target": res.url, "verdict": "patched", "severity": "none",
            "cves": [], "php_version": ".".join(map(str, v.version)),
            "summary": f"PHP {'.'.join(map(str, v.version))} >= fixed release "
                       f"({v.fixed_in}) for its branch.",
            "recommendations": [MITIGATIONS["monitor"]],
        }

    # vulnerable / eol_unpatched
    up = res.signals.get("upload_progress_probe", {}) or {}
    preconditions = []
    if up.get("session_cookie_issued"):
        preconditions.append("session module active on multipart pre-init path "
                             "(CVE-2026-109618 upload-progress chain)")
    if up.get("oversized_session_cookie"):
        preconditions.append("oversized PHPSESSID observed (possible memory-"
                             "disclosure primitive)")

    if v.status == "eol_unpatched":
        severity = "critical"
        summary = (f"PHP {'.'.join(map(str, v.version))} is EOL and affected by "
                   f"at least one of {CVE_109618}/{CVE_109619} (all >= 5.4 "
                   f"pre-advisory builds carry the bugs); no official fix for "
                   f"this branch.")
    else:
        severity = "critical"
        summary = (f"PHP {'.'.join(map(str, v.version))} < {v.fixed_in}: "
                   f"vulnerable to {CVE_109618} and {CVE_109619} "
                   f"(CVSS 9.2, pre-auth RCE / memory disclosure).")

    recs = [MITIGATIONS["upgrade"]]
    if up.get("session_cookie_issued"):
        recs += [MITIGATIONS["waf"], MITIGATIONS["worker_recycle"],
                 MITIGATIONS["memory_limit"]]
    recs.append(MITIGATIONS["monitor"])

    return {
        "target": res.url, "verdict": "vulnerable", "severity": severity,
        "cves": cves, "php_version": ".".join(map(str, v.version)),
        "sapi_hint": res.sapi_hint,
        "attack_surface_preconditions": preconditions,
        "summary": summary,
        "recommendations": recs,
    }


def render_table(verdicts: List[Dict]) -> str:
    headers = ("TARGET", "PHP", "VERDICT", "SEVERITY", "CVES", "NOTES")
    rows = []
    for v in verdicts:
        rows.append((
            v["target"],
            v.get("php_version") or "-",
            v["verdict"],
            v["severity"],
            ", ".join(c.replace("CVE-2026-", "") for c in v["cves"]) or "-",
            "; ".join(v.get("attack_surface_preconditions", []))[:60] or
            v["summary"][:60],
        ))
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    out = [line, "-" * len(line)]
    for r in rows:
        out.append("  ".join(c.ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


def render_json(verdicts: List[Dict], results=None) -> str:
    doc = {
        "tool": "php2shellscan",
        "cves": [CVE_109618, CVE_109619],
        "fixed_versions": {"8.2": "8.2.35", "8.3": "8.3.36",
                           "8.4": "8.4.27", "8.5": "8.5.12"},
        "verdicts": verdicts,
    }
    if results is not None:
        doc["raw"] = [
            {
                "url": r.url, "status": r.status, "server": r.server,
                "x_powered_by": r.powered_by, "generator": r.generator,
                "sapi_hint": r.sapi_hint, "cookies": r.cookies,
                "signals": r.signals, "errors": r.errors,
            }
            for r in results
        ]
    return json.dumps(doc, indent=2, ensure_ascii=False)
