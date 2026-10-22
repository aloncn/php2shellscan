"""Version parsing and PHP2Shell vulnerability determination."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from . import EOL_BRANCHES, FIXED_VERSIONS

_VERSION_RE = re.compile(r"(?:^|[^\d])((?:[5-9])\.\d+(?:\.\d+)?)")


def parse_php_version(text: str) -> Optional[tuple]:
    """Extract a PHP version tuple like (8, 2, 34) from arbitrary text."""
    if not text:
        return None
    m = _VERSION_RE.search(text)
    if not m:
        return None
    parts = tuple(int(p) for p in m.group(1).split("."))
    while len(parts) < 3:
        parts += (0,)
    return parts


@dataclass
class VersionFinding:
    version: Optional[tuple]
    branch: Optional[str]
    vulnerable: bool
    fixed_in: Optional[str] = None
    status: str = "unknown"          # vulnerable | patched | eol_unpatched | unknown
    evidence: list = field(default_factory=list)


def _cmp(a: tuple, b: tuple) -> int:
    return (a > b) - (a < b)


def assess_version(version_text: str) -> VersionFinding:
    """Decide whether a detected PHP version is vulnerable to PHP2Shell.

    Rules (from the PHP security release of 2026-10-21):
      * 8.5.x  < 8.5.12, 8.4.x < 8.4.27, 8.3.x < 8.3.36, 8.2.x < 8.2.35
        -> vulnerable (CVE-2026-109618 & CVE-2026-109619).
      * <= 8.1 (down to 5.4) -> affected by at least one CVE; only minimal
        source patches exist for 7.4/8.0/8.1, none for <= 7.3.
      * Newer than the fixed version in its branch -> patched.
    """
    version = parse_php_version(version_text)
    if version is None:
        return VersionFinding(None, None, False, status="unknown")

    branch = f"{version[0]}.{version[1]}"

    if branch in FIXED_VERSIONS:
        fixed = FIXED_VERSIONS[branch]
        if _cmp(version, fixed) < 0:
            return VersionFinding(
                version, branch, True, fixed_in=".".join(map(str, fixed)),
                status="vulnerable",
            )
        return VersionFinding(version, branch, False, status="patched")

    # Branch not in the supported set: EOL (<= 8.1) or pre-8.2 vintage.
    # All versions >= 5.4 released before the 2026-10-21 advisory carry at
    # least one of the two bugs.
    return VersionFinding(
        version, branch, True,
        fixed_in="upgrade to 8.2.35+ / 8.3.36+ / 8.4.27+ / 8.5.12+ (or apply the minimal branch patch)",
        status="eol_unpatched",
    )
