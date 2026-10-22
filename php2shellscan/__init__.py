"""php2shellscan — exposure scanner for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)."""

__version__ = "1.0.0"

# PHP2Shell advisory (2026-10-21): fixed branches / minimal patch branches.
FIXED_VERSIONS = {
    "8.5": (8, 5, 12),
    "8.4": (8, 4, 27),
    "8.3": (8, 3, 36),
    "8.2": (8, 2, 35),
}

# Branches no longer regularly supported; the PHP team published minimal
# source patches only. Anything at/below these is affected by at least one
# of the two CVEs (per Wiz Research, versions >= 5.4 are affected).
EOL_BRANCHES = ("8.1", "8.0", "7.4")

CVE_109618 = "CVE-2026-109618"  # OOM corruption: upload-progress unserializer UAF, memory disclosure
CVE_109619 = "CVE-2026-109619"  # OOM corruption: fatal backtrace UAF, OPcache type confusion
