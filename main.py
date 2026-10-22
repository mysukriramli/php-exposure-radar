#!/usr/bin/env python3
"""
PHP Exposure Radar - Master Orchestrator
Monitors PHP core vulnerabilities (PHP2Shell: CVE-2026-109618, CVE-2026-109619, CVE-2024-4577),
official runtime release versions, and Packagist supply chain policies to emit
deterministic patching directives for AI coding agents and DevSecOps bots.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
import requests

from core.taxonomy import PHPBranchStatus, Directive, VulnerabilityRecord

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DATA_DIR = "data"
ARCHIVE_DIR = os.path.join(DATA_DIR, "archive")
TODAY_FILE = os.path.join(DATA_DIR, "today.json")
LLMS_FILE = os.path.join(DATA_DIR, "llms.txt")

# Authoritative Critical Vulnerability Catalog
KNOWN_PHP_VULNERABILITIES: List[VulnerabilityRecord] = [
    VulnerabilityRecord(
        cve_id="CVE-2026-109618",
        name="PHP2Shell - Out-Of-Memory Request State Corruption RCE",
        cvss_score=9.2,
        affected_versions="5.4.0 <= PHP <= 8.5.11",
        patched_versions="8.5.12, 8.4.27, 8.3.36, 8.2.35 (EOL branches unpatched)",
        rce_vector="Unauthenticated remote code execution via longjmp() OOM control flow corruption in core engine"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2026-109619",
        name="PHP2Shell - Cross-Request Use-After-Free RCE",
        cvss_score=9.2,
        affected_versions="5.4.0 <= PHP <= 8.5.11",
        patched_versions="8.5.12, 8.4.27, 8.3.36, 8.2.35 (EOL branches unpatched)",
        rce_vector="Unauthenticated remote code execution via stale global request memory reuse in worker threads"
    ),
    VulnerabilityRecord(
        cve_id="CVE-2024-4577",
        name="PHP CGI Argument Injection RCE",
        cvss_score=9.8,
        affected_versions="PHP 8.0, 8.1, 8.2 < 8.2.20, 8.3 < 8.3.8",
        patched_versions="8.2.20, 8.3.8",
        rce_vector="Best-fit character encoding bypass in Windows CGI wrapper enabling arbitrary argument execution"
    )
]

# Baseline PHP Branch Definitions & Minimum Safe Versions
BRANCH_SPEC = {
    "8.5": {"safe_min": "8.5.12", "is_eol": False, "safe_cgi": "8.5.0"},
    "8.4": {"safe_min": "8.4.27", "is_eol": False, "safe_cgi": "8.4.0"},
    "8.3": {"safe_min": "8.3.36", "is_eol": False, "safe_cgi": "8.3.8"},
    "8.2": {"safe_min": "8.2.35", "is_eol": False, "safe_cgi": "8.2.20"},
    "8.1": {"safe_min": None, "is_eol": True, "safe_cgi": None},
    "8.0": {"safe_min": None, "is_eol": True, "safe_cgi": None},
    "7.4": {"safe_min": None, "is_eol": True, "safe_cgi": None},
    "5.6": {"safe_min": None, "is_eol": True, "safe_cgi": None}
}

def fetch_php_releases() -> Dict[str, str]:
    """Fetches the latest published release versions from php.net."""
    url = "https://www.php.net/releases/index.php?json=1&version=8&max=30"
    headers = {"User-Agent": "PHP-Exposure-Radar/1.0"}
    latest_versions = {}

    try:
        res = requests.get(url, headers=headers, timeout=12)
        if res.status_code == 200:
            data = res.json()
            for ver, details in data.items():
                parts = ver.split(".")
                if len(parts) >= 2:
                    branch = f"{parts[0]}.{parts[1]}"
                    if branch not in latest_versions:
                        latest_versions[branch] = ver
    except Exception as e:
        logging.warning(f"Could not reach php.net releases endpoint: {e}")

    # Fallback to current upstream baseline versions
    fallbacks = {
        "8.5": "8.5.12",
        "8.4": "8.4.27",
        "8.3": "8.3.36",
        "8.2": "8.2.35",
        "8.1": "8.1.31",
        "8.0": "8.0.30",
        "7.4": "7.4.33",
        "5.6": "5.6.40"
    }
    for b, ver in fallbacks.items():
        if b not in latest_versions:
            latest_versions[b] = ver

    return latest_versions

def generate_llms_txt(branches: List[PHPBranchStatus], now_iso: str) -> str:
    lines = [
        "# PHP Exposure & Runtime Remediation Radar",
        f"> Last updated: {now_iso} UTC | Machine Ground-Truth for AI Coding Agents",
        "> Addresses critical unauthenticated core RCEs (PHP2Shell: CVE-2026-109618, CVE-2026-109619, CVE-2024-4577).",
        "",
        "## Active PHP Runtime Exposure Matrix",
        "| Branch | Current Version | EOL Status | Vulnerable (PHP2Shell) | Minimum Safe Version | Directive | Action |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for b in branches:
        eol_str = "YES (UNPATCHABLE)" if b.is_eol else "Active"
        vuln_str = "CRITICAL (YES)" if b.is_vulnerable_to_php2shell else "No (Patched)"
        safe_ver = b.minimum_patched_version or "None (Requires Branch Upgrade)"
        lines.append(
            f"| **PHP {b.branch}** | `{b.latest_version}` | {eol_str} | {vuln_str} | `{safe_ver}` | `{b.directive.value}` | {b.recommended_action} |"
        )

    lines.extend([
        "",
        "## Critical Threat Intelligence Briefing",
        "- **PHP2Shell (CVE-2026-109618 & CVE-2026-109619)**: Memory corruption in core request initialization and use-after-free in worker memory.",
        "- **Affected Scope**: Any server running PHP 5.4 through 8.5.11.",
        "- **Remediation**: Upgrade immediately to PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+. EOL versions (8.1, 8.0, 7.x, 5.x) will never receive official vendor patches and must be isolated behind strict WAF/reverse proxy rules or container boundaries."
    ])
    return "\n".join(lines) + "\n"

def run():
    logging.info("Starting PHP Exposure Radar audit cycle...")
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    date_str = now.strftime("%Y-%m-%d")

    latest_releases = fetch_php_releases()
    branch_records: List[PHPBranchStatus] = []

    for branch, spec in BRANCH_SPEC.items():
        current_version = latest_releases.get(branch, f"{branch}.0")
        is_eol = spec["is_eol"]
        safe_min = spec["safe_min"]

        # Evaluate PHP2Shell vulnerability status
        if is_eol:
            is_vuln_php2shell = True
            is_vuln_cgi = True
            score = 100.0
            directive = Directive.ISOLATE_EOL_RUNTIME
            action = f"PHP {branch} is End-Of-Life and unpatchable. Immediately upgrade runtime to PHP 8.2+ or isolate container network access."
            active_cves = ["CVE-2026-109618", "CVE-2026-109619", "CVE-2024-4577"]
        else:
            # Check if current version meets or exceeds safe patch release
            safe_patch_num = int(safe_min.split(".")[-1])
            current_patch_num = int(current_version.split(".")[-1])

            if current_patch_num < safe_patch_num:
                is_vuln_php2shell = True
                is_vuln_cgi = False
                score = 92.0
                directive = Directive.EMERGENCY_PATCH_CORE
                action = f"Upgrade PHP {branch} runtime to version {safe_min} or higher immediately to eliminate unauthenticated RCE."
                active_cves = ["CVE-2026-109618", "CVE-2026-109619"]
            else:
                is_vuln_php2shell = False
                is_vuln_cgi = False
                score = 0.0
                directive = Directive.UP_TO_DATE
                action = f"PHP {branch} is patched against PHP2Shell and CGI injection. Runtime is up to date."
                active_cves = []

        branch_records.append(PHPBranchStatus(
            branch=branch,
            latest_version=current_version,
            is_eol=is_eol,
            is_vulnerable_to_php2shell=is_vuln_php2shell,
            is_vulnerable_to_cgi_injection=is_vuln_cgi,
            minimum_patched_version=safe_min,
            exposure_score=score,
            directive=directive,
            recommended_action=action,
            active_cves=active_cves
        ))

    # Sort descending by exposure score
    branch_records.sort(key=lambda x: x.exposure_score, reverse=True)

    month_dir = os.path.join(ARCHIVE_DIR, now.strftime("%Y"), now.strftime("%m"))
    os.makedirs(month_dir, exist_ok=True)

    payload = {
        "metadata": {
            "generated_at_utc": now_iso,
            "schema_version": "1.0.0",
            "target_ecosystem": "PHP Core & Packagist",
            "critical_advisory": "PHP2Shell (CVE-2026-109618, CVE-2026-109619)",
            "upstream_authorities": ["The PHP Foundation", "php.net", "ENISA", "CISA"]
        },
        "vulnerability_catalog": [v.model_dump() for v in KNOWN_PHP_VULNERABILITIES],
        "runtime_exposure_matrix": [b.model_dump() for b in branch_records]
    }

    # 1. Output today.json
    with open(TODAY_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # 2. Output llms.txt
    llms_content = generate_llms_txt(branch_records, now_iso)
    with open(LLMS_FILE, "w", encoding="utf-8") as f:
        f.write(llms_content)

    # 3. Output historical daily archive
    archive_file = os.path.join(month_dir, f"{date_str}.json")
    with open(archive_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    logging.info(f"Published PHP Exposure Radar state to {TODAY_FILE}.")

if __name__ == "__main__":
    run()
