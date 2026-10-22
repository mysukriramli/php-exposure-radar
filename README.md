# PHP Exposure Radar

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Autonomous Machine Feed](https://img.shields.io/badge/Feed-Autonomous_6h-blue.svg)](data/today.json)

An autonomous software runtime & supply-chain radar engineered for **AI coding agents (Cursor, Devin, Copilot), DevOps bots, and automated container patching pipelines**.

Monitors critical PHP core unauthenticated remote code execution vulnerabilities (**PHP2Shell: CVE-2026-109618, CVE-2026-109619**, and **CGI Injection: CVE-2024-4577**), tracks active vs. End-Of-Life (EOL) runtime versions, and outputs machine-readable patching directives.

---

## 📡 Live Machine Endpoints (Zero-Auth / Fastly Edge CDN)

| Endpoint | Format | Consumer Purpose |
| :--- | :--- | :--- |
| [`data/today.json`](data/today.json) | JSON | Machine-readable exposure scores, branch status, and directives. |
| [`data/llms.txt`](data/llms.txt) | Markdown | Token-efficient context digest for Cursor and Claude prompt hooks. |
| `data/archive/YYYY/MM/` | JSON | Permanent historical log of PHP runtime patch cadence over time. |

---

## 🤖 Directives Emitted

- `EMERGENCY_PATCH_CORE`: Runtime is supported but vulnerable to PHP2Shell; upgrade to safe patch version immediately.
- `ISOLATE_EOL_RUNTIME`: Runtime is End-Of-Life (PHP 8.1, 8.0, 7.x, 5.x) and will not receive vendor patches; isolate network or upgrade branch.
- `APPLY_WAF_VIRTUAL_PATCH`: Intermediate defense directive when immediate binary rebuilds are blocked.
- `AUDIT_COMPOSER_POLICY`: Scan Composer packages for supply-chain retagging and unverified lifecycle scripts.
- `UP_TO_DATE`: Runtime is running confirmed patched versions (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+).

---

## 💡 How AI Coding Agents Ingest This in Cursor / Claude Code

Add this rule to your project's `.cursorrules` or system prompt:

```text
Before deploying or auditing PHP Dockerfiles, Kubernetes manifests, or CI pipelines:
1. Fetch [https://raw.githubusercontent.com/mysukriramli/php-exposure-radar/main/data/today.json](https://raw.githubusercontent.com/mysukriramli/php-exposure-radar/main/data/today.json)
2. Check the "runtime_exposure_matrix" for your target PHP version.
3. If directive is EMERGENCY_PATCH_CORE or ISOLATE_EOL_RUNTIME, update base images (e.g., php:8.3-fpm) to minimum patched versions.
