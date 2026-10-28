# 🔍 LinkLens Security & Privacy Audit Guide

This document helps users and independent security reviewers verify how **LinkLens** works under the hood without hidden telemetry, spyware, or unauthorized data collection.

---

## 1. Zero Hidden Telemetry & Network Transparency

Every external HTTP request in LinkLens occurs openly inside `tgcloud/lib/providers/`:

| File | Outbound Endpoints Contacted | Purpose |
|---|---|---|
| `tgcloud/lib/providers/httpInspector.js` | User-submitted URL (up to 6 safe hops) | Inspects HTTP status, redirect chain, OWASP security headers, and static phishing/skimmer DOM patterns |
| `tgcloud/lib/providers/domainDnsSsl.js` | `cloudflare-dns.com`, `rdap.org`, `crt.sh` | Verifies DNS (`A`/`MX`/`SPF`/`DMARC`/`CAA`), domain age, and SSL Certificate Transparency logs |
| `tgcloud/lib/providers/iranIntel.js` | `haveibeenpwned.com/api/v3/breaches`, `github.com/miladnouri/motmaenbash-data`, `github.com/Leakfarsi/Leakfa-Alert`, `github.com/Nooshdaroo-Code/Kaveh` | Checks public breach records, phishing blacklists, official Shaparak gateways, and APK malware SHA-256 hashes |
| `tgcloud/lib/providers/{virustotal,safeBrowsing,urlscan,ipReputation}.js` | VirusTotal v3, Google Safe Browsing v4, URLScan.io, AbuseIPDB v2, IPQualityScore | Queries external threat-intelligence vendors for known malware/phishing verdicts |

No user messages unrelated to URL scanning are forwarded anywhere, and zero third-party analytics trackers exist in `index.html` or `src/`.

---

## 2. Application Security & Isolation Controls

- **Strict SSRF Protection (`tgcloud/lib/urlUtils.js`)**: Blocks loopback (`127.0.0.0/8`, `::1`), RFC-1918 private networks (`10/8`, `172.16/12`, `192.168/16`), link-local metadata endpoints (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), and `.local` / `.internal` hostnames on initial input and on every HTTP redirect hop.
- **Per-User Scan Isolation (`tgcloud/endpoints/getScan.js`)**: Enforces strict `tg_id` ownership verification so one user cannot enumerate or view another user's private scan report (`FORBIDDEN` against IDOR).
- **User-Controlled Data Deletion (`tgcloud/endpoints/getHistory.js` & `tgcloud/handlers/callback_query.js`)**: Users can permanently wipe their personal scan history at any time from either the Bot (`/history` → Clear) or Mini App.
- **Pure ECMAScript V8 Isolate Execution (`tgcloud/lib/v8Runtime.js`)**: Built directly on pure ES2022 primitives (`sha256HexPure`, `parseUrlPure`, `utf8Encode`, `utf8Decode`) with zero opaque third-party runtime dependencies inside `tgcloud/`.
- **Official Instance Verification (`tgcloud/lib/instanceGuard.js`)**: Protects users from counterfeit/fake clone bots via a one-way SHA-256 cryptographic commitment (`OFFICIAL_SEAL_SHA256`) checked across every chat handler and API endpoint.
