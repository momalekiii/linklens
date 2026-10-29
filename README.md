# LinkLens

### Telegram-native link and threat-intelligence assessment

LinkLens inspects submitted and forwarded links in Telegram, combines local URL heuristics with public intelligence sources, and updates a single chat report. The runtime target is **Telegram Serverless**, not an external hosting provider.

**Version: 2.2.0 · Public source for audit only · Not open source**

> **Release status:** this is a source-review release, not a production certification. Local behavioral tests passed and keyless providers responded in workspace tests. This version has **not yet been confirmed working end-to-end in the live Telegram bot**. A low score does not establish safety.

## Capabilities

- Persian, English and Russian interfaces; first-run language selection.
- Automatic URL detection in supported message text, captions and forwarded content.
- In-place report updates and multi-link report selection.
- URL-pattern heuristics and supported HTTP/HTML inspection.
- Cached indicator matching against MotmaenBash, Kaveh, Leakfa-Alert and public HIBP breach data.
- DNS, domain-registration and certificate-transparency lookups.
- URLScan public historical domain search.
- No Mini App, external website scanner or frontend in this snapshot.

Telegram clients and API compatibility can affect button styling and message rendering. A failed message edit or interrupted runtime can still leave an outdated report.

## What is actually available?

| Source | Purpose | Credentials / limitations |
|---|---|---|
| MotmaenBash | Hashed domain, URL, package and APK indicators | Public dataset; cached matches, not universal detection |
| Leakfa-Alert | Regional domain breach history | Public feed; not a direct Leakfa API |
| Kaveh | Malware hash indicators | Public feed; payload hash required for file matching |
| Have I Been Pwned | Website breach history | Public breach catalog, **not** email/account search |
| Cloudflare DoH | DNS posture | Public network requests |
| RDAP | Registration dates and registrar | Registry coverage varies; `.ir` public age unavailable in this implementation |
| Cert Spotter / crt.sh | Certificate history | Historical CT records, **not** live certificate validation |
| URLScan | Existing domain scan intelligence | Public search; no new sandbox submission without a key |
| HTTP inspector | Redirect destination, headers and supported content signals | Fetches submitted website; availability and body limits apply |

Optional adapters for VirusTotal, Google Safe Browsing, AbuseIPDB and IPQualityScore remain in the source. They require operator credentials and were **not enabled or verified** in the keyless release.

## Evidence, not marketing

Workspace tests for the 2.2.0 candidate loaded 1,280 MotmaenBash indicators, 101 Leakfa-Alert domains, 539 Kaveh signatures and 983 HIBP records. A known Adobe breach matched. DNS, RDAP, HTTP inspection, URLScan search and Cert Spotter responded for the test target. These are point-in-time observations, **not uptime guarantees or Telegram-runtime verification**.

The private development suite reported **26 passing behavioral tests**. That harness contains private owner fixtures and is intentionally not published here; this repository does not claim independently reproducible behavioral testing. The included manifest verifies file integrity only.

## Important limitations

- External SDK calls are no longer disabled just because `setTimeout` is missing.
- Where timers exist, the layer budget is six seconds. In a timerless isolate there is **no independent enforceable request watchdog**; slow sources can still delay scanning.
- Cached feeds can be stale. Source metadata exposes age; a cached snapshot is not a fresh upstream health check.
- General status is configuration/cache information. Inspect per-scan source outcomes rather than treating “enabled” as evidence of success.
- Reports remain marked limited. Internal `SAFE`, grades and numerical scores are heuristics, not a verified security guarantee. Secondary UI and stored fields still require review for misleading labels.
- A breach history does not make a domain a phishing site. Absence from a feed does not make it safe.
- No independent penetration test, privacy audit or full dependency audit has been completed.

## Repository map

```text
tgcloud/schema.js             SQLite schema
 tgcloud/handlers/            Telegram event handlers
 tgcloud/lib/                 Scan orchestration, parsing, rendering and runtime helpers
 tgcloud/lib/providers/       Threat-feed and external-service adapters
 tgcloud/endpoints/ownerOps.js Owner configuration and source diagnostics
 docs/                       Architecture, data handling and verification limits
```

## Public audit boundary

This archive deliberately omits deployment scripts, activation secrets, credentials, databases, private test fixtures, local previews and deployment configuration. The public activation commitment is not the activation secret. **The software guard is not DRM and does not prevent a reader from changing source.**

No setup or self-hosting instructions are provided. Publication permits review under the [audit-only license](LICENSE); it does not grant permission to operate a clone. GitHub platform rights and independently licensed third-party material remain governed by their own terms.

## Review and reporting

Start with [ARCHITECTURE](docs/ARCHITECTURE.md), [PRIVACY](PRIVACY.md), [SECURITY](SECURITY.md), [KNOWN LIMITATIONS](docs/KNOWN-LIMITATIONS.md), [CHANGELOG](CHANGELOG.md) and [ATTRIBUTIONS](ATTRIBUTIONS.md).

Do not submit credentials, activation values, private URLs, user IDs or live exploit payloads in public issues. Follow the private-reporting guidance in SECURITY.md.
