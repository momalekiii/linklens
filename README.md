# 🛡 LinkLens — Official Source Code & Security Audit Repository

[![Launch on Telegram](https://img.shields.io/badge/Telegram-Launch_@linklenssbot-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/linklenssbot)

**🚀 Try the live bot on Telegram:** [**@linklenssbot↗**](https://t.me/linklenssbot)

> **📌 Transparency & Audit Notice (All Rights Reserved)**
> This repository publishes the backend source code of **LinkLens** strictly so users and security reviewers can **inspect and verify** that all threat-scanning logic, database schemas, and multi-engine modules are transparent and privacy-safe.
> **Self-hosting, cloning, modifying, or operating unauthorized copies of this bot is strictly prohibited** ([`LICENSE`](./LICENSE)) and cryptographically enforced at runtime (`tgcloud/lib/instanceGuard.js`)[span_0](start_span)[span_0](end_span).

---

## ✨ Architecture & Backend Overview

LinkLens runs directly on **Telegram Serverless** isolated V8 workers (`tgcloud/`)[span_1](start_span)[span_1](end_span):

* **Pure V8 Isolate Engine (`tgcloud/lib/v8Runtime.js`)**: Zero Node/browser host dependencies; pure implementations of SHA-256, URL parsing, and encoding.
* **Multi-Layer Threat & Breach Verification**:
  * **Threat & Malware Vendors**: VirusTotal v3 (`90+` engines), Google Safe Browsing v4, URLScan.io v1, AbuseIPDB v2, and IPQualityScore AI.
  * **Open Breach & Anti-Phishing Intelligence**: Have I Been Pwned (`api/v3/breaches`), MotmaenBash Shaparak verification (`CC-BY-4.0`), Leakfa (`MIT`), and Nooshdaroo Kaveh SHA-256 signatures[span_2](start_span)[span_2](end_span).
* **Infrastructure & DOM Forensics**: Cloudflare DNS-over-HTTPS (`SPF`/`DMARC`/`CAA`), IANA RDAP WHOIS age, certificate transparency logs, and deep OWASP HTTP header + phishing DOM inspection[span_3](start_span)[span_3](end_span).
* **Owner Operations & Diagnostics**: Token-safe source health checks (`tgcloud/lib/sourceDiagnostics.js`)[span_4](start_span)[span_4](end_span) and secure serverless seeding (`tgcloud/endpoints/ownerOps.js`)[span_5](start_span)[span_5](end_span).

---

## 📂 Repository File Map (Audit Index)

```text
├── SECURITY.md                        # Line-by-line privacy & network audit guide[span_6](start_span)[span_6](end_span)
├── PRIVACY.md                         # Data handling and zero-logging policy
├── ATTRIBUTIONS.md                    # Open-source datasets and third-party attributions
├── RELEASE-AUDIT.md                   # Build and cryptographic seal verification log
├── CHANGELOG.md                       # Version history and updates
├── MANIFEST.sha256                    # Cryptographic file manifest
├── LICENSE                            # Public Audit License (All Rights Reserved)[span_7](start_span)[span_7](end_span)
├── docs/
│   ├── ARCHITECTURE.md                # Detailed technical spec & worker design[span_8](start_span)[span_8](end_span)
│   └── KNOWN-LIMITATIONS.md           # Rate limits, timeouts & edge cases[span_9](start_span)[span_9](end_span)
└── tgcloud/
    ├── schema.js                      # Cloud SQLite schema (users, scans, cache)[span_10](start_span)[span_10](end_span)
    ├── endpoints/
    │   └── ownerOps.js                # Secure serverless owner configuration & node probe[span_11](start_span)[span_11](end_span)
    ├── handlers/
    │   ├── message.js                 # Incoming/forwarded message & command handler[span_12](start_span)[span_12](end_span)
    │   ├── callback_query.js          # Inline report tabs & action callbacks[span_13](start_span)[span_13](end_span)
    │   ├── channel_post.js            # Channel link scan handler[span_14](start_span)[span_14](end_span)
    │   ├── inline_query.js            # Inline mode (`@Bot <url>`) handler[span_15](start_span)[span_15](end_span)
    │   └── stopped_message_generation.js
    └── lib/
        ├── instanceGuard.js           # SHA-256 Official Instance Seal (Anti-Clone)[span_16](start_span)[span_16](end_span)
        ├── v8Runtime.js               # Pure ES2022 crypto, URL parser & utilities[span_17](start_span)[span_17](end_span)
        ├── urlUtils.js                # Link extraction, spoof check & SSRF blocker[span_18](start_span)[span_18](end_span)
        ├── scanner.js                 # Multi-engine scan orchestrator & scoring[span_19](start_span)[span_19](end_span)
        ├── chatFlow.js                # Single-message live real-time edit executor[span_20](start_span)[span_20](end_span)
        ├── reportFormatter.js         # Telegram HTML report renderer[span_21](start_span)[span_21](end_span)
        ├── keyboards.js               # Bot API colored inline keyboards[span_22](start_span)[span_22](end_span)
        ├── secrets.js                 # Runtime config loader (empty defaults)[span_23](start_span)[span_23](end_span)[span_24](start_span)[span_24](end_span)
        ├── usersRepo.js               # Per-user SQLite isolation & history queries[span_25](start_span)[span_25](end_span)
        ├── botProfile.js              # Localized Telegram bot commands & descriptions[span_26](start_span)[span_26](end_span)
        ├── tgSend.js                  # Resilient Telegram Bot API transport wrapper[span_27](start_span)[span_27](end_span)
        ├── sourceDiagnostics.js       # Token-safe node health check and source probe[span_28](start_span)[span_28](end_span)
        └── providers/
            ├── domainDnsSsl.js        # DoH DNS, RDAP WHOIS & SSL verifier[span_29](start_span)[span_29](end_span)
            ├── httpInspector.js       # Redirect-safe HTTP & phishing DOM inspector[span_30](start_span)[span_30](end_span)
            ├── ipReputation.js        # AbuseIPDB v2 & IPQualityScore threat AI[span_31](start_span)[span_31](end_span)
            ├── iranIntel.js           # HIBP, MotmaenBash, Leakfa & Kaveh feeds[span_32](start_span)[span_32](end_span)
            ├── safeBrowsing.js        # Google Safe Browsing v4 lookup[span_33](start_span)[span_33](end_span)
            ├── urlscan.js             # URLScan.io sandbox lookup[span_34](start_span)[span_34](end_span)
            └── virustotal.js          # VirusTotal v3 multi-engine lookup[span_35](start_span)[span_35](end_span)
```

---

## 📚 Open Threat & Breach Intelligence Attribution

* **MotmaenBash Open Dataset**: [`miladnouri/motmaenbash-data`](https://github.com/miladnouri/motmaenbash-data) — **CC-BY-4.0**[span_36](start_span)[span_36](end_span)
* **Leakfa Breach Intelligence**: [`Leakfarsi/Leakfa-Alert`](https://github.com/Leakfarsi/Leakfa-Alert) — **MIT**[span_37](start_span)[span_37](end_span)
* **Nooshdaroo Kaveh Project**: [`Nooshdaroo-Code/Kaveh`](https://github.com/Nooshdaroo-Code/Kaveh)[span_38](start_span)[span_38](end_span)
* **Have I Been Pwned**: [`haveibeenpwned.com/API/v3`](https://haveibeenpwned.com/API/v3)[span_39](start_span)[span_39](end_span)

---

## ⚖️ Copyright & License

Copyright © 2026 [momalekiii.github.io](https://momalekiii.github.io) — **All Rights Reserved.**[span_40](start_span)[span_40](end_span)  
Published strictly for public security & privacy code auditing. See [`LICENSE`](./LICENSE), [`SECURITY.md`](./SECURITY.md), and [`ATTRIBUTIONS.md`](./ATTRIBUTIONS.md)[span_41](start_span)[span_41](end_span).
