# 🛡 LinkLens — Official Source Code & Security Audit Repository

> **📌 Transparency & Audit Notice (All Rights Reserved)**
> This repository publishes the source code of **LinkLens** strictly so users and security reviewers can **inspect and verify** that all link-scanning logic, database tables, and Mini App views are transparent, clean, and privacy-safe.
> **Self-hosting, cloning, modifying, or operating unauthorized copies of this bot is strictly prohibited** ([`LICENSE`](./LICENSE)) and cryptographically locked at runtime (`tgcloud/lib/instanceGuard.js`).

---

## ✨ Architecture Overview

LinkLens runs directly on **Telegram Serverless** isolated V8 workers backed by isolated cloud SQLite (`tgcloud/schema.js`) and a same-origin Web Scanner Mini App (`src/`):

- **Pure V8 Isolate Engine (`tgcloud/lib/v8Runtime.js`)**: Zero Node/browser host dependencies; pure ES2022 implementations of SHA-256, RFC-3986 URL parsing, UTF-8 encoding/decoding, and Base64URL.
- **Single-Message Live Scan Updates (`tgcloud/lib/chatFlow.js`)**: Responds to any sent or forwarded link with strictly one message and edits that single message live across all scan stages (`[▱▱▱▱] → [▰▰▰▰]`).
- **Multi-Layer Security & Breach Verification**:
  - **Threat & Malware Vendors**: VirusTotal v3 (`90+` engines), Google Safe Browsing v4, URLScan.io v1, AbuseIPDB v2, and IPQualityScore AI (`tgcloud/lib/providers/`).
  - **Open Breach & Anti-Phishing Intelligence**: Have I Been Pwned (`api/v3/breaches`), MotmaenBash (`CC-BY-4.0`), Leakfa (`MIT`), Nooshdaroo Kaveh SHA-256 signatures, and official payment-gateway verification (`tgcloud/lib/providers/iranIntel.js`).
  - **Infrastructure & DOM Forensics**: Cloudflare DNS-over-HTTPS (`SPF`/`DMARC`/`CAA`), IANA RDAP WHOIS age, `crt.sh` SSL Certificate Transparency logs (`tgcloud/lib/providers/domainDnsSsl.js`), and deep OWASP HTTP header + phishing/card-skimmer DOM inspection (`tgcloud/lib/providers/httpInspector.js`).
- **Trilingual Interface (`فارسی` • `English` • `Русский`)**: Full RTL/LTR support across both Telegram Bot menus and the Mini App UI (`tgcloud/lib/i18n.js`, `src/uiStrings.js`).

---

## 📂 Repository File Map (Audit Index)

```text
├── SECURITY.md                        # Line-by-line privacy & network audit guide
├── LICENSE                            # Public Audit License (All Rights Reserved)
├── index.html                         # Mini App HTML shell (zero external trackers)
├── src/
│   ├── apiClient.js                   # Telegram Serverless WebApp RPC client
│   ├── main.js                        # Mini App UI state & interactive scan view
│   ├── styles.css                     # Native Telegram theme-adaptive styles
│   └── uiStrings.js                   # Trilingual UI translations (FA / EN / RU)
└── tgcloud/
    ├── schema.js                      # Cloud SQLite schema (users, scans, cache)
    ├── handlers/
    │   ├── message.js                 # Incoming/forwarded message & command handler
    │   ├── callback_query.js          # Inline report tabs & action callbacks
    │   ├── channel_post.js            # Channel link scan handler
    │   ├── inline_query.js            # Inline mode (`@Bot <url>`) handler
    │   └── stopped_message_generation.js
    ├── endpoints/                     # Authenticated Mini App Serverless endpoints
    │   ├── bootstrap.js
    │   ├── scanLink.js
    │   ├── getScan.js
    │   ├── getHistory.js
    │   ├── setLanguage.js
    │   ├── saveApiKeys.js
    │   └── syncFeeds.js
    └── lib/
        ├── instanceGuard.js           # SHA-256 Official Instance Seal (Anti-Clone)
        ├── v8Runtime.js               # Pure ES2022 SHA-256, URL parser & UTF-8 utils
        ├── urlUtils.js                # Link extraction, spoof check & SSRF blocker
        ├── scanner.js                 # Multi-engine scan orchestrator & scoring
        ├── chatFlow.js                # Single-message live real-time edit executor
        ├── reportFormatter.js         # Telegram HTML report renderer
        ├── keyboards.js               # Bot API 9.4+ colored inline keyboards
        ├── secrets.js                 # Runtime config loader (empty defaults)
        ├── usersRepo.js               # Per-user SQLite isolation & history queries
        ├── botProfile.js              # Localized Telegram bot commands & description
        ├── tgSend.js                  # Resilient Telegram Bot API transport wrapper
        └── providers/
            ├── domainDnsSsl.js        # DoH DNS, RDAP WHOIS & crt.sh SSL verifier
            ├── httpInspector.js       # Redirect-safe HTTP & phishing DOM inspector
            ├── ipReputation.js        # AbuseIPDB v2 & IPQualityScore threat AI
            ├── iranIntel.js           # HIBP, MotmaenBash, Leakfa & Kaveh feeds
            ├── safeBrowsing.js        # Google Safe Browsing v4 lookup
            ├── urlscan.js             # URLScan.io sandbox lookup
            └── virustotal.js          # VirusTotal v3 multi-engine lookup
```

---

## 📚 Open Threat & Breach Intelligence Attribution

- **MotmaenBash Open Dataset**: [`miladnouri/motmaenbash-data`](https://github.com/miladnouri/motmaenbash-data) — **CC-BY-4.0**
- **Leakfa Breach Intelligence**: [`Leakfarsi/Leakfa-Alert`](https://github.com/Leakfarsi/Leakfa-Alert) — **MIT**
- **Nooshdaroo Kaveh Project**: [`Nooshdaroo-Code/Kaveh`](https://github.com/Nooshdaroo-Code/Kaveh)
- **Have I Been Pwned**: [`haveibeenpwned.com/API/v3`](https://haveibeenpwned.com/API/v3)

---

## ⚖️ Copyright & License

Copyright © 2026 [momalekiii.github.io](https://momalekiii.github.io) — **All Rights Reserved.**
Published strictly for public security & privacy code auditing. See [`LICENSE`](./LICENSE) and [`SECURITY.md`](./SECURITY.md).
