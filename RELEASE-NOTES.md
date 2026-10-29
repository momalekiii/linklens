# LinkLens v2.2.0 — public source audit release

**Pre-release / audit candidate. Not a verified production release.**

This snapshot restores keyless source execution, reuses cached feed intelligence,
adds source-specific diagnostics, and adds a certificate-transparency alternative.
It includes corrections for duplicate preview URLs and misleading zero-coverage
reports introduced in earlier iterations.

## Validation
- 26 private local behavioral tests passed.
- Source syntax and release preflight passed.
- Workspace network diagnostics succeeded for the nine keyless source groups.
- A known HIBP breach match was exercised.
- Full live Telegram end-to-end verification remains outstanding.

## Known blockers to production assurance
No enforceable independent deadline in timerless isolates; provider uptime is not
guaranteed; stale data remains possible; scan/privacy/authorization paths require
further audit. Numerical risk and internal SAFE fields are not safety guarantees.

## Asset
`linklens-public-audit-v2.2.0.zip` contains public review source and documentation.
It does not include deployment tools, activation secrets, private test fixtures,
credentials, databases or the owner kit. Do not attach private deployment ZIPs
to a public release. See LICENSE before use.

Recommended GitHub release setting: **mark as pre-release**. Tag: `v2.2.0-audit`.
