# Security policy

## Supported review target
Version 2.2.0 is the current public audit snapshot. It is not independently
certified or confirmed production-ready. Only the original authorized instance
is intended for operation; this publication is for static review.

## Reporting
Prefer the repository's **Security → Report a vulnerability** workflow if the
owner has enabled GitHub private vulnerability reporting. If unavailable, open
only a non-sensitive issue requesting a private contact channel. Do not disclose
a live exploit, private user URL, credential, activation value or personal data
in public. No response-time promise or bug-bounty program is established here.

Include the affected version, file/function, impact, minimal redacted evidence,
and suggested mitigation. Avoid scanning third parties without permission.

## Priority review areas
- URL normalization, embedded links, Unicode and public/private destination checks.
- Redirect handling, DNS rebinding and SSRF resistance; full coverage is not proven.
- Missing timers, platform execution limits, failed edits and cancellation paths.
- Cached-feed freshness and provider failures versus genuine negative results.
- HTML escaping, callback authorization and data isolation between users.
- Persistent URL/configuration data and absence of a demonstrated retention policy.
- Owner diagnostics, bootstrap and probe authorization. The generic probe branch
  currently runs before the administrator check used by source diagnostics; review
  its platform identity assumptions and potential information exposure.
- Heuristic verdicts, internal SAFE fields and secondary UI labels despite limited
  source coverage. No clean result should be presented as a guarantee.

The activation guard restricts an unmodified instance; public source can be
modified. It is not a substitute for runtime authentication or legal rights.

## Release checks are limited
Credential-pattern checks and file hashing reduce accidental publication risk.
They are not a proof of absence of secrets or vulnerabilities. See RELEASE-AUDIT.md.
