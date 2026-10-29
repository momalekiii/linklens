# Changelog

## 2.2.0 — public audit candidate
- Restored SDK source execution in timerless runtimes instead of silently skipping it.
- Reused persisted feed snapshots for local matching, with stale/fresh metadata.
- Added source diagnostics and per-scan source outcomes.
- Fixed URLScan HTTP failures being reported as successful searches.
- Marked DNS unavailable when both address queries fail.
- Added Cert Spotter CT lookup, with crt.sh fallback.
- Invalidated older report-cache versions.
- Documented timerless latency, privacy and verification limits.

## 2.1.1
- Corrected empty-coverage reports: no A+ headline, false TLS failure or all-clean claim.

## 2.1.0
- Addressed preview links counted as extra inputs and HTTP-to-HTTPS scoring.
- Introduced limited-assessment messaging. Timerless external skipping from this
  version was a regression and was removed in 2.2.0.

## 2.0.1–2.0.2
- Replaced unsupported SQL-expression write values with primitive timestamps.
- Added provider fallbacks and top-level scan error handling.
- Removed Mini App surfaces; improved Persian rendering.
