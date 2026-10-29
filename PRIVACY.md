# Data handling disclosure

This document describes the published source, not a verified deployment policy.

## Stored data
The SQLite schema includes Telegram user ID, first name, optional username,
language, administrator flag, preferences, scan counters and timestamps. Scan
rows include user ID, submitted URL, normalized URL, final URL, domain, scores,
full JSON reports and timestamps. Feed snapshots and configuration values are
also persisted. Configuration may contain API credentials in the private instance.

**URLs may contain sensitive path, query or fragment data.** No comprehensive
redaction, automatic retention expiry or verified user-deletion workflow is
established by this release. The 15-minute report reuse window is not a deletion
policy. Do not submit password-reset, invitation, session or private document links.

## Outbound disclosure
- Telegram handles bot messages and metadata under its own terms.
- The website inspector requests the submitted target and may follow redirects.
  Destination operators can observe requests and URLs; GET requests may have effects.
- DNS providers receive queried hostnames; RDAP and CT services receive domains.
- URLScan public search receives the target hostname; enabled authenticated scan
  submission can disclose the full URL to URLScan.
- Optional VirusTotal, Google Safe Browsing and IPQualityScore adapters can send
  full URLs when configured; AbuseIPDB and IP geolocation receive IP addresses.
- GitHub-hosted feeds and HIBP receive feed-download requests. Matching against a
  cached feed is local and does not itself submit an email address to HIBP.

No claim is made that all URLs are anonymous, that data is encrypted at rest by
this application, or that secrets are held in a dedicated secret vault. Access
controls and host storage protections require deployment-specific verification.

## Publication boundary
The release archive contains code and documentation, not user databases, scan
logs, credentials or activation preimages. Review the integrity and release audit
files for the checks performed on this archive.
