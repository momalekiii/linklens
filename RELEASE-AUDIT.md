# Publication checks — v2.2.0 audit candidate

## Automated checks performed
- 28 published JavaScript modules passed Node syntax checks (not runtime validation).
- No matches for the known private activation-preimage format, the supplied personal Telegram ID, Bot API token pattern, Telegram Serverless credential pattern, common GitHub token patterns or private-key headers.
- No deployment scripts, private test harness, credentials directory, environment files, databases, dependency directories or nested deployment archives included.
- Public runtime modules copied byte-for-byte from the 2.2.0 candidate; private owner files omitted.
- Third-party attribution and restrictive original-software license included.

These are bounded checks, not a professional audit or a proof of absence of secrets.
Human review before publishing is still recommended. The original activation hash
commitment is intentionally public; the activation preimage is not included.

## Evidence boundary
The private suite reported 26 passing tests and workspace network diagnostics
returned data for nine keyless source groups. The private test harness and raw
execution logs are not bundled. Telegram deployment verification remains pending.
This release must not be advertised as fully operational or security-certified.

## Integrity
MANIFEST.sha256 lists every payload file except itself. Its hash does not sign
the release. SHA256SUMS.txt alongside the archive hashes the entire ZIP. Anyone
who can alter both files can replace their hashes; publish signatures separately
if stronger authenticity evidence is needed.
