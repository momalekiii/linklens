# Known limitations and review checklist

- [ ] Confirm this exact version on Telegram with single/multiple links and failures.
- [ ] Establish supported platform network cancellation and total execution limits.
- [ ] Test redirects and DNS rebinding/private-network access protections.
- [ ] Review generic probe authorization and report access controls.
- [ ] Audit all secondary UI for unqualified SAFE / CLEAN / grade language.
- [ ] Establish data retention, deletion and full-URL redaction policy.
- [ ] Verify stale feed refresh/retry and upstream rate-limit behavior.
- [ ] Test positive and negative matches for each indicator type, including APKs.
- [ ] Review external provider response schemas and false positives/negatives.
- [ ] Independently audit dependencies and reproduce behavioral evidence.

A hash manifest is an integrity aid, not a signature. Runtime activation secrets
are intentionally withheld. Source review is not a promise of secure operation.
