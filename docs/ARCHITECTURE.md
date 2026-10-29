# Architecture

Telegram handlers parse events, apply instance/configuration checks and user
preferences, extract targets, then delegate to chatFlow and scanner. The chat
flow sends one initial response and edits it for progress and the final report.
Multi-link work is sequential within that flow; slow lookups can accumulate.

Scanner stages cover lexical/HTTP checks, feed and infrastructure requests,
IP reputation, and scoring/persistence. The SDK supplies database, network and
Telegram API functions. Browser/Node host globals are not assumed in runtime code.

Feed providers index public data in memory and SQLite. In 2.2.0 an available
persisted snapshot is reused even after its freshness window. Refresh can be
requested through owner diagnostics. A stale snapshot is labeled stale; this is
not an independent scheduled refresh service.

The public ownerOps endpoint includes bootstrap, configuration, probe and
source-specific diagnostic operations. Inspect its separate authorization
branches rather than assuming they all enforce identical checks.

The manifest hashes the published snapshot. It neither signs the archive nor
proves the deployed bot runs this exact source. No deployed-source attestation
or formal security proof is provided.
