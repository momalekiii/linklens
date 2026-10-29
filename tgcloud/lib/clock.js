// ============================================================================
// lib/clock.js — plain-integer timestamps for SQLite writes
// ============================================================================
// The Telegram Serverless DB layer validates every value passed to `.values()`
// or `.set()` and rejects non-primitive objects (including `sql` expressions).
// `sql` tags are valid only in schema `.default()`, `check()`, `index()` and raw
// queries — never as a bound value. So timestamps for writes are plain numbers.
// ============================================================================

export function nowSec() {
  return Math.floor(Date.now() / 1000);
}

export function nowMs() {
  return Date.now();
}
