import { ensureUser, getUserHistory, clearUserHistory } from '../lib/usersRepo.js';
import { getConfigMap } from '../lib/secrets.js';
import { formatFinding } from '../lib/i18n.js';
import { assertAuthorizedInstance } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/getHistory.js — Fetch or Clear Authenticated User's Scan History
// ============================================================================

export default async function (input, ctx) {
  const cfg = await getConfigMap();
  assertAuthorizedInstance(cfg);

  const tgUser = ctx?.initData?.user || { id: 0, first_name: 'Guest' };
  const user = await ensureUser(tgUser);
  const lang = input?.lang || user.lang || 'en';

  if (input?.action === 'clear') {
    await clearUserHistory(tgUser.id);
    return { history: [], cleared: true };
  }

  const rows = await getUserHistory(tgUser.id, Math.min(30, Math.max(1, Number(input?.limit || 15))));
  return {
    history: rows.map((row) => ({
      id: row.id,
      inputUrl: row.inputUrl,
      finalUrl: row.finalUrl,
      domain: row.domain,
      riskScore: row.riskScore,
      verdict: row.verdict,
      grade: row.grade,
      durationMs: row.durationMs,
      createdAt: row.createdAt,
      findingsPreview: (row.report?.findings || []).slice(0, 2).map((f) => formatFinding(f, lang)),
    })),
  };
}
