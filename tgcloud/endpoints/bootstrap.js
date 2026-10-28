import { ensureUser, getUserHistory, getGlobalStats, isUserAdmin } from '../lib/usersRepo.js';
import { getConfigMap, getEngineStatuses } from '../lib/secrets.js';
import { formatFinding } from '../lib/i18n.js';
import { assertAuthorizedInstance } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/bootstrap.js — Initial Mini App Handshake (`POST /api/bootstrap`)
// ============================================================================

export default async function (_input, ctx) {
  const cfg = await getConfigMap();
  assertAuthorizedInstance(cfg);

  const tgUser = ctx?.initData?.user || { id: 0, first_name: 'Guest' };
  const user = await ensureUser(tgUser);
  const lang = user.lang || 'en';
  const [historyRows, stats, engines, admin] = await Promise.all([
    getUserHistory(tgUser.id, 10),
    getGlobalStats(tgUser.id),
    getEngineStatuses(lang),
    isUserAdmin(tgUser.id, cfg),
  ]);

  return {
    user: {
      id: tgUser.id,
      firstName: user.firstName || tgUser.first_name || 'Guest',
      username: user.username || tgUser.username || null,
      lang: user.lang,
      langSelected: Boolean(user.langSelected && user.lang),
      isAdmin: admin,
    },
    stats,
    engines: admin
      ? engines
      : engines.map((eng) => ({
          id: eng.id,
          name: eng.name,
          configured: eng.configured,
          tier: eng.tier,
          masked: eng.tier === 'live_api' ? eng.masked : (eng.configured ? 'Active' : 'Standby'),
        })),
    history: historyRows.map((row) => ({
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
