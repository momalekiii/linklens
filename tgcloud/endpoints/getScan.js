import { EndpointError } from 'sdk';
import { ensureUser, getScanById, isUserAdmin } from '../lib/usersRepo.js';
import { getConfigMap } from '../lib/secrets.js';
import { formatFinding } from '../lib/i18n.js';
import { assertAuthorizedInstance } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/getScan.js — Load Saved Scan Report by ID (`?scan=<id>`)
// Enforces Official Instance Guard + Strict Per-User Ownership Check (IDOR)
// ============================================================================

export default async function (input, ctx) {
  const tgUser = ctx?.initData?.user || { id: 0, first_name: 'Guest' };
  const scanId = Number(input?.scanId || 0);
  if (!scanId) {
    throw new EndpointError('Missing scan ID.', { code: 'INVALID_ID' });
  }

  const [user, cfg, row] = await Promise.all([
    ensureUser(tgUser),
    getConfigMap(),
    getScanById(scanId),
  ]);

  assertAuthorizedInstance(cfg);

  if (!row || !row.report) {
    throw new EndpointError('Scan report not found.', { code: 'NOT_FOUND' });
  }

  // Enforce strict user isolation so users can only view their own scan history
  if (Number(row.tgId) !== Number(tgUser.id) && !(await isUserAdmin(tgUser.id, cfg))) {
    throw new EndpointError('Access denied for this scan report.', { code: 'FORBIDDEN' });
  }

  const lang = input?.lang || user.lang || 'en';
  return {
    scanId: row.id,
    report: {
      ...row.report,
      findings: (row.report.findings || []).map((f) => ({
        ...f,
        localizedText: formatFinding(f, lang),
      })),
    },
  };
}
