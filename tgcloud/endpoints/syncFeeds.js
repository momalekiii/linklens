import { EndpointError } from 'sdk';
import { getIranFeedTelemetry } from '../lib/providers/iranIntel.js';
import { getConfigMap, getEngineStatuses } from '../lib/secrets.js';
import { isUserAdmin } from '../lib/usersRepo.js';
import { assertAuthorizedInstance } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/syncFeeds.js — Authenticated Admin Threat Feed Sync
// ============================================================================

export default async function (input, ctx) {
  const tgUser = ctx?.initData?.user;
  if (!tgUser?.id) {
    throw new EndpointError('Telegram WebApp authentication required.', { code: 'UNAUTHORIZED' });
  }

  const cfg = await getConfigMap();
  assertAuthorizedInstance(cfg);

  if (!(await isUserAdmin(tgUser.id, cfg))) {
    throw new EndpointError('Administrator authorization required.', { code: 'FORBIDDEN' });
  }

  const force = input?.force !== false;
  const counts = await getIranFeedTelemetry(force);
  const engines = await getEngineStatuses(input?.lang || 'en');
  return {
    ok: true,
    counts,
    engines,
  };
}
