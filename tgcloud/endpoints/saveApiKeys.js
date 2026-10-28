import { EndpointError } from 'sdk';
import { getConfigMap, setConfigValue, getEngineStatuses } from '../lib/secrets.js';
import { isUserAdmin, claimAdminIfNone } from '../lib/usersRepo.js';
import { assertAuthorizedInstance, verifyActivationKey } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/saveApiKeys.js — Authenticated Owner Configuration Endpoint
// Requires BOTH:
//   1. Verified owner instance seal (`INSTANCE_ACTIVATION_KEY` -> SHA-256)
//   2. Verified Telegram WebApp `ctx.initData.user.id` (admin authorization)
// ============================================================================

export default async function (input, ctx) {
  const tgUser = ctx?.initData?.user;
  if (!tgUser?.id) {
    throw new EndpointError('Telegram WebApp authentication required.', {
      code: 'UNAUTHORIZED',
    });
  }

  let cfg = await getConfigMap();
  const keys = input?.keys && typeof input.keys === 'object' ? input.keys : {};

  if (input?.bootstrapOwner) {
    if (!verifyActivationKey(keys.INSTANCE_ACTIVATION_KEY || cfg.INSTANCE_ACTIVATION_KEY)) {
      throw new EndpointError('Valid owner cryptographic seal required to initialize instance.', {
        code: 'UNAUTHORIZED_INSTANCE',
      });
    }
    const claim = await claimAdminIfNone(tgUser.id, cfg, tgUser);
    if (!claim.ok && !(await isUserAdmin(tgUser.id, cfg))) {
      throw new EndpointError('Admin role already locked.', { code: claim.reason });
    }
    if (keys.INSTANCE_ACTIVATION_KEY) {
      await setConfigValue('INSTANCE_ACTIVATION_KEY', keys.INSTANCE_ACTIVATION_KEY);
    }
    cfg = await getConfigMap();
  }

  assertAuthorizedInstance(cfg);

  if (!(await isUserAdmin(tgUser.id, cfg))) {
    throw new EndpointError('Administrator authorization required.', {
      code: 'FORBIDDEN',
    });
  }

  for (const [k, v] of Object.entries(keys)) {
    if (v !== undefined) {
      await setConfigValue(k, v);
    }
  }

  const engines = await getEngineStatuses(input?.lang || 'en');
  return { ok: true, engines };
}
