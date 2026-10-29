import { EndpointError } from 'sdk';
import { getConfigMap, setConfigValue, getEngineStatuses } from '../lib/secrets.js';
import { isUserAdmin, claimAdminIfNone } from '../lib/usersRepo.js';
import { assertAuthorizedInstance, verifyActivationKey, isInstanceActivated } from '../lib/instanceGuard.js';
import { diagnoseSources } from '../lib/sourceDiagnostics.js';
import { runFullSecurityScan } from '../lib/scanner.js';

// ============================================================================
// endpoints/ownerOps.js — Owner Operations Endpoint (no user-facing UI)
// ============================================================================
// There is no Mini App. This is the single serverless endpoint in the project,
// and it exists only so the owner's deploy pipeline (`deploy.mjs`) can seed
// runtime configuration into cloud SQLite and probe the isolate.
//
// Every action requires BOTH:
//   1. the 256-bit activation preimage matching OFFICIAL_SEAL_SHA256, and
//   2. an authenticated owner/admin identity (ctx.initData.user.id)
//
// Actions:
//   { action: 'probe' }                       -> isolate + layer health report
//   { bootstrapOwner: true, keys: {...} }     -> seed config (first deploy)
//   { keys: {...} }                           -> update config as admin
// ============================================================================

function requireIdentity(ctx) {
  const tgUser = ctx?.initData?.user;
  if (!tgUser?.id) {
    throw new EndpointError('Authenticated owner identity required.', { code: 'UNAUTHORIZED' });
  }
  return tgUser;
}

export default async function (input, ctx) {
  const tgUser = requireIdentity(ctx);
  let cfg = await getConfigMap();
  const keys = input?.keys && typeof input.keys === 'object' ? input.keys : {};

  if (input?.action === 'diagnoseSources') {
    assertAuthorizedInstance(cfg);
    if (!(await isUserAdmin(tgUser.id, cfg))) throw new EndpointError('Administrator required.', {code:'FORBIDDEN'});
    return diagnoseSources(input);
  }

  // --- probe: verify the isolate executes and report layer readiness --------
  if (input?.action === 'probe' || input?.probe === true) {
    const engines = await getEngineStatuses(input?.lang || 'en');
    let scan = null;
    if (input?.url) {
      const res = await runFullSecurityScan({ rawUrl: String(input.url), tgId: tgUser.id });
      scan = res?.ok
        ? { verdict: res.report.verdict, riskScore: res.report.riskScore, grade: res.report.grade, limited: res.report.limited, sources: res.report.sourceResults }
        : { error: res?.error || 'SCAN_FAILED' };
    }
    return {
      ok: true,
      instanceAuthorized: isInstanceActivated(cfg),
      engines,
      scan,
    };
  }

  // --- bootstrapOwner: first-time activation --------------------------------
  if (input?.bootstrapOwner) {
    const candidate = keys.INSTANCE_ACTIVATION_KEY || cfg.INSTANCE_ACTIVATION_KEY;
    if (!verifyActivationKey(candidate)) {
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
    throw new EndpointError('Administrator authorization required.', { code: 'FORBIDDEN' });
  }

  for (const [k, v] of Object.entries(keys)) {
    if (v !== undefined) await setConfigValue(k, v);
  }

  const engines = await getEngineStatuses(input?.lang || 'en');
  return { ok: true, engines };
}
