import { EndpointError } from 'sdk';
import { isValidLang } from '../lib/i18n.js';
import { setUserLanguage, isUserAdmin } from '../lib/usersRepo.js';
import { getConfigMap, getEngineStatuses } from '../lib/secrets.js';
import { assertAuthorizedInstance } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/setLanguage.js — Save User Language (`fa` | `en` | `ru`)
// ============================================================================

export default async function (input, ctx) {
  const tgUser = ctx?.initData?.user || { id: 0, first_name: 'Guest' };
  const lang = String(input?.lang || '').toLowerCase().trim();

  if (!isValidLang(lang)) {
    throw new EndpointError('Unsupported language. Choose fa, en, or ru.', {
      code: 'INVALID_LANG',
    });
  }

  const cfg = await getConfigMap();
  assertAuthorizedInstance(cfg);

  const [res, engines] = await Promise.all([
    setUserLanguage(tgUser.id, lang, tgUser),
    getEngineStatuses(lang),
  ]);
  const admin = await isUserAdmin(tgUser.id, cfg);

  return {
    lang: res.user.lang,
    langSelected: true,
    engines: admin
      ? engines
      : engines.map((eng) => ({
          id: eng.id,
          name: eng.name,
          configured: eng.configured,
          tier: eng.tier,
          masked: eng.tier === 'live_api' ? eng.masked : (eng.configured ? 'Active' : 'Standby'),
        })),
  };
}
