import { api, db } from 'sdk';
import { eq } from 'sdk/db';
import { botConfig } from '../schema.js';
import { getConfigMap } from './secrets.js';
import { ensureDbReady } from './usersRepo.js';
import { nowSec } from './clock.js';

// ============================================================================
// Auto-Configures Telegram's Native Pre-/start Welcome Card, Menu Button &
// Slash Commands in All 3 Languages (`fa`, `en`, `ru` + Trilingual Fallback)!
// Note: Shaparak (`شاپرک`) is exclusive to Iran and appears ONLY in `fa`!
// ============================================================================

let initializedInIsolate = false;

export async function ensureBotProfileInitialized() {
  if (initializedInIsolate) return;
  initializedInIsolate = true;

  await ensureDbReady();
  const cfg = await getConfigMap();
  const profileKey = 'BOT_PROFILE_SYNCED_V8';

  try {
    const existing = await db.select()
      .from(botConfig)
      .where(eq(botConfig.key, profileKey))
      .get();
    if (existing?.value === '1') return;
  } catch (_) {
    // Continue gracefully
  }

  try {
    const trilingualDesc = [
      'LinkLens — link & breach analysis engine',
      '',
      'Send a link or forward any message. Scanning starts automatically.',
      'Отправьте ссылку или перешлите сообщение — проверка начнётся автоматически.',
      '\u200Fلینک بفرستید یا هر پیامی را فوروارد کنید؛ اسکن خودکار آغاز می‌شود.',
    ].join('\n');

    const tasks = [
      api.setMyDescription({ description: trilingualDesc }),
      api.setMyDescription({
        language_code: 'fa',
        description:
          'LinkLens — موتور تحلیل لینک و نشت داده\n\n' +
          '\u200Fلینک بفرستید یا هر پیامی را فوروارد کنید تا به‌صورت خودکار در منابع ایران (مطمئن‌باش، شاپرک، کاوه، لیک‌فا) و جهانی بررسی شود.',
      }),
      api.setMyDescription({
        language_code: 'en',
        description:
          'LinkLens — multi-layer link & data-breach analysis\n\n' +
          'Send a link or forward any message. Threat intelligence, infrastructure and breach feeds are checked automatically before you open it.',
      }),
      api.setMyDescription({
        language_code: 'ru',
        description:
          'LinkLens — многоуровневый анализ ссылок и утечек данных\n\n' +
          'Отправьте ссылку или перешлите сообщение — проверка по базам угроз, инфраструктуре и утечкам выполнится автоматически.',
      }),
      api.setMyShortDescription({
        short_description: 'Automatic link, phishing and breach analysis (FA / EN / RU)',
      }),
      api.setMyCommands({
        commands: [
          { command: 'start', description: 'Menu / منو / Меню' },
          { command: 'lang', description: 'Language / زبان / Язык' },
          { command: 'history', description: 'History / تاریخچه / История' },
          { command: 'status', description: 'Service status / وضعیت سرویس' },
          { command: 'stats', description: 'Stats / آمار / Статистика' },
          { command: 'about', description: 'About / درباره / О проекте' },
        ],
      }),
    ];

    // Reset the chat menu button to Telegram's native default. Any web_app
    // (Mini App) button configured by an earlier version lives on Telegram's
    // side and must be overwritten explicitly — it cannot be removed in code.
    tasks.push(api.setChatMenuButton({ menu_button: { type: 'default' } }).catch(() => null));

    await Promise.all(tasks);

    await db.insert(botConfig)
      .values({ key: profileKey, value: '1', updatedAt: nowSec() })
      .onConflictDoUpdate({
        target: botConfig.key,
        set: { value: '1', updatedAt: nowSec() },
      })
      .run()
      .catch(() => null);
  } catch (_) {
    // Non-fatal in local preview or restricted environments
  }
}
