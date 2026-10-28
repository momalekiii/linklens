import { api, db } from 'sdk';
import { eq, sql } from 'sdk/db';
import { botConfig } from '../schema.js';
import { getConfigMap } from './secrets.js';
import { ensureDbReady } from './usersRepo.js';

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
  const profileKey = `BOT_PROFILE_SYNCED_V5_${cfg.MINI_APP_URL ? 'APP' : 'BASE'}`;

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
      '🛡 LinkLens — اسکنر عمیق امنیت لینک و نشت اطلاعات',
      '',
      '\u200F🇮🇷 هر لینک یا پیام تلگرامی را بفرستید یا فوروارد کنید تا اصالت درگاه شاپرک، فیشینگ (مطمئن‌باش) و نشت داده (لیک‌فا) خودکار بررسی شود!',
      '🇬🇧 Send any link or forward any Telegram message to scan for phishing, malware & data breaches automatically!',
      '🇷🇺 Отправьте любую ссылку или перешлите любое сообщение для автоматической проверки на фишинг, вирусы и утечки!',
    ].join('\n');

    const tasks = [
      api.setMyDescription({ description: trilingualDesc }),
      api.setMyDescription({
        language_code: 'fa',
        description:
          '🛡 LinkLens — اسکنر هوشمند امنیت لینک، درگاه شاپرک و نشت اطلاعات\n\n' +
          'هر لینک یا پیام مشکوک را بفرستید یا به ربات فوروارد کنید تا خودکار در دیتابیس‌های ایران (مطمئن‌باش، شاپرک، کاوه، لیک‌فا) و جهان بررسی شود!',
      }),
      api.setMyDescription({
        language_code: 'en',
        description:
          '🛡 LinkLens — Deep Multi-Layer Link & Data Breach Scanner\n\n' +
          'Send any URL or forward any Telegram message to scan automatically across global threat & data-breach feeds before clicking!',
      }),
      api.setMyDescription({
        language_code: 'ru',
        description:
          '🛡 LinkLens — Глубокий сканер ссылок и утечек данных\n\n' +
          'Отправляйте любые ссылки или пересылайте сообщения для автоматической проверки по мировым базам угроз и утечек!',
      }),
      api.setMyShortDescription({
        short_description: '🛡 Automatic URL Phishing, Malware & Data Breach Scanner (FA / EN / RU)',
      }),
      api.setMyCommands({
        commands: [
          { command: 'start', description: '🛡 Main Menu / منوی اصلی / Главное меню' },
          { command: 'lang', description: '🌐 Change Language (فارسی / English / Русский)' },
          { command: 'history', description: '📜 Scan History / تاریخچه اسکن‌ها' },
          { command: 'status', description: '📡 System Status / وضعیت سرویس‌ها' },
          { command: 'stats', description: '📊 Security Stats / آمار اسکن‌ها' },
          { command: 'about', description: 'ℹ️ About Us / درباره ما / О нас' },
        ],
      }),
    ];

    if (cfg.MINI_APP_URL && /^https?:\/\//i.test(cfg.MINI_APP_URL)) {
      tasks.push(
        api.setChatMenuButton({
          menu_button: {
            type: 'web_app',
            text: '🌐 Mini App',
            web_app: { url: cfg.MINI_APP_URL.replace(/\/$/, '') },
          },
        }).catch(() => null)
      );
    }

    await Promise.all(tasks);

    await db.insert(botConfig)
      .values({ key: profileKey, value: '1', updatedAt: sql`(unixepoch())` })
      .onConflictDoUpdate({
        target: botConfig.key,
        set: { value: '1', updatedAt: sql`(unixepoch())` },
      })
      .run()
      .catch(() => null);
  } catch (_) {
    // Non-fatal in local preview or restricted environments
  }
}
