import { db } from 'sdk';
import { eq, sql } from 'sdk/db';
import { botConfig } from '../schema.js';
import { getIranFeedTelemetry } from './providers/iranIntel.js';

// ============================================================================
// LinkLens External Threat-Intelligence & Runtime Configuration
// ============================================================================
// SECURITY NOTE FOR PUBLIC GITHUB REPOSITORIES:
// Keep ALL fields in `DEFAULT_SECRETS` empty (`''`) in source control!
// Runtime secrets (`ADMIN_TG_IDS`, `MINI_APP_URL`, and optional API keys) are
// stored strictly in Telegram Serverless's isolated SQLite table (`bot_config`)
// via local `.env` + `npm run deploy` or via `/setkey` inside Telegram chat.
// ============================================================================

export const DEFAULT_SECRETS = {
  VIRUSTOTAL_API_KEY: '',
  GOOGLE_SAFE_BROWSING_KEY: '',
  URLSCAN_API_KEY: '',
  ABUSEIPDB_API_KEY: '',
  IPQUALITYSCORE_API_KEY: '',
  MINI_APP_URL: '',
  ADMIN_TG_IDS: '',
  INSTANCE_ACTIVATION_KEY: '',
};

export const KEY_ALIASES = {
  vt: 'VIRUSTOTAL_API_KEY',
  virustotal: 'VIRUSTOTAL_API_KEY',
  VIRUSTOTAL_API_KEY: 'VIRUSTOTAL_API_KEY',

  gsb: 'GOOGLE_SAFE_BROWSING_KEY',
  safebrowsing: 'GOOGLE_SAFE_BROWSING_KEY',
  google: 'GOOGLE_SAFE_BROWSING_KEY',
  GOOGLE_SAFE_BROWSING_KEY: 'GOOGLE_SAFE_BROWSING_KEY',

  urlscan: 'URLSCAN_API_KEY',
  URLSCAN_API_KEY: 'URLSCAN_API_KEY',

  abuseipdb: 'ABUSEIPDB_API_KEY',
  abuse: 'ABUSEIPDB_API_KEY',
  ABUSEIPDB_API_KEY: 'ABUSEIPDB_API_KEY',

  ipqs: 'IPQUALITYSCORE_API_KEY',
  ipqualityscore: 'IPQUALITYSCORE_API_KEY',
  IPQUALITYSCORE_API_KEY: 'IPQUALITYSCORE_API_KEY',

  miniapp: 'MINI_APP_URL',
  appurl: 'MINI_APP_URL',
  MINI_APP_URL: 'MINI_APP_URL',

  admin: 'ADMIN_TG_IDS',
  admins: 'ADMIN_TG_IDS',
  ADMIN_TG_IDS: 'ADMIN_TG_IDS',

  seal: 'INSTANCE_ACTIVATION_KEY',
  INSTANCE_ACTIVATION_KEY: 'INSTANCE_ACTIVATION_KEY',
};

export async function getConfigMap() {
  const merged = { ...DEFAULT_SECRETS };
  try {
    const rows = await db.select().from(botConfig).all();
    for (const row of rows) {
      if (row && row.key && row.value !== undefined && row.value !== '') {
        merged[row.key] = row.value;
      }
    }
  } catch (_) {
    // Gracefully fallback if migration has not run yet
  }
  return merged;
}

export async function setConfigValue(rawKey, value) {
  const canonical = KEY_ALIASES[rawKey] || KEY_ALIASES[String(rawKey || '').toLowerCase()];
  if (!canonical) {
    return { ok: false, reason: 'UNKNOWN_KEY' };
  }
  const cleanVal = String(value ?? '').trim();
  if (!cleanVal || cleanVal === 'clear' || cleanVal === 'off') {
    await db.delete(botConfig).where(eq(botConfig.key, canonical)).run();
    return { ok: true, key: canonical, cleared: true };
  }
  await db.insert(botConfig)
    .values({ key: canonical, value: cleanVal, updatedAt: sql`(unixepoch())` })
    .onConflictDoUpdate({
      target: botConfig.key,
      set: { value: cleanVal, updatedAt: sql`(unixepoch())` },
    })
    .run();
  return { ok: true, key: canonical, cleared: false };
}

export function maskSecret(val) {
  if (!val || typeof val !== 'string' || val.length < 6) return val ? '••••••' : '';
  return `${val.slice(0, 4)}••••${val.slice(-4)}`;
}

export async function getEngineStatuses(lang = 'en') {
  const [cfg, iranFeeds] = await Promise.all([
    getConfigMap(),
    getIranFeedTelemetry(false).catch(() => null),
  ]);
  const isFa = lang === 'fa';
  return [
    ...(isFa
      ? [
          {
            id: 'motmaenbash',
            alias: 'mb',
            envKey: null,
            name: '🇮🇷 اصالت درگاه شاپرک و ضد فیشینگ مطمئن‌باش (CC-BY-4.0)',
            configured: true,
            masked: iranFeeds?.motmaenBashUrls
              ? `فعال (${iranFeeds.motmaenBashUrls} لینک فیشینگ + ${iranFeeds.motmaenBashApks} بدافزار اندروید)`
              : 'فعال (بدون نیاز به کلید)',
            tier: 'live_api',
          },
          {
            id: 'leakfa',
            alias: 'leakfa',
            envKey: null,
            name: '🇮🇷 دیتابیس نشت اطلاعات لیک‌فا (Leakfa) + HIBP v3',
            configured: true,
            masked: iranFeeds?.leakfaDomains
              ? `فعال (${iranFeeds.leakfaDomains} سامانه ایرانی + ${iranFeeds.hibpBreaches} سرویس جهانی)`
              : 'فعال (بدون نیاز به کلید)',
            tier: 'live_api',
          },
          {
            id: 'kaveh',
            alias: 'kaveh',
            envKey: null,
            name: '🇮🇷 پایگاه بدافزار و تروجان کاوه (نوشدارو)',
            configured: true,
            masked: iranFeeds?.kavehMalware
              ? `فعال (${iranFeeds.kavehMalware} امضای SHA-256)`
              : 'فعال (بدون نیاز به کلید)',
            tier: 'live_api',
          },
        ]
      : [
          {
            id: 'hibp_breaches',
            alias: 'hibp',
            envKey: null,
            name: 'Have I Been Pwned v3 Data Breach Feed',
            configured: true,
            masked: iranFeeds?.hibpBreaches
              ? `Live (${iranFeeds.hibpBreaches} verified breaches)`
              : 'Active',
            tier: 'live_api',
          },
          {
            id: 'phish_malware_feeds',
            alias: 'feeds',
            envKey: null,
            name: 'Open Anti-Phishing & APK Malware SHA-256 Feeds',
            configured: true,
            masked: iranFeeds?.motmaenBashUrls
              ? `Live (${iranFeeds.motmaenBashUrls + (iranFeeds.motmaenBashApks || 0) + (iranFeeds.kavehMalware || 0)} IOC hashes)`
              : 'Active',
            tier: 'live_api',
          },
        ]),
    {
      id: 'virustotal',
      alias: 'vt',
      envKey: 'VIRUSTOTAL_API_KEY',
      name: 'VirusTotal v3 (90+ Engines)',
      configured: Boolean(cfg.VIRUSTOTAL_API_KEY),
      masked: maskSecret(cfg.VIRUSTOTAL_API_KEY),
      tier: 'api_key',
    },
    {
      id: 'safebrowsing',
      alias: 'gsb',
      envKey: 'GOOGLE_SAFE_BROWSING_KEY',
      name: 'Google Safe Browsing v4',
      configured: Boolean(cfg.GOOGLE_SAFE_BROWSING_KEY),
      masked: maskSecret(cfg.GOOGLE_SAFE_BROWSING_KEY),
      tier: 'api_key',
    },
    {
      id: 'urlscan',
      alias: 'urlscan',
      envKey: 'URLSCAN_API_KEY',
      name: 'URLScan.io Sandbox + Search',
      configured: true,
      hasApiKey: Boolean(cfg.URLSCAN_API_KEY),
      masked: maskSecret(cfg.URLSCAN_API_KEY),
      tier: 'hybrid',
    },
    {
      id: 'abuseipdb',
      alias: 'abuse',
      envKey: 'ABUSEIPDB_API_KEY',
      name: 'AbuseIPDB v2 Threat Feed',
      configured: Boolean(cfg.ABUSEIPDB_API_KEY),
      masked: maskSecret(cfg.ABUSEIPDB_API_KEY),
      tier: 'api_key',
    },
    {
      id: 'ipqs',
      alias: 'ipqs',
      envKey: 'IPQUALITYSCORE_API_KEY',
      name: 'IPQualityScore URL Threat AI',
      configured: Boolean(cfg.IPQUALITYSCORE_API_KEY),
      masked: maskSecret(cfg.IPQUALITYSCORE_API_KEY),
      tier: 'api_key',
    },
    {
      id: 'doh_dns',
      alias: 'dns',
      envKey: null,
      name: 'Cloudflare DoH (DNS / SPF / DMARC / CAA)',
      configured: true,
      masked: 'Active (Keyless API)',
      tier: 'live_api',
    },
    {
      id: 'rdap_whois',
      alias: 'rdap',
      envKey: null,
      name: 'IANA RDAP WHOIS & Domain Age',
      configured: true,
      masked: 'Active (Keyless API)',
      tier: 'live_api',
    },
    {
      id: 'ssl_ct',
      alias: 'ssl',
      envKey: null,
      name: 'crt.sh Certificate Transparency + TLS',
      configured: true,
      masked: 'Active (Keyless API)',
      tier: 'live_api',
    },
    {
      id: 'http_dom',
      alias: 'http',
      envKey: null,
      name: 'Deep HTTP Headers, Redirects & Phishing DOM',
      configured: true,
      masked: 'Active (Built-in Engine)',
      tier: 'live_api',
    },
  ];
}
