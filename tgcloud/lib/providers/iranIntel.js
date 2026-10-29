import { db, fetch } from 'sdk';
import { eq, sql } from 'sdk/db';
import { feedCache } from '../../schema.js';
import { sha256Hex, withTimeout } from '../urlUtils.js';
import { parseUrlPure, parseQueryEntriesPure } from '../v8Runtime.js';

// ============================================================================
// Iranian Link Security, Shaparak Gateway Verifier & Data Breach Intelligence
// 100% Native Zero-Key Telegram Serverless Provider with RAM + SQLite Caching
//
// Integrated Open Threat & Breach Intelligence Sources:
// 1. MotmaenBash Open Dataset (`miladnouri/motmaenbash-data`, CC-BY-4.0)
//    - Iranian phishing portals, fake payment gateways, scams, Ponzi schemes &
//      malicious Android banking trojan SHA-256 signatures.
// 2. Official Central Bank of Iran (`شاپرک / CBI`) PSP Verifier (`*.shaparak.ir`)
//    + Iranian Payment Aggregator & Government / Bank Anti-Spoofing Rules.
// 3. Nooshdaroo Kaveh Project (`Nooshdaroo-Code/Kaveh`)
//    - Iranian Android spyware & banking trojan (`IRATA`, `Android.Spy.Lydia`) IOCs.
// 4. Leakfa Official Breach Database (`Leakfarsi/Leakfa-Alert`, MIT)
//    - Documented data breaches across 100+ Iranian & regional websites/platforms.
// 5. Have I Been Pwned Public Breach API (`haveibeenpwned.com/api/v3/breaches`)
//    - Global + `.ir` verified website data breach history & exposed data classes.
// ============================================================================

const MOTMAENBASH_MALICIOUS_URL =
  'https://raw.githubusercontent.com/miladnouri/motmaenbash-data/refs/heads/main/data/malicious-data.json';
const MOTMAENBASH_TRUSTED_URL =
  'https://raw.githubusercontent.com/miladnouri/motmaenbash-data/refs/heads/main/data/trusted-data.json';
const LEAKFA_DOMAINS_URL =
  'https://raw.githubusercontent.com/Leakfarsi/Leakfa-Alert/refs/heads/domains/leaks.json';
const KAVEH_MINI_URL =
  'https://raw.githubusercontent.com/Nooshdaroo-Code/Kaveh/HEAD/mini.json';
const HIBP_BREACHES_URL =
  'https://haveibeenpwned.com/api/v3/breaches';

const FEED_TTL_SECONDS = 6 * 3600; // Refresh upstream feeds every 6 hours

// Official Central Bank of Iran (Shaparak) Licensed Payment Service Providers (PSPs)
export const SHAPARAK_PSP_DIRECTORY = {
  'bpm.shaparak.ir': {
    code: 'BPM',
    fa: 'به‌پرداخت ملت (بانک ملت)',
    en: 'Behpardakht Mellat (Bank Mellat PSP)',
    ru: 'Behpardakht Mellat (официальный PSP шлюз Shaparak)',
  },
  'sep.shaparak.ir': {
    code: 'SEP',
    fa: 'پرداخت الکترونیک سامان کیش',
    en: 'Saman Electronic Payment (SEP)',
    ru: 'Saman Electronic Payment (SEP Shaparak)',
  },
  'asan.shaparak.ir': {
    code: 'AP',
    fa: 'آسان پرداخت پرشین (آپ)',
    en: 'Asan Pardakht Persian (AP)',
    ru: 'Asan Pardakht Persian (AP Shaparak)',
  },
  'sadad.shaparak.ir': {
    code: 'SADAD',
    fa: 'پرداخت الکترونیک سداد (بانک ملی ایران)',
    en: 'Sadad Electronic Payment (Bank Melli)',
    ru: 'Sadad Electronic Payment (Bank Melli Shaparak)',
  },
  'pec.shaparak.ir': {
    code: 'PEC',
    fa: 'تجارت الکترونیک پارسیان',
    en: 'Parsian E-Commerce (PEC)',
    ru: 'Parsian E-Commerce (PEC Shaparak)',
  },
  'pasargad.shaparak.ir': {
    code: 'PEP',
    fa: 'پرداخت الکترونیک پاسارگاد',
    en: 'Pasargad Electronic Payment (PEP)',
    ru: 'Pasargad Electronic Payment (PEP Shaparak)',
  },
  'pep.shaparak.ir': {
    code: 'PEP',
    fa: 'پرداخت الکترونیک پاسارگاد',
    en: 'Pasargad Electronic Payment (PEP)',
    ru: 'Pasargad Electronic Payment (PEP Shaparak)',
  },
  'ikc.shaparak.ir': {
    code: 'IKC',
    fa: 'کارت اعتباری ایران کیش',
    en: 'Iran Kish Credit Card (IKC)',
    ru: 'Iran Kish Credit Card (IKC Shaparak)',
  },
  'fcp.shaparak.ir': {
    code: 'FCP',
    fa: 'فن‌آوا کارت',
    en: 'Fanava Card (FCP)',
    ru: 'Fanava Card (FCP Shaparak)',
  },
  'sepehr.shaparak.ir': {
    code: 'SEPEHR',
    fa: 'مبنا کارت آریا (درگاه سپهر بانک صادرات)',
    en: 'Mabna Card Aria — Sepehr PSP',
    ru: 'Mabna Card Aria — Sepehr Shaparak',
  },
  'pna.shaparak.ir': {
    code: 'PNA',
    fa: 'پرداخت نوین آرین (بانک اقتصاد نوین)',
    en: 'Pardakht Novin Arian (PNA)',
    ru: 'Pardakht Novin Arian (PNA Shaparak)',
  },
  'sizpay.shaparak.ir': {
    code: 'SIZPAY',
    fa: 'سیزپی (کارت اعتباری شهر)',
    en: 'SizPay Electronic Payment',
    ru: 'SizPay Shaparak PSP',
  },
  'damavand.shaparak.ir': {
    code: 'DAMAVAND',
    fa: 'درگاه پرداخت الکترونیک دماوند شاپرک',
    en: 'Damavand Shaparak PSP',
    ru: 'Damavand Shaparak PSP',
  },
  'sepidar.shaparak.ir': {
    code: 'SEPIDAR',
    fa: 'درگاه پرداخت سپیدار شاپرک',
    en: 'Sepidar Shaparak PSP',
    ru: 'Sepidar Shaparak PSP',
  },
  'shaparak.ir': {
    code: 'SHAPARAK_PORTAL',
    fa: 'پورتال رسمی شرکت شبکه الکترونیکی پرداخت کارت (شاپرک)',
    en: 'Official Shaparak Payment Network Portal (CBI)',
    ru: 'Официальный портал платёжной сети Shaparak (ЦБ Ирана)',
  },
};

// Known legitimate Iranian Payment Facilitators (IPG Aggregators — redirect to *.shaparak.ir for card entry)
const VERIFIED_IRAN_PAYMENT_FACILITATORS = {
  'zarinpal.com': { fa: 'زرین‌پال (پرداخت‌یار رسمی شاپرک)', en: 'Zarinpal (Licensed Payment Facilitator)', ru: 'Zarinpal (лицензированный платёжный агрегатор)' },
  'idpay.ir': { fa: 'آیدی‌پی (پرداخت‌یار رسمی)', en: 'IDPay (Licensed Payment Facilitator)', ru: 'IDPay (платёжный агрегатор)' },
  'zibal.ir': { fa: 'زیبال (پرداخت‌یار رسمی)', en: 'Zibal (Licensed Payment Facilitator)', ru: 'Zibal (платёжный агрегатор)' },
  'payping.ir': { fa: 'پی‌پینگ (پرداخت‌یار رسمی)', en: 'PayPing (Licensed Payment Facilitator)', ru: 'PayPing (платёжный агрегатор)' },
  'vandar.io': { fa: 'وندار (پرداخت‌یار رسمی)', en: 'Vandar (Licensed Payment Facilitator)', ru: 'Vandar (платёжный агрегатор)' },
  'jibit.ir': { fa: 'جیبیت (زیرساخت پرداخت رسمی)', en: 'Jibit Payment Infrastructure', ru: 'Jibit (платёжный сервис)' },
};

// Official Iranian Banks, Exchanges & High-Value Portals Commonly Targeted by Phishing
const PROTECTED_IRANIAN_BRANDS = [
  { label: 'Shaparak Payment Network (شاپرک)', keyword: 'shaparak', allowed: ['shaparak.ir'] },
  { label: 'Adliran / Sana Judiciary (ثنا / عدل ایران)', keyword: 'adliran', allowed: ['adliran.ir'] },
  { label: 'Sana Judiciary Notice (سامانه ثنا)', keyword: 'sana-eblagh', allowed: ['adliran.ir'] },
  { label: 'Bank Mellat / Behpardakht (بانک ملت)', keyword: 'bankmellat', allowed: ['bankmellat.ir', 'shaparak.ir'] },
  { label: 'Behpardakht Mellat (به‌پرداخت)', keyword: 'behpardakht', allowed: ['behpardakht.com', 'shaparak.ir', 'bankmellat.ir'] },
  { label: 'Sadad / Bank Melli (سداد / بانک ملی)', keyword: 'sadad', allowed: ['sadadpsp.ir', 'bmi.ir', 'shaparak.ir'] },
  { label: 'BluBank (بلوبانک)', keyword: 'blubank', allowed: ['blubank.com', 'blubank.sb24.ir', 'sb24.ir'] },
  { label: 'Nobitex Exchange (نوبیتکس)', keyword: 'nobitex', allowed: ['nobitex.ir', 'nobitex.net'] },
  { label: 'Wallex Exchange (والکس)', keyword: 'wallex', allowed: ['wallex.ir', 'wallex.network'] },
  { label: 'Ramzinex Exchange (رمزینکس)', keyword: 'ramzinex', allowed: ['ramzinex.com', 'ramzinex.ir'] },
  { label: 'Digikala (دیجی‌کالا)', keyword: 'digikala', allowed: ['digikala.com', 'digikalajet.com', 'digikala.ir'] },
  { label: 'Divar Classifieds (دیوار)', keyword: 'divar-ir', allowed: ['divar.ir'] },
  { label: 'Iran Post (شرکت ملی پست)', keyword: 'post-eblagh', allowed: ['post.ir'] },
];

// Warm V8 isolate in-memory index (0.05ms lookup on subsequent requests!)
const memCache = {
  motmaenbash: null, // { domainMap, urlMap, apkMap, trustedSet, urlThreatCount, apkThreatCount, syncedAt }
  leakfa: null,      // { domains, count, feedTimestamp, syncedAt }
  kaveh: null,       // { malwareMap, count, version, syncedAt }
  hibp: null,        // { domainMap, count, syncedAt }
};

async function readFeedSqlCache(feedId) {
  try {
    const row = await db.select().from(feedCache).where(eq(feedCache.feedId, feedId)).get();
    if (!row || !row.payload) return null;
    const nowSec = Math.floor(Date.now() / 1000);
    return {
      fresh: nowSec - Number(row.syncedAt || 0) < FEED_TTL_SECONDS,
      syncedAt: Number(row.syncedAt || 0),
      entriesCount: Number(row.entriesCount || 0),
      data: JSON.parse(row.payload),
    };
  } catch (_) {
    return null;
  }
}

async function writeFeedSqlCache(feedId, data, entriesCount) {
  const syncedAt = Math.floor(Date.now() / 1000);
  try {
    await db.insert(feedCache)
      .values({
        feedId,
        payload: JSON.stringify(data),
        entriesCount: Number(entriesCount || 0),
        syncedAt,
      })
      .onConflictDoUpdate({
        target: feedCache.feedId,
        set: {
          payload: JSON.stringify(data),
          entriesCount: Number(entriesCount || 0),
          syncedAt,
        },
      })
      .run();
  } catch (_) {
    // Runs smoothly in memory even if DB migration hasn't run yet
  }
  return syncedAt;
}

// ----------------------------------------------------------------------------
// 1. Load & Index MotmaenBash Dataset (`miladnouri/motmaenbash-data`, CC-BY-4.0)
// ----------------------------------------------------------------------------
export async function ensureMotmaenBashIndex(forceRefresh = false) {
  const nowSec = Math.floor(Date.now() / 1000);
  if (!forceRefresh && memCache.motmaenbash && nowSec - memCache.motmaenbash.syncedAt < FEED_TTL_SECONDS) {
    return memCache.motmaenbash;
  }

  let raw = null;
  let syncedAt = nowSec;

  if (!forceRefresh) {
    const sqlHit = await readFeedSqlCache('motmaenbash_v1');
    if (sqlHit?.data) {
      raw = sqlHit.data;
      syncedAt = sqlHit.syncedAt;
    }
  }

  if (!raw) {
    try {
      const [malRes, trustRes] = await Promise.all([
        withTimeout(fetch(MOTMAENBASH_MALICIOUS_URL, { headers: { 'User-Agent': 'LinkLens-TelegramServerless/1.1' } }), 5500, 'MotmaenBash malicious timeout'),
        withTimeout(fetch(MOTMAENBASH_TRUSTED_URL, { headers: { 'User-Agent': 'LinkLens-TelegramServerless/1.1' } }), 4500, 'MotmaenBash trusted timeout'),
      ]);
      if (malRes.ok) {
        const malicious = await malRes.json();
        const trusted = trustRes.ok ? await trustRes.json() : [];
        raw = { malicious, trusted };
        const countEstimate = JSON.stringify(malicious).match(/[a-f0-9]{64}/gi)?.length || 0;
        syncedAt = await writeFeedSqlCache('motmaenbash_v1', raw, countEstimate);
      }
    } catch (_) {
      const stale = await readFeedSqlCache('motmaenbash_v1');
      if (stale?.data) {
        raw = stale.data;
        syncedAt = stale.syncedAt;
      }
    }
  }

  const domainMap = new Map();
  const urlMap = new Map();
  const apkMap = new Map();
  const trustedSet = new Set();

  if (raw?.malicious && Array.isArray(raw.malicious)) {
    // Slot [0]: Malicious URLs & Fake Shaparak Domains (`type`: 1=Phishing, 2=Scam, 3=Ponzi, 4=Other; `match`: 1=Domain, 2=Full URL)
    const urlGroups = Array.isArray(raw.malicious[0]) ? raw.malicious[0] : [];
    for (const grp of urlGroups) {
      if (!grp || !Array.isArray(grp.hashes)) continue;
      const meta = { type: Number(grp.type || 1), level: Number(grp.level || 1) };
      const targetMap = Number(grp.match) === 2 ? urlMap : domainMap;
      for (const h of grp.hashes) {
        if (typeof h === 'string' && h.length === 64) {
          targetMap.set(h.toLowerCase(), meta);
        }
      }
    }

    // Slot [2]: Malicious Android Banking Trojan APKs / Packages / DEX / Signatures
    const apkGroups = Array.isArray(raw.malicious[2]) ? raw.malicious[2] : [];
    const apkKindMap = { 1: 'PACKAGE', 2: 'APK_BINARY', 3: 'DEX', 4: 'CERT_SIGN' };
    for (const grp of apkGroups) {
      if (!grp || !Array.isArray(grp.hashes)) continue;
      const kind = apkKindMap[Number(grp.type)] || 'APK_MALWARE';
      for (const h of grp.hashes) {
        if (typeof h === 'string' && h.length === 64) {
          apkMap.set(h.toLowerCase(), { kind });
        }
      }
    }
  }

  if (raw?.trusted && Array.isArray(raw.trusted)) {
    for (const sub of raw.trusted) {
      if (Array.isArray(sub)) {
        for (const item of sub) {
          if (typeof item === 'string' && item.length === 64) {
            trustedSet.add(item.toLowerCase());
          } else if (item && Array.isArray(item.hashes)) {
            for (const h of item.hashes) {
              if (typeof h === 'string' && h.length === 64) trustedSet.add(h.toLowerCase());
            }
          }
        }
      }
    }
  }

  memCache.motmaenbash = {
    available: domainMap.size + urlMap.size > 0,
    domainMap,
    urlMap,
    apkMap,
    trustedSet,
    urlThreatCount: domainMap.size + urlMap.size,
    apkThreatCount: apkMap.size,
    trustedCount: trustedSet.size,
    syncedAt,
  };
  return memCache.motmaenbash;
}

// ----------------------------------------------------------------------------
// 2. Load & Index Official Leakfa Breach Feed (`Leakfarsi/Leakfa-Alert`)
// ----------------------------------------------------------------------------
export async function ensureLeakfaIndex(forceRefresh = false) {
  const nowSec = Math.floor(Date.now() / 1000);
  if (!forceRefresh && memCache.leakfa && nowSec - memCache.leakfa.syncedAt < FEED_TTL_SECONDS) {
    return memCache.leakfa;
  }

  let data = null;
  let syncedAt = nowSec;

  if (!forceRefresh) {
    const sqlHit = await readFeedSqlCache('leakfa_v1');
    if (sqlHit?.data) {
      data = sqlHit.data;
      syncedAt = sqlHit.syncedAt;
    }
  }

  if (!data) {
    try {
      const res = await withTimeout(
        fetch(LEAKFA_DOMAINS_URL, { headers: { 'User-Agent': 'LinkLens-TelegramServerless/1.1' } }),
        5500,
        'Leakfa feed timeout'
      );
      if (res.ok) {
        data = await res.json();
        const count = Object.keys(data?.domains || {}).length;
        syncedAt = await writeFeedSqlCache('leakfa_v1', data, count);
      }
    } catch (_) {
      const stale = await readFeedSqlCache('leakfa_v1');
      if (stale?.data) {
        data = stale.data;
        syncedAt = stale.syncedAt;
      }
    }
  }

  const domains = data?.domains && typeof data.domains === 'object' ? data.domains : {};
  memCache.leakfa = {
    available: Object.keys(domains).length > 0,
    domains,
    count: Object.keys(domains).length,
    feedTimestamp: data?.timestamp || null,
    syncedAt,
  };
  return memCache.leakfa;
}

// ----------------------------------------------------------------------------
// 3. Load & Index Nooshdaroo Kaveh Threat Feed (`Nooshdaroo-Code/Kaveh`)
// ----------------------------------------------------------------------------
export async function ensureKavehIndex(forceRefresh = false) {
  const nowSec = Math.floor(Date.now() / 1000);
  if (!forceRefresh && memCache.kaveh && nowSec - memCache.kaveh.syncedAt < FEED_TTL_SECONDS) {
    return memCache.kaveh;
  }

  let data = null;
  let syncedAt = nowSec;

  if (!forceRefresh) {
    const sqlHit = await readFeedSqlCache('kaveh_v1');
    if (sqlHit?.data) {
      data = sqlHit.data;
      syncedAt = sqlHit.syncedAt;
    }
  }

  if (!data) {
    try {
      const res = await withTimeout(
        fetch(KAVEH_MINI_URL, { headers: { 'User-Agent': 'LinkLens-TelegramServerless/1.1' } }),
        4500,
        'Kaveh feed timeout'
      );
      if (res.ok) {
        data = await res.json();
        syncedAt = await writeFeedSqlCache('kaveh_v1', data, (data?.malware || []).length);
      }
    } catch (_) {
      const stale = await readFeedSqlCache('kaveh_v1');
      if (stale?.data) {
        data = stale.data;
        syncedAt = stale.syncedAt;
      }
    }
  }

  const malwareMap = new Map();
  if (Array.isArray(data?.malware)) {
    for (const item of data.malware) {
      if (item?.sha256_hash) {
        malwareMap.set(String(item.sha256_hash).toLowerCase(), {
          detections: Array.isArray(item.detection) ? item.detection : [],
        });
      }
    }
  }

  memCache.kaveh = {
    available: malwareMap.size > 0,
    malwareMap,
    docs: data?.docs || {},
    version: data?.version || null,
    count: malwareMap.size,
    syncedAt,
  };
  return memCache.kaveh;
}

// ----------------------------------------------------------------------------
// 4. Load & Index Have I Been Pwned Public Breach Catalog (`api/v3/breaches`)
// ----------------------------------------------------------------------------
export async function ensureHibpIndex(forceRefresh = false) {
  const nowSec = Math.floor(Date.now() / 1000);
  if (!forceRefresh && memCache.hibp && nowSec - memCache.hibp.syncedAt < FEED_TTL_SECONDS) {
    return memCache.hibp;
  }

  let slim = null;
  let syncedAt = nowSec;

  if (!forceRefresh) {
    const sqlHit = await readFeedSqlCache('hibp_slim_v1');
    if (sqlHit?.data) {
      slim = sqlHit.data;
      syncedAt = sqlHit.syncedAt;
    }
  }

  if (!slim) {
    try {
      const res = await withTimeout(
        fetch(HIBP_BREACHES_URL, {
          headers: {
            'User-Agent': 'LinkLens-TelegramServerless/1.1',
            Accept: 'application/json',
          },
        }),
        5500,
        'HIBP breaches timeout'
      );
      if (res.ok) {
        const list = await res.json();
        // Store compact slim records so SQLite cache stays ~65 KB instead of 800 KB!
        slim = (Array.isArray(list) ? list : [])
          .filter((b) => b && b.Domain && !b.IsRetired && !b.IsSpamList)
          .map((b) => ({
            d: String(b.Domain).toLowerCase(),
            t: b.Title || b.Name,
            dt: b.BreachDate || null,
            n: Number(b.PwnCount || 0),
            c: Array.isArray(b.DataClasses) ? b.DataClasses.slice(0, 6) : [],
            v: Boolean(b.IsVerified),
          }));
        syncedAt = await writeFeedSqlCache('hibp_slim_v1', slim, slim.length);
      }
    } catch (_) {
      const stale = await readFeedSqlCache('hibp_slim_v1');
      if (stale?.data) {
        slim = stale.data;
        syncedAt = stale.syncedAt;
      }
    }
  }

  const domainMap = new Map();
  for (const item of slim || []) {
    const existing = domainMap.get(item.d) || [];
    existing.push(item);
    domainMap.set(item.d, existing);
  }

  memCache.hibp = {
    available: domainMap.size > 0,
    domainMap,
    count: (slim || []).length,
    syncedAt,
  };
  return memCache.hibp;
}

// Exact `leakfaMatchDomain` algorithm from `Leakfarsi/Leakfa-Alert/js/matching.js`
function matchLeakfaDomain(hostname, domainDescriptions) {
  if (!hostname || !domainDescriptions) return null;
  const h = hostname.toLowerCase().replace(/^www\./, '');
  if (Object.prototype.hasOwnProperty.call(domainDescriptions, h)) return h;
  if (Object.prototype.hasOwnProperty.call(domainDescriptions, hostname.toLowerCase())) {
    return hostname.toLowerCase();
  }
  for (const key of Object.keys(domainDescriptions)) {
    if (h.endsWith(`.${key}`)) return key;
  }
  return null;
}

function matchHibpDomain(hostname, domainMap) {
  if (!hostname || !domainMap) return [];
  const h = hostname.toLowerCase().replace(/^www\./, '');
  if (domainMap.has(h)) return domainMap.get(h);
  for (const [key, list] of domainMap.entries()) {
    if (h.endsWith(`.${key}`)) return list;
  }
  return [];
}

// Generates all candidate domain/URL/package strings matching BOTH
// `motmaenbash-chrome` AND `motmaenbash-android/utils/UrlUtils.kt`
async function buildCandidateHashes(urlsToCheck) {
  const domainStrings = new Set();
  const urlStrings = new Set();
  const packageStrings = new Set();

  for (const raw of urlsToCheck) {
    if (!raw || typeof raw !== 'string') continue;
    const trimmed = raw.trim().toLowerCase();
    urlStrings.add(trimmed);

    const noPrefix = trimmed.replace(/^https?:\/\//, '').replace(/^www\./, '');
    const cleanNoQuery = noPrefix.split('?')[0].split('#')[0].replace(/\/+$/, '');
    if (cleanNoQuery) urlStrings.add(cleanNoQuery);

    try {
      const u = parseUrlPure(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
      if (!u) continue;
      const host = u.hostname.toLowerCase();
      const bareHost = host.replace(/^www\./, '');
      domainStrings.add(host);
      domainStrings.add(bareHost);

      const parts = bareHost.split('.');
      if (parts.length >= 2) {
        domainStrings.add(parts.slice(-2).join('.'));
      }
      if (parts.length >= 3) {
        domainStrings.add(parts.slice(-3).join('.'));
      }

      urlStrings.add(`${bareHost}${u.pathname}${u.search}${u.hash}`);
      urlStrings.add(`${bareHost}${u.pathname}`.replace(/\/+$/, ''));

      // Extract Android package IDs from Google Play, CafeBazaar, Myket, or query params
      const queryMap = new Map(parseQueryEntriesPure(u.search));
      const idParam = queryMap.get('id') || queryMap.get('package') || queryMap.get('pkg');
      if (idParam && /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/i.test(idParam)) {
        packageStrings.add(idParam.toLowerCase());
      }
      const bazaarOrMyket = u.pathname.match(/\/app\/([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)/i);
      if (bazaarOrMyket) {
        packageStrings.add(bazaarOrMyket[1].toLowerCase());
      }
    } catch (_) {
      // Ignore malformed candidate
    }
  }

  const [domainHashes, urlHashes, packageHashes] = await Promise.all([
    Promise.all([...domainStrings].map(async (s) => ({ str: s, hash: await sha256Hex(s) }))),
    Promise.all([...urlStrings].map(async (s) => ({ str: s, hash: await sha256Hex(s) }))),
    Promise.all([...packageStrings].map(async (s) => ({ str: s, hash: await sha256Hex(s) }))),
  ]);

  return { domainHashes, urlHashes, packageHashes };
}

function classifyMotmaenBashThreatCode(typeCode) {
  switch (Number(typeCode)) {
    case 1: return 'PHISHING';
    case 2: return 'SCAM';
    case 3: return 'PONZI';
    default: return 'SUSPICIOUS';
  }
}

// ----------------------------------------------------------------------------
// Main Iranian Threat, Shaparak Gateway & Breach Intelligence Analyzer
// ----------------------------------------------------------------------------
export async function checkIranianSecurityAndBreaches({
  inputUrl,
  normalizedUrl,
  finalUrl,
  initialHostname,
  finalHostname,
  httpsEnforced = true,
  payloadSha256 = null,
}) {
  const [mb, leakfa, kaveh, hibp] = await Promise.all([
    ensureMotmaenBashIndex(false),
    ensureLeakfaIndex(false),
    ensureKavehIndex(false),
    ensureHibpIndex(false),
  ]);

  const candidates = await buildCandidateHashes([inputUrl, normalizedUrl, finalUrl]);

  // 1. Check MotmaenBash Malicious URL / Domain SHA-256 Hashes
  let motmaenBashThreat = null;
  for (const c of candidates.domainHashes) {
    const hit = mb.domainMap.get(c.hash);
    if (hit) {
      motmaenBashThreat = {
        matched: true,
        matchScope: 'DOMAIN',
        matchedValue: c.str,
        sha256: c.hash,
        typeCode: hit.type,
        threatCategory: classifyMotmaenBashThreatCode(hit.type),
        level: hit.level,
      };
      break;
    }
  }
  if (!motmaenBashThreat) {
    for (const c of candidates.urlHashes) {
      const hit = mb.urlMap.get(c.hash) || mb.domainMap.get(c.hash);
      if (hit) {
        motmaenBashThreat = {
          matched: true,
          matchScope: 'URL',
          matchedValue: c.str,
          sha256: c.hash,
          typeCode: hit.type,
          threatCategory: classifyMotmaenBashThreatCode(hit.type),
          level: hit.level,
        };
        break;
      }
    }
  }

  // 2. Check MotmaenBash & Nooshdaroo Kaveh Android Banking Trojan / APK Malware Hashes
  let apkMalwareHit = null;
  if (payloadSha256) {
    const lowerSha = payloadSha256.toLowerCase();
    const mbApk = mb.apkMap.get(lowerSha);
    const kavehHit = kaveh.malwareMap.get(lowerSha);
    if (mbApk || kavehHit) {
      apkMalwareHit = {
        matched: true,
        sha256: lowerSha,
        source: mbApk && kavehHit ? 'MotmaenBash + Nooshdaroo Kaveh' : mbApk ? 'MotmaenBash APK DB' : 'Nooshdaroo Kaveh',
        detections: kavehHit?.detections || [mbApk.kind],
      };
    }
  }
  if (!apkMalwareHit) {
    for (const pkg of candidates.packageHashes) {
      const mbPkg = mb.apkMap.get(pkg.hash);
      if (mbPkg) {
        apkMalwareHit = {
          matched: true,
          packageName: pkg.str,
          sha256: pkg.hash,
          source: 'MotmaenBash Malicious Package DB',
          detections: [mbPkg.kind],
        };
        break;
      }
    }
  }

  // Check MotmaenBash Trusted Entities Set
  let motmaenBashTrusted = false;
  for (const c of [...candidates.domainHashes, ...candidates.urlHashes, ...candidates.packageHashes]) {
    if (mb.trustedSet.has(c.hash)) {
      motmaenBashTrusted = true;
      break;
    }
  }

  // 3. Official Central Bank of Iran (`شاپرک`) Payment Gateway & Iranian Brand Spoof Check
  const host = (finalHostname || initialHostname || '').toLowerCase();
  const bareHost = host.replace(/^www\./, '');
  let shaparakStatus = 'NOT_GATEWAY'; // 'VERIFIED_SHAPARAK' | 'VERIFIED_FACILITATOR' | 'INSECURE_HTTP_SHAPARAK' | 'FAKE_IRAN_BRAND' | 'NOT_GATEWAY'
  let gatewayInfo = null;
  let spoofedIranBrand = null;

  const isOfficialShaparakDomain = bareHost === 'shaparak.ir' || /^[a-z0-9-]+\.shaparak\.ir$/.test(bareHost);
  if (isOfficialShaparakDomain && !host.includes('xn--') && !motmaenBashThreat) {
    const psp = SHAPARAK_PSP_DIRECTORY[bareHost] || {
      code: bareHost.split('.')[0].toUpperCase(),
      fa: `درگاه رسمی شبکه پرداخت شاپرک (${bareHost})`,
      en: `Official Shaparak Payment Gateway (${bareHost})`,
      ru: `Официальный платёжный шлюз Shaparak (${bareHost})`,
    };
    if (httpsEnforced) {
      shaparakStatus = 'VERIFIED_SHAPARAK';
      gatewayInfo = psp;
    } else {
      shaparakStatus = 'INSECURE_HTTP_SHAPARAK';
      gatewayInfo = psp;
    }
  } else {
    // Check licensed Iranian payment facilitators (Zarinpal, IDPay, Zibal, PayPing, Vandar, Jibit)
    for (const [facDomain, facMeta] of Object.entries(VERIFIED_IRAN_PAYMENT_FACILITATORS)) {
      if (bareHost === facDomain || bareHost.endsWith(`.${facDomain}`)) {
        shaparakStatus = 'VERIFIED_FACILITATOR';
        gatewayInfo = facMeta;
        break;
      }
    }

    // Check high-priority Iranian payment / judiciary / bank brand spoofing
    for (const rule of PROTECTED_IRANIAN_BRANDS) {
      if (bareHost.includes(rule.keyword)) {
        const isAllowed = rule.allowed.some((d) => bareHost === d || bareHost.endsWith(`.${d}`));
        if (!isAllowed) {
          shaparakStatus = 'FAKE_IRAN_BRAND';
          spoofedIranBrand = rule.label;
          break;
        }
      }
    }
  }

  // 4. Leakfa (`Leakfarsi/Leakfa-Alert`) + Have I Been Pwned Website Breach History
  const leakfaMatchedKey =
    matchLeakfaDomain(bareHost, leakfa.domains) ||
    matchLeakfaDomain(initialHostname, leakfa.domains);

  const leakfaEntry = leakfaMatchedKey ? leakfa.domains[leakfaMatchedKey] : null;
  const hibpEntries = matchHibpDomain(bareHost, hibp.domainMap);

  const breaches = [];
  if (leakfaEntry) {
    breaches.push({
      source: 'Leakfa',
      domain: leakfaMatchedKey,
      nameFa: leakfaEntry.name_fa || leakfaMatchedKey,
      nameEn: leakfaEntry.name_en || leakfaMatchedKey,
      descriptionFa: leakfaEntry.description_fa || '',
      descriptionEn: leakfaEntry.description_en || '',
      relatedUrl: leakfaEntry.relatedURL || 'https://leakfa.com/leaks',
      companyResponse: leakfaEntry.companyResponse || 'unknown',
    });
  }

  for (const hb of hibpEntries.slice(0, 4)) {
    breaches.push({
      source: 'HaveIBeenPwned',
      domain: hb.d,
      nameFa: hb.t,
      nameEn: hb.t,
      breachDate: hb.dt,
      pwnCount: hb.n,
      dataClasses: hb.c || [],
      isVerified: hb.v,
    });
  }

  return {
    status: 'ok',
    sources: {
      motmaenbash: feedState(mb, mb.urlThreatCount + mb.apkThreatCount),
      leakfa: feedState(leakfa, leakfa.count),
      kaveh: feedState(kaveh, kaveh.count),
      hibp: feedState(hibp, hibp.count),
    },
    attribution: {
      motmaenbash: 'MotmaenBash Open Dataset (miladnouri/motmaenbash-data • CC-BY-4.0)',
      kaveh: 'Nooshdaroo Kaveh Threat Feed (Nooshdaroo-Code/Kaveh)',
      leakfa: 'Leakfa Breach Intelligence (Leakfarsi/Leakfa-Alert • MIT)',
      hibp: 'Have I Been Pwned Breach API v3',
    },
    feedStats: {
      motmaenBashUrls: mb.urlThreatCount,
      motmaenBashApks: mb.apkThreatCount,
      kavehMalware: kaveh.count,
      leakfaDomains: leakfa.count,
      leakfaUpdatedAt: leakfa.feedTimestamp,
      hibpBreaches: hibp.count,
    },
    motmaenBashThreat,
    motmaenBashTrusted,
    apkMalwareHit,
    shaparakStatus,
    gatewayInfo,
    spoofedIranBrand,
    hasBreachHistory: breaches.length > 0,
    leakfaMatched: Boolean(leakfaEntry),
    hibpMatched: hibpEntries.length > 0,
    primaryLeakfaUrl: leakfaEntry?.relatedURL || null,
    breaches,
  };
}

export async function getIranFeedTelemetry(forceRefresh = false) {
  const [mb, leakfa, kaveh, hibp] = await Promise.all([
    ensureMotmaenBashIndex(forceRefresh),
    ensureLeakfaIndex(forceRefresh),
    ensureKavehIndex(forceRefresh),
    ensureHibpIndex(forceRefresh),
  ]);
  return {
    motmaenBashUrls: mb.urlThreatCount,
    motmaenBashApks: mb.apkThreatCount,
    motmaenBashTrusted: mb.trustedCount,
    leakfaDomains: leakfa.count,
    leakfaUpdatedAt: leakfa.feedTimestamp,
    kavehMalware: kaveh.count,
    kavehVersion: kaveh.version,
    hibpBreaches: hibp.count,
  };
}

function feedState(index, count) {
  const ageSeconds = Math.max(0, Math.floor(Date.now() / 1000) - Number(index.syncedAt || 0));
  return { status: count > 0 ? (ageSeconds < FEED_TTL_SECONDS ? 'cached' : 'stale_cache') : 'unavailable', entries: Number(count || 0), syncedAt: index.syncedAt || null, ageSeconds };
}
