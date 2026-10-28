import { db } from 'sdk';
import { eq, desc, sql } from 'sdk/db';
import { users, scans } from '../schema.js';
import { isValidLang } from './i18n.js';

// ============================================================================
// User Profile, Language Resolution & Scan History Repository
// Zero hardcoded personal IDs — Admins managed strictly via SQLite / `.env`
// ============================================================================

const fallbackUsers = new Map();
let tablesVerifiedInIsolate = false;

export async function ensureDbReady() {
  if (tablesVerifiedInIsolate) return;
  tablesVerifiedInIsolate = true;
  try {
    await db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tg_id INTEGER NOT NULL UNIQUE,
      first_name TEXT DEFAULT 'User',
      username TEXT,
      lang TEXT,
      lang_selected INTEGER NOT NULL DEFAULT 0,
      is_admin INTEGER NOT NULL DEFAULT 0,
      total_scans INTEGER NOT NULL DEFAULT 0,
      threats_blocked INTEGER NOT NULL DEFAULT 0,
      prefs TEXT DEFAULT '{}',
      created_at INTEGER NOT NULL DEFAULT (unixepoch()),
      updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
    await db.run(`CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tg_id INTEGER NOT NULL,
      input_url TEXT NOT NULL,
      normalized_url TEXT NOT NULL,
      final_url TEXT NOT NULL,
      domain TEXT NOT NULL,
      url_hash TEXT NOT NULL,
      risk_score INTEGER NOT NULL DEFAULT 0,
      verdict TEXT NOT NULL DEFAULT 'SAFE',
      grade TEXT NOT NULL DEFAULT 'A',
      engines_flagged INTEGER NOT NULL DEFAULT 0,
      engines_checked INTEGER NOT NULL DEFAULT 0,
      duration_ms INTEGER NOT NULL DEFAULT 0,
      report TEXT NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
    await db.run(`CREATE TABLE IF NOT EXISTS bot_config (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
    await db.run(`CREATE TABLE IF NOT EXISTS scan_stops (
      draft_key TEXT PRIMARY KEY,
      stopped_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
    await db.run(`CREATE TABLE IF NOT EXISTS feed_cache (
      feed_id TEXT PRIMARY KEY,
      payload TEXT NOT NULL,
      entries_count INTEGER NOT NULL DEFAULT 0,
      synced_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
  } catch (_) {
    // Graceful fallback if DDL is managed solely via `tgcloud migrate`
  }
}

export function inferBestLanguage(user, tgUser = {}, sampleText = '') {
  if (user?.lang && isValidLang(user.lang)) return user.lang;
  const lc = String(tgUser?.language_code || '').toLowerCase();
  if (lc.startsWith('fa') || lc.startsWith('pes')) return 'fa';
  if (lc.startsWith('ru') || lc.startsWith('uk') || lc.startsWith('be') || lc.startsWith('kk')) return 'ru';
  if (/[\u0600-\u06FF]/.test(sampleText)) return 'fa';
  if (/[\u0400-\u04FF]/.test(sampleText)) return 'ru';
  return 'en';
}

export async function ensureUser(tgUser = {}) {
  await ensureDbReady();
  const tgId = Number(tgUser?.id || 0);
  if (!tgId) {
    return { tgId: 0, firstName: 'Guest', lang: null, langSelected: false, isAdmin: false, totalScans: 0, threatsBlocked: 0, prefs: {} };
  }

  try {
    let row = await db.select().from(users).where(eq(users.tgId, tgId)).get();
    if (!row) {
      const [created] = await db.insert(users)
        .values({
          tgId,
          firstName: tgUser.first_name || 'User',
          username: tgUser.username || null,
          lang: null,
          langSelected: false,
          isAdmin: false,
          prefs: {},
        })
        .returning()
        .run();
      row = created;
    }
    return row;
  } catch (_) {
    if (!fallbackUsers.has(tgId)) {
      fallbackUsers.set(tgId, {
        tgId,
        firstName: tgUser.first_name || 'User',
        username: tgUser.username || null,
        lang: null,
        langSelected: false,
        isAdmin: false,
        totalScans: 0,
        threatsBlocked: 0,
        prefs: {},
      });
    }
    return fallbackUsers.get(tgId);
  }
}

export async function setUserLanguage(tgId, lang, tgUser = {}) {
  if (!isValidLang(lang)) return null;
  const user = await ensureUser({ id: tgId, ...tgUser });
  const prevPrefs = (user.prefs && typeof user.prefs === 'object') ? { ...user.prefs } : {};
  const pendingUrl = prevPrefs.pendingUrl || null;
  const pendingSpoof = prevPrefs.pendingSpoof || null;
  delete prevPrefs.pendingUrl;
  delete prevPrefs.pendingSpoof;

  if (!Number(tgId)) {
    return { user: { ...user, lang, langSelected: true, prefs: prevPrefs }, pendingUrl, pendingSpoof };
  }

  try {
    const [updated] = await db.update(users)
      .set({
        lang,
        langSelected: true,
        prefs: prevPrefs,
        updatedAt: sql`(unixepoch())`,
      })
      .where(eq(users.tgId, Number(tgId)))
      .returning()
      .run();
    return { user: updated || { ...user, lang, langSelected: true }, pendingUrl, pendingSpoof };
  } catch (_) {
    const mem = fallbackUsers.get(Number(tgId)) || user;
    mem.lang = lang;
    mem.langSelected = true;
    mem.prefs = prevPrefs;
    fallbackUsers.set(Number(tgId), mem);
    return { user: mem, pendingUrl, pendingSpoof };
  }
}

export async function savePendingScanForNewUser(tgId, url, spoofAlert = null, tgUser = {}) {
  if (!Number(tgId)) return;
  const user = await ensureUser({ id: tgId, ...tgUser });
  const prefs = {
    ...(user.prefs && typeof user.prefs === 'object' ? user.prefs : {}),
    pendingUrl: url,
    pendingSpoof: spoofAlert,
  };
  try {
    await db.update(users)
      .set({ prefs, updatedAt: sql`(unixepoch())` })
      .where(eq(users.tgId, Number(tgId)))
      .run();
  } catch (_) {
    const mem = fallbackUsers.get(Number(tgId)) || user;
    mem.prefs = prefs;
    fallbackUsers.set(Number(tgId), mem);
  }
}

export async function recordUserScanStats(tgId, isThreat) {
  if (!Number(tgId)) return;
  await ensureDbReady();
  try {
    await db.update(users)
      .set({
        totalScans: sql`${users.totalScans} + 1`,
        threatsBlocked: isThreat ? sql`${users.threatsBlocked} + 1` : users.threatsBlocked,
        updatedAt: sql`(unixepoch())`,
      })
      .where(eq(users.tgId, Number(tgId)))
      .run();
  } catch (_) {
    const mem = fallbackUsers.get(Number(tgId));
    if (mem) {
      mem.totalScans = (mem.totalScans || 0) + 1;
      if (isThreat) mem.threatsBlocked = (mem.threatsBlocked || 0) + 1;
    }
  }
}

export async function isUserAdmin(tgId, cfg) {
  const numericId = Number(tgId || 0);
  if (!numericId) return false;

  const envAdmins = String(cfg?.ADMIN_TG_IDS || '')
    .split(',')
    .map((s) => Number(s.trim()))
    .filter(Boolean);
  if (envAdmins.includes(numericId)) return true;

  try {
    const row = await db.select().from(users).where(eq(users.tgId, numericId)).get();
    return Boolean(row?.isAdmin);
  } catch (_) {
    return Boolean(fallbackUsers.get(numericId)?.isAdmin);
  }
}

export async function claimAdminIfNone(tgId, cfg, tgUser = {}) {
  const numericId = Number(tgId || 0);
  if (!numericId) return { ok: false, reason: 'UNAUTHENTICATED' };

  const envAdmins = String(cfg?.ADMIN_TG_IDS || '').trim();
  if (envAdmins) {
    const ok = await isUserAdmin(numericId, cfg);
    return { ok, reason: ok ? 'CONFIG_ADMIN' : 'LOCKED_BY_CONFIG' };
  }
  await ensureUser({ id: numericId, ...tgUser });
  try {
    const existing = await db.select().from(users).where(eq(users.isAdmin, true)).get();
    if (existing && Number(existing.tgId) !== numericId) {
      return { ok: false, reason: 'ALREADY_CLAIMED' };
    }
    await db.update(users)
      .set({ isAdmin: true, updatedAt: sql`(unixepoch())` })
      .where(eq(users.tgId, numericId))
      .run();
    return { ok: true };
  } catch (_) {
    const mem = fallbackUsers.get(numericId);
    if (mem) mem.isAdmin = true;
    return { ok: true };
  }
}

export async function getScanById(scanId) {
  await ensureDbReady();
  try {
    return await db.select().from(scans).where(eq(scans.id, Number(scanId))).get();
  } catch (_) {
    return null;
  }
}

export async function getUserHistory(tgId, limitCount = 8) {
  if (!Number(tgId)) return [];
  await ensureDbReady();
  try {
    return await db.select()
      .from(scans)
      .where(eq(scans.tgId, Number(tgId)))
      .orderBy(desc(scans.id))
      .limit(limitCount)
      .all();
  } catch (_) {
    return [];
  }
}

export async function clearUserHistory(tgId) {
  if (!Number(tgId)) return;
  await ensureDbReady();
  try {
    await db.delete(scans).where(eq(scans.tgId, Number(tgId))).run();
  } catch (_) {
    // ignore
  }
}

export async function getGlobalStats(tgId) {
  await ensureDbReady();
  try {
    const userRow = Number(tgId)
      ? await db.select().from(users).where(eq(users.tgId, Number(tgId))).get()
      : null;
    const globalTotal = await db.$count(scans);
    return {
      totalScans: userRow?.totalScans || 0,
      threatsBlocked: userRow?.threatsBlocked || 0,
      globalScans: globalTotal || 0,
    };
  } catch (_) {
    const mem = fallbackUsers.get(Number(tgId));
    return {
      totalScans: mem?.totalScans || 0,
      threatsBlocked: mem?.threatsBlocked || 0,
      globalScans: mem?.totalScans || 0,
    };
  }
}
