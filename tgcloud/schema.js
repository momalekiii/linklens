import { table, integer, text, boolean, json, index, sql } from 'sdk/db';

// LinkLens Database Schema — Telegram Serverless SQLite (Drizzle DSL)
// Note: Telegram Serverless runs with PRAGMA foreign_keys = OFF; logical links
// are enforced cleanly in application code per platform rules.

export const users = table('users', {
  id:             integer('id').primaryKey({ autoIncrement: true }),
  tgId:           integer('tg_id').notNull().unique(),
  firstName:      text('first_name').default('User'),
  username:       text('username'),
  // Starts null + langSelected=false so every new user chooses FA / EN / RU first!
  lang:           text('lang'),
  langSelected:   boolean('lang_selected').notNull().default(false),
  isAdmin:        boolean('is_admin').notNull().default(false),
  totalScans:     integer('total_scans').notNull().default(0),
  threatsBlocked: integer('threats_blocked').notNull().default(0),
  prefs:          json('prefs').default({}),
  createdAt:      integer('created_at').notNull().default(sql`(unixepoch())`),
  updatedAt:      integer('updated_at').notNull().default(sql`(unixepoch())`),
}, (t) => ({
  langIdx: index('idx_users_lang').on(t.lang),
}));

export const scans = table('scans', {
  id:            integer('id').primaryKey({ autoIncrement: true }),
  tgId:          integer('tg_id').notNull(),
  inputUrl:      text('input_url').notNull(),
  normalizedUrl: text('normalized_url').notNull(),
  finalUrl:      text('final_url').notNull(),
  domain:        text('domain').notNull(),
  urlHash:       text('url_hash').notNull(),
  riskScore:     integer('risk_score').notNull().default(0),
  verdict:       text('verdict').notNull().default('SAFE'),
  grade:         text('grade').notNull().default('A'),
  enginesFlagged:integer('engines_flagged').notNull().default(0),
  enginesChecked:integer('engines_checked').notNull().default(0),
  durationMs:    integer('duration_ms').notNull().default(0),
  report:        json('report').notNull(),
  createdAt:     integer('created_at').notNull().default(sql`(unixepoch())`),
}, (t) => ({
  userScansIdx:  index('idx_scans_tg_created').on(t.tgId, t.createdAt),
  cacheLookupIdx:index('idx_scans_norm_created').on(t.normalizedUrl, t.createdAt),
  domainIdx:     index('idx_scans_domain').on(t.domain),
}));

export const botConfig = table('bot_config', {
  key:       text('key').primaryKey(),
  value:     text('value').notNull(),
  updatedAt: integer('updated_at').notNull().default(sql`(unixepoch())`),
});

export const scanStops = table('scan_stops', {
  draftKey:  text('draft_key').primaryKey(),
  stoppedAt: integer('stopped_at').notNull().default(sql`(unixepoch())`),
});

// Persistent 6-hour SQLite Threat & Breach Feed Cache (MotmaenBash, Leakfa, Kaveh, HIBP)
export const feedCache = table('feed_cache', {
  feedId:       text('feed_id').primaryKey(),
  payload:      text('payload').notNull(),
  entriesCount: integer('entries_count').notNull().default(0),
  syncedAt:     integer('synced_at').notNull().default(sql`(unixepoch())`),
});
