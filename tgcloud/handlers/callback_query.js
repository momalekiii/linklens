import { api } from 'sdk';
import { t, isValidLang } from '../lib/i18n.js';
import {
  ensureUser,
  setUserLanguage,
  getScanById,
  getUserHistory,
  clearUserHistory,
  getGlobalStats,
  isUserAdmin,
} from '../lib/usersRepo.js';
import { getConfigMap, getEngineStatuses } from '../lib/secrets.js';
import { getIranFeedTelemetry } from '../lib/providers/iranIntel.js';
import {
  buildLanguageGateKeyboard,
  buildHomeKeyboard,
  buildAboutKeyboard,
  buildScanReportKeyboard,
  buildHistoryKeyboard,
  buildSimpleBackKeyboard,
} from '../lib/keyboards.js';
import {
  renderHomeMessage,
  renderAboutMessage,
  renderScanReportHtml,
  buildPlainClipboardSummary,
  renderHistoryMessage,
  renderStatsMessage,
  renderApiKeysMessage,
} from '../lib/reportFormatter.js';
import { executeStreamingChatScan } from '../lib/chatFlow.js';
import { safeEditMessageText } from '../lib/tgSend.js';
import { isInstanceActivated } from '../lib/instanceGuard.js';

// ============================================================================
// handlers/callback_query.js — Interactive Colored Inline Button Handler
// All navigation, multi-link switching & live re-scans update IN-PLACE!
// ============================================================================

async function loadSiblingMeta(csvIds) {
  if (!csvIds) return null;
  const ids = String(csvIds).split(',').map((n) => Number(n)).filter(Boolean);
  if (ids.length <= 1) return null;
  const rows = await Promise.all(ids.map((id) => getScanById(id)));
  const valid = rows.filter((r) => r?.report);
  if (valid.length <= 1) return null;
  return valid.map((r) => ({
    scanId: r.id,
    domain: r.domain,
    verdict: r.verdict,
    riskScore: r.riskScore,
  }));
}

export default async function (query) {
  if (!query?.id) return;

  const data = String(query.data || '');
  const tgUser = query.from || {};
  const chat = query.message?.chat;
  const chatId = chat?.id || tgUser.id;
  const messageId = query.message?.message_id;

  const user = await ensureUser(tgUser);
  const cfg = await getConfigMap();

  if (!isInstanceActivated(cfg)) {
    await api.answerCallbackQuery({
      callback_query_id: query.id,
      text: '⛔ Unauthorized clone instance (Audit-only repository)',
      show_alert: true,
    }).catch(() => null);
    return;
  }

  // 1. Language Selection Handler
  if (data.startsWith('lang:set:')) {
    const chosen = data.slice('lang:set:'.length);
    if (!isValidLang(chosen)) {
      await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
      return;
    }

    const updated = await setUserLanguage(tgUser.id, chosen, tgUser);
    const s = t(chosen);

    await api.answerCallbackQuery({
      callback_query_id: query.id,
      text: s.langSavedToast,
    }).catch(() => null);

    if (updated?.pendingUrl && chatId) {
      await executeStreamingChatScan({
        chatId,
        existingMessageId: messageId || null,
        tgId: tgUser.id,
        rawUrl: updated.pendingUrl,
        spoofAlert: updated.pendingSpoof || null,
        forceRescan: false,
        lang: chosen,
      });
      return;
    }

    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderHomeMessage(chosen),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildHomeKeyboard(chosen, cfg.MINI_APP_URL),
      });
    }
    return;
  }

  // Guard: If a button was clicked before language selection, open language selector
  if (!user.langSelected || !user.lang) {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    if (chatId && messageId) {
      await api.editMessageReplyMarkup({
        chat_id: chatId,
        message_id: messageId,
        reply_markup: buildLanguageGateKeyboard(null),
      }).catch(() => null);
    }
    return;
  }

  const lang = user.lang;
  const s = t(lang);

  // 2. Open Language Switcher Menu
  if (data === 'lang:menu') {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: s.chooseLangPrompt,
        parse_mode: 'HTML',
        reply_markup: buildLanguageGateKeyboard(lang),
      });
    }
    return;
  }

  // 3. Home Menu Navigation
  if (data === 'nav:home') {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderHomeMessage(lang),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildHomeKeyboard(lang, cfg.MINI_APP_URL),
      });
    }
    return;
  }

  // 4. Dedicated About Us Page (ONLY screen with owner copyright & link!)
  if (data === 'nav:about') {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderAboutMessage(lang),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildAboutKeyboard(lang),
      });
    }
    return;
  }

  // 5. Stats Screen
  if (data === 'nav:stats') {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    const stats = await getGlobalStats(tgUser.id);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderStatsMessage(stats, lang),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildSimpleBackKeyboard(lang),
      });
    }
    return;
  }

  // 6. System & Feeds Status
  if (data === 'keys:menu') {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    const [engines, admin] = await Promise.all([
      getEngineStatuses(lang),
      isUserAdmin(tgUser.id, cfg),
    ]);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderApiKeysMessage(engines, cfg.MINI_APP_URL, lang),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildSimpleBackKeyboard(lang, admin),
      });
    }
    return;
  }

  if (data === 'keys:sync') {
    if (!(await isUserAdmin(tgUser.id, cfg))) {
      await api.answerCallbackQuery({ callback_query_id: query.id, text: s.lblNotAdmin, show_alert: true }).catch(() => null);
      return;
    }
    const counts = await getIranFeedTelemetry(true);
    const engines = await getEngineStatuses(lang);
    await api.answerCallbackQuery({ callback_query_id: query.id, text: '✅ Synced!' }).catch(() => null);
    if (chatId && messageId) {
      const syncBanner = s.lblFeedsSynced
        .replace('{urls}', String(counts.motmaenBashUrls))
        .replace('{apks}', String(counts.motmaenBashApks))
        .replace('{leakfa}', String(counts.leakfaDomains))
        .replace('{kaveh}', String(counts.kavehMalware))
        .replace('{hibp}', String(counts.hibpBreaches));
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: `${syncBanner}\n\n${renderApiKeysMessage(engines, cfg.MINI_APP_URL, lang)}`,
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildSimpleBackKeyboard(lang, true),
      });
    }
    return;
  }

  // 7. History List & Clear
  if (data === 'hist:list') {
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    const rows = await getUserHistory(tgUser.id, 8);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderHistoryMessage(rows, lang),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildHistoryKeyboard(rows, lang),
      });
    }
    return;
  }

  if (data === 'hist:clear') {
    await clearUserHistory(tgUser.id);
    await api.answerCallbackQuery({
      callback_query_id: query.id,
      text: s.lblHistoryCleared,
    }).catch(() => null);
    if (chatId && messageId) {
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderHistoryMessage([], lang),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildHistoryKeyboard([], lang),
      });
    }
    return;
  }

  // 8. Interactive Multi-Tab & Multi-Link Switching (`tab:<scanId>:<tabName>[:<csvIds>]`)
  if (data.startsWith('tab:')) {
    const [, rawId, tabName, csvIds] = data.split(':');
    const [row, siblingMeta] = await Promise.all([
      getScanById(Number(rawId)),
      loadSiblingMeta(csvIds),
    ]);
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    if (row?.report && chatId && messageId) {
      row.report._scanId = row.id;
      const plainSummary = buildPlainClipboardSummary(row.report, lang);
      await safeEditMessageText({
        chat_id: chatId,
        message_id: messageId,
        text: renderScanReportHtml(row.report, tabName || 'overview', lang, siblingMeta),
        parse_mode: 'HTML',
        link_preview_options: { is_disabled: true },
        reply_markup: buildScanReportKeyboard({
          scanId: row.id,
          report: row.report,
          activeTab: tabName || 'overview',
          lang,
          miniAppUrl: cfg.MINI_APP_URL,
          plainSummary,
          siblingScans: siblingMeta,
        }),
      });
    }
    return;
  }

  // 9. Live Force Re-Scan (`rescan:<scanId>`) — edits THIS SAME MESSAGE in real time!
  if (data.startsWith('rescan:')) {
    const rawId = Number(data.slice('rescan:'.length));
    const row = await getScanById(rawId);
    await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
    if (row?.inputUrl && chatId) {
      await executeStreamingChatScan({
        chatId,
        existingMessageId: messageId || null,
        tgId: tgUser.id,
        rawUrl: row.inputUrl,
        forceRescan: true,
        lang,
      });
    }
    return;
  }

  await api.answerCallbackQuery({ callback_query_id: query.id }).catch(() => null);
}
