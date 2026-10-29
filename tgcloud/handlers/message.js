import { api, db } from 'sdk';
import { eq } from 'sdk/db';
import { botConfig } from '../schema.js';
import { t, renderLanguageGateText, isValidLang } from '../lib/i18n.js';
import { extractLinksFromMessage } from '../lib/urlUtils.js';
import {
  ensureUser,
  setUserLanguage,
  inferBestLanguage,
  getUserHistory,
  getGlobalStats,
  isUserAdmin,
  claimAdminIfNone,
} from '../lib/usersRepo.js';
import {
  getConfigMap,
  setConfigValue,
  getEngineStatuses,
} from '../lib/secrets.js';
import { getIranFeedTelemetry } from '../lib/providers/iranIntel.js';
import { nowSec } from '../lib/clock.js';
import {
  buildLanguageGateKeyboard,
  buildHomeKeyboard,
  buildAboutKeyboard,
  buildHistoryKeyboard,
  buildSimpleBackKeyboard,
} from '../lib/keyboards.js';
import {
  renderHomeMessage,
  renderAboutMessage,
  renderHistoryMessage,
  renderStatsMessage,
  renderApiKeysMessage,
} from '../lib/reportFormatter.js';
import { executeMultiLinkChatScan } from '../lib/chatFlow.js';
import { ensureBotProfileInitialized } from '../lib/botProfile.js';
import { safeSendMessage } from '../lib/tgSend.js';
import { isInstanceActivated, UNAUTHORIZED_CLONE_MESSAGE } from '../lib/instanceGuard.js';

// ============================================================================
// handlers/message.js — Main Incoming & Forwarded Message Handler
// Strict Once-Per-Message Idempotency + Single-Message Live Real-Time Edit!
// ============================================================================

async function acquireMessageOnceLock(chatId, messageId) {
  if (!messageId) return true;
  const key = `MSG_LOCK_${chatId}_${messageId}`;
  try {
    const existing = await db.select().from(botConfig).where(eq(botConfig.key, key)).get();
    if (existing?.value) return false;
    await db.insert(botConfig)
      .values({ key, value: '1', updatedAt: nowSec() })
      .run();
    return true;
  } catch (_) {
    // If UNIQUE constraint conflicted across parallel isolates, another worker already handled it!
    try {
      const checkAgain = await db.select().from(botConfig).where(eq(botConfig.key, key)).get();
      if (checkAgain?.value) return false;
    } catch (_2) {
      // ignore
    }
    return true;
  }
}

export async function handleIncomingMessage(message) {
  if (!message?.chat?.id) return;

  const chatId = message.chat.id;
  const chatType = message.chat.type || 'private';
  const threadId = message.message_thread_id;
  const tgUser = message.from || { id: chatId, first_name: 'User' };
  const text = (message.text || message.caption || '').trim();

  const user = await ensureUser(tgUser);

  // Prevent duplicate webhook retries or double triggers for the exact same Telegram message!
  const isFirstDelivery = await acquireMessageOnceLock(chatId, message.message_id);
  if (!isFirstDelivery) return;

  // Verify official owner deployment cryptographic seal before processing any command or scan
  const bootCfg = await getConfigMap();
  if (!isInstanceActivated(bootCfg)) {
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: UNAUTHORIZED_CLONE_MESSAGE,
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
    });
    return;
  }

  // Ensure pre-/start Telegram welcome description & slash commands are set in FA/EN/RU!
  ensureBotProfileInitialized().catch(() => null);

  const { urls, spoofAlert } = extractLinksFromMessage(message);
  const isForwarded = Boolean(
    message.forward_origin ||
    message.forward_from ||
    message.forward_from_chat ||
    message.forward_sender_name ||
    message.forward_date ||
    message.external_reply
  );

  // Extract deep-link start parameter if user opened `/start lang_fa` etc.
  const startMatch = !isForwarded ? text.match(/^\/start(?:@\w+)?(?:\s+(.+))?$/i) : null;
  if (startMatch && startMatch[1]) {
    const param = startMatch[1].trim();
    if (param.startsWith('lang_')) {
      const code = param.replace('lang_', '').toLowerCase();
      if (isValidLang(code)) {
        await setUserLanguage(tgUser.id, code, tgUser);
        const cfg = await getConfigMap();
        await safeSendMessage({
          chat_id: chatId,
          ...(threadId ? { message_thread_id: threadId } : {}),
          text: renderHomeMessage(code),
          parse_mode: 'HTML',
          reply_markup: buildHomeKeyboard(code),
        });
        return;
      }
    }
  }

  // PRIORITY #1: ANY forwarded message with link(s) OR ANY non-command message with link(s)
  // responds with STRICTLY 1 LIVE REAL-TIME MESSAGE updated in-place!
  const isSlashCommand = !isForwarded && text.startsWith('/');
  if (urls.length > 0 && !isSlashCommand) {
    let effectiveLang = user.lang;
    if (!user.langSelected || !effectiveLang) {
      effectiveLang = inferBestLanguage(user, tgUser, text);
      await setUserLanguage(tgUser.id, effectiveLang, tgUser);
    }

    await executeMultiLinkChatScan({
      chatId,
      threadId,
      replyToMessageId: message.message_id,
      tgId: tgUser.id,
      urls,
      spoofAlert,
      lang: effectiveLang,
    });
    return;
  }

  // First-Launch Trilingual Language Picker when user opens `/start`
  if (!user.langSelected || !user.lang) {
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: renderLanguageGateText(tgUser.first_name, false, inferBestLanguage(user, tgUser, text)),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: buildLanguageGateKeyboard(null),
    });
    return;
  }

  const lang = user.lang;
  const s = t(lang);
  const cfg = await getConfigMap();

  if (/^\/(start|menu|help)(?:@\w+)?$/i.test(text)) {
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: renderHomeMessage(lang),
      parse_mode: 'HTML',
      reply_markup: buildHomeKeyboard(lang),
    });
    return;
  }

  if (/^\/about(?:@\w+)?$/i.test(text)) {
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: renderAboutMessage(lang),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: buildAboutKeyboard(lang),
    });
    return;
  }

  if (/^\/(lang|language)(?:@\w+)?$/i.test(text)) {
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: s.chooseLangPrompt,
      parse_mode: 'HTML',
      reply_markup: buildLanguageGateKeyboard(lang),
    });
    return;
  }

  if (/^\/history(?:@\w+)?$/i.test(text)) {
    const rows = await getUserHistory(tgUser.id, 8);
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: renderHistoryMessage(rows, lang),
      parse_mode: 'HTML',
      reply_markup: buildHistoryKeyboard(rows, lang),
    });
    return;
  }

  if (/^\/stats(?:@\w+)?$/i.test(text)) {
    const stats = await getGlobalStats(tgUser.id);
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: renderStatsMessage(stats, lang),
      parse_mode: 'HTML',
      reply_markup: buildSimpleBackKeyboard(lang),
    });
    return;
  }

  if (/^\/claimadmin(?:@\w+)?$/i.test(text)) {
    const claim = await claimAdminIfNone(tgUser.id, cfg, tgUser);
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: claim.ok ? s.lblAdminClaimed : s.lblNotAdmin,
      parse_mode: 'HTML',
      reply_markup: buildSimpleBackKeyboard(lang),
    });
    return;
  }

  if (/^\/(status|keys|feeds)(?:@\w+)?$/i.test(text)) {
    const [engines, admin] = await Promise.all([
      getEngineStatuses(lang),
      isUserAdmin(tgUser.id, cfg),
    ]);
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: renderApiKeysMessage(engines, lang),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: buildSimpleBackKeyboard(lang, admin),
    });
    return;
  }

  if (/^\/syncfeeds(?:@\w+)?$/i.test(text)) {
    if (!(await isUserAdmin(tgUser.id, cfg))) {
      await safeSendMessage({
        chat_id: chatId,
        ...(threadId ? { message_thread_id: threadId } : {}),
        text: s.lblNotAdmin,
        parse_mode: 'HTML',
        reply_markup: buildSimpleBackKeyboard(lang, false),
      });
      return;
    }
    const counts = await getIranFeedTelemetry(true);
    const engines = await getEngineStatuses(lang);
    const syncBanner = s.lblFeedsSynced
      .replace('{urls}', String(counts.motmaenBashUrls))
      .replace('{apks}', String(counts.motmaenBashApks))
      .replace('{leakfa}', String(counts.leakfaDomains))
      .replace('{kaveh}', String(counts.kavehMalware))
      .replace('{hibp}', String(counts.hibpBreaches));
    await safeSendMessage({
      chat_id: chatId,
      ...(threadId ? { message_thread_id: threadId } : {}),
      text: `${syncBanner}\n\n${renderApiKeysMessage(engines, lang)}`,
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: buildSimpleBackKeyboard(lang, true),
    });
    return;
  }

  const setKeyMatch = text.match(/^\/setkey(?:@\w+)?\s+(\S+)\s+(.+)$/i);
  if (setKeyMatch) {
    if (!(await isUserAdmin(tgUser.id, cfg))) {
      await safeSendMessage({
        chat_id: chatId,
        text: s.lblNotAdmin,
        parse_mode: 'HTML',
        reply_markup: buildSimpleBackKeyboard(lang),
      });
      return;
    }
    const saved = await setConfigValue(setKeyMatch[1], setKeyMatch[2]);
    await api.deleteMessage({ chat_id: chatId, message_id: message.message_id }).catch(() => null);
    const engines = await getEngineStatuses(lang);
    const updatedCfg = await getConfigMap();
    await safeSendMessage({
      chat_id: chatId,
      text: saved.ok
        ? `${s.lblKeySaved.replace('{key}', saved.key)}\n\n${renderApiKeysMessage(engines, lang)}`
        : renderApiKeysMessage(engines, lang),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: buildSimpleBackKeyboard(lang, true),
    });
    return;
  }

  // Also allow `/scan https://example.com`
  if (urls.length > 0) {
    await executeMultiLinkChatScan({
      chatId,
      threadId,
      replyToMessageId: message.message_id,
      tgId: tgUser.id,
      urls,
      spoofAlert,
      lang,
    });
    return;
  }

  // In groups/supergroups, stay quiet on plain chatter with zero URLs and no command
  if (chatType !== 'private' && !isForwarded && !isSlashCommand) {
    return;
  }

  await safeSendMessage({
    chat_id: chatId,
    ...(threadId ? { message_thread_id: threadId } : {}),
    text: s.lblNoUrlFound,
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    reply_markup: buildHomeKeyboard(lang),
  });
}

export default handleIncomingMessage;
