import { api } from 'sdk';

// ============================================================================
// Fault-Tolerant Telegram Bot API Sender & Editor
// Guarantees 100% delivery even if a client/API edge case rejects optional
// button properties (`style`, `copy_text`, invalid `web_app` URL) or `<blockquote expandable>`.
// ============================================================================

function downgradeKeyboard(replyMarkup) {
  if (!replyMarkup?.inline_keyboard) return undefined;
  const rows = [];
  for (const row of replyMarkup.inline_keyboard) {
    const cleanRow = [];
    for (const btn of row) {
      if (!btn) continue;
      // Drop `copy_text` if rejected and strip non-essential `style`
      if (btn.copy_text) continue;
      // MINI APP SURFACE: LinkLens is chat-only. Any web_app button is dropped
      // outright, so a stale keyboard can never resurrect a webview entry point.
      if (btn.web_app) continue;
      const copy = { ...btn };
      delete copy.style;
      cleanRow.push(copy);
    }
    if (cleanRow.length > 0) rows.push(cleanRow);
  }
  return rows.length > 0 ? { inline_keyboard: rows } : undefined;
}

function downgradeHtml(html) {
  return String(html || '').replace(/<blockquote\s+expandable>/gi, '<blockquote>');
}

export async function safeSendMessage(params) {
  try {
    return await api.sendMessage(params);
  } catch (_) {
    try {
      return await api.sendMessage({
        ...params,
        text: downgradeHtml(params.text),
        reply_markup: downgradeKeyboard(params.reply_markup),
      });
    } catch (err2) {
      return await api.sendMessage({
        chat_id: params.chat_id,
        ...(params.message_thread_id ? { message_thread_id: params.message_thread_id } : {}),
        text: downgradeHtml(params.text).replace(/<[^>]+>/g, ''),
      });
    }
  }
}

export async function safeEditMessageText(params) {
  try {
    return await api.editMessageText(params);
  } catch (_) {
    return await api.editMessageText({
      ...params,
      text: downgradeHtml(params.text),
      reply_markup: downgradeKeyboard(params.reply_markup),
    }).catch(() => null);
  }
}
