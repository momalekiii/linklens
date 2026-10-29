import { t } from './i18n.js';
import { getConfigMap } from './secrets.js';
import { runFullSecurityScan } from './scanner.js';
import {
  renderDraftProgressMessage,
  renderScanReportHtml,
  buildPlainClipboardSummary,
} from './reportFormatter.js';
import { buildScanReportKeyboard, buildHomeKeyboard } from './keyboards.js';
import { safeSendMessage, safeEditMessageText } from './tgSend.js';

// ============================================================================
// Single-Message Real-Time In-Place Live-Edit Scan Executor (`chatFlow.js`)
// STRICT GUARANTEE:
// - Calls `sendMessage` AT MOST ONCE per user message (`0` if `existingMessageId` passed!)
// - Updates THAT EXACT SAME 1 MESSAGE live in real time (`editMessageText`) across
//   every scan stage (`0/4 -> 1/4 -> 2/4 -> 3/4 -> 4/4`) and final report!
// - Even when a forwarded message contains multiple links, ALL links are scanned
//   inside that SAME 1 message with highest-risk first + interactive link switcher!
// ============================================================================

const MAX_AUTO_LINKS_PER_MESSAGE = 4;

export async function executeStreamingChatScan({
  chatId,
  threadId = undefined,
  replyToMessageId = undefined,
  existingMessageId = null,
  tgId,
  rawUrl,
  spoofAlert = null,
  forceRescan = false,
  lang = 'en',
}) {
  return executeMultiLinkChatScan({
    chatId,
    threadId,
    replyToMessageId,
    existingMessageId,
    tgId,
    urls: [rawUrl],
    spoofAlert,
    forceRescan,
    lang,
  });
}

export async function executeMultiLinkChatScan({
  chatId,
  threadId = undefined,
  replyToMessageId = undefined,
  existingMessageId = null,
  tgId,
  urls = [],
  spoofAlert = null,
  forceRescan = false,
  lang = 'en',
}) {
  const s = t(lang);
  const cfg = await getConfigMap();
  const targets = urls.slice(0, MAX_AUTO_LINKS_PER_MESSAGE);
  if (!targets.length) return;

  let liveMsgId = existingMessageId || null;
  let lastHtmlSent = '';
  let editChain = Promise.resolve();

  const pushLiveView = (html, replyMarkup = undefined) => {
    if (!html || html === lastHtmlSent) return editChain;
    lastHtmlSent = html;

    editChain = editChain.then(async () => {
      if (!liveMsgId) {
        const sent = await safeSendMessage({
          chat_id: chatId,
          ...(threadId ? { message_thread_id: threadId } : {}),
          ...(replyToMessageId ? { reply_parameters: { message_id: replyToMessageId, allow_sending_without_reply: true } } : {}),
          text: html,
          parse_mode: 'HTML',
          link_preview_options: { is_disabled: true },
          ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
        });
        liveMsgId = sent?.message_id || null;
      } else {
        await safeEditMessageText({
          chat_id: chatId,
          message_id: liveMsgId,
          text: html,
          parse_mode: 'HTML',
          link_preview_options: { is_disabled: true },
          ...(replyMarkup ? { reply_markup: replyMarkup } : {}),
        });
      }
    }).catch(() => null);

    return editChain;
  };

  // Send the ONE AND ONLY message immediately (Stage 0) so user sees instant live feedback!
  const firstExtra = targets.length > 1
    ? s.multiLinkProgress.replace('{idx}', '1').replace('{total}', String(targets.length))
    : '';
  await pushLiveView(renderDraftProgressMessage(0, targets[0], lang, firstExtra));

  const completedScans = [];
  let lastError = null;

  for (let i = 0; i < targets.length; i += 1) {
    const currentUrl = targets[i];
    const extraHeader = targets.length > 1
      ? s.multiLinkProgress.replace('{idx}', String(i + 1)).replace('{total}', String(targets.length))
      : '';

    const onStage = async (stageNum) => {
      await pushLiveView(renderDraftProgressMessage(stageNum, currentUrl, lang, extraHeader));
    };

    // A failed layer or an unexpected throw must never leave the live message
    // frozen on a progress stage — always fall through to a rendered outcome.
    let result;
    try {
      result = await runFullSecurityScan({
        rawUrl: currentUrl,
        tgId,
        spoofAlert: i === 0 ? spoofAlert : null,
        forceRescan,
        onStage,
      });
    } catch (_) {
      result = { ok: false, error: 'SCAN_FAILED' };
    }

    if (result.ok && result.report) {
      result.report._scanId = result.scanId;
      completedScans.push({
        scanId: result.scanId,
        report: result.report,
        domain: result.report.domain,
        verdict: result.report.verdict,
        riskScore: result.report.riskScore,
      });
    } else {
      lastError = result.error || 'INVALID_URL';
    }
  }

  // Wait for any pending live progress edit to settle cleanly before final edit
  await editChain;

  if (completedScans.length === 0) {
    const errText = lastError === 'PRIVATE_TARGET'
      ? s.lblBlockedPrivate
      : lastError === 'SCAN_FAILED'
        ? s.lblScanFailed
        : s.lblNoUrlFound;
    lastHtmlSent = '';
    await pushLiveView(errText, buildHomeKeyboard(lang));
    return;
  }

  // If multiple links were in a forwarded post, showcase the highest-risk link first!
  const sorted = [...completedScans].sort((a, b) => b.riskScore - a.riskScore);
  const primary = sorted[0];
  const siblingMeta = sorted.length > 1
    ? sorted.map((x) => ({
        scanId: x.scanId,
        domain: x.domain,
        verdict: x.verdict,
        riskScore: x.riskScore,
      }))
    : null;

  const plainSummary = buildPlainClipboardSummary(primary.report, lang);
  const finalHtml = renderScanReportHtml(primary.report, 'overview', lang, siblingMeta);
  const replyMarkup = buildScanReportKeyboard({
    scanId: primary.scanId,
    report: primary.report,
    activeTab: 'overview',
    lang,
    plainSummary,
    siblingScans: siblingMeta,
  });

  lastHtmlSent = '';
  await pushLiveView(finalHtml, replyMarkup);
}
