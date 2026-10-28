import { api } from 'sdk';
import { t } from '../lib/i18n.js';
import { ensureUser, inferBestLanguage } from '../lib/usersRepo.js';
import { runFullSecurityScan } from '../lib/scanner.js';
import { renderScanReportHtml, buildPlainClipboardSummary } from '../lib/reportFormatter.js';
import { coloredBtn } from '../lib/keyboards.js';
import { getConfigMap } from '../lib/secrets.js';
import { isInstanceActivated } from '../lib/instanceGuard.js';

// ============================================================================
// handlers/inline_query.js — Scan & Share LinkLens Cards Inside ANY Chat!
// ============================================================================

export default async function (inlineQuery) {
  if (!inlineQuery?.id) return;

  const cfg = await getConfigMap();
  if (!isInstanceActivated(cfg)) {
    await api.answerInlineQuery({
      inline_query_id: inlineQuery.id,
      cache_time: 10,
      results: [],
    }).catch(() => null);
    return;
  }

  const raw = String(inlineQuery.query || '').trim();
  const user = await ensureUser(inlineQuery.from);
  const lang = user.lang || inferBestLanguage(user, inlineQuery.from, raw);
  const s = t(lang);

  if (!raw || raw.length < 4) {
    await api.answerInlineQuery({
      inline_query_id: inlineQuery.id,
      cache_time: 5,
      results: [],
      button: {
        text: '🛡 Open LinkLens Scanner',
        start_parameter: 'inline_open',
      },
    }).catch(() => null);
    return;
  }

  const res = await runFullSecurityScan({
    rawUrl: raw,
    tgId: inlineQuery.from?.id || 0,
  });

  if (!res.ok) {
    await api.answerInlineQuery({
      inline_query_id: inlineQuery.id,
      cache_time: 5,
      results: [],
    }).catch(() => null);
    return;
  }

  const { report } = res;
  const isSafe = report.verdict === 'SAFE' || report.verdict === 'LOW_RISK';
  const summary = buildPlainClipboardSummary(report, lang);
  const safeCopyTarget = String(report.defangedUrl || report.finalUrl || '').slice(0, 200);

  await api.answerInlineQuery({
    inline_query_id: inlineQuery.id,
    cache_time: 60,
    results: [
      {
        type: 'article',
        id: `scan_${report.urlHash.slice(0, 24)}`,
        title: `${s[`verdict_${report.verdict}`]} — ${report.domain} (${report.riskScore}/100)`,
        description: `Grade ${report.grade} • SSL: ${report.http?.httpsEnforced ? 'HTTPS' : 'HTTP'} • Headers: ${report.http?.headerGrade}`,
        input_message_content: {
          message_text: renderScanReportHtml(report, 'overview', lang),
          parse_mode: 'HTML',
          link_preview_options: { is_disabled: true },
        },
        reply_markup: {
          inline_keyboard: [
            [
              isSafe && /^https?:\/\//i.test(report.finalUrl) && String(report.finalUrl).length <= 1024
                ? coloredBtn({ text: s.btnOpenSafeUrl, url: report.finalUrl, style: 'success' })
                : coloredBtn({ text: s.btnCopyDefanged, copy_text: { text: safeCopyTarget || 'LinkLens' }, style: 'danger' }),
            ],
            [
              coloredBtn({ text: s.btnCopySummary, copy_text: { text: summary.slice(0, 200) }, style: 'primary' }),
            ],
          ],
        },
      },
    ],
  }).catch(() => null);
}
