import { EndpointError } from 'sdk';
import { ensureUser } from '../lib/usersRepo.js';
import { runFullSecurityScan } from '../lib/scanner.js';
import { formatFinding } from '../lib/i18n.js';
import { getConfigMap } from '../lib/secrets.js';
import { renderScanReportHtml, buildPlainClipboardSummary } from '../lib/reportFormatter.js';
import { buildScanReportKeyboard } from '../lib/keyboards.js';
import { safeSendMessage } from '../lib/tgSend.js';
import { assertAuthorizedInstance } from '../lib/instanceGuard.js';

// ============================================================================
// endpoints/scanLink.js — Deep Multi-Layer Security Scan from Mini App
// ============================================================================

export default async function (input, ctx) {
  const cfg = await getConfigMap();
  assertAuthorizedInstance(cfg);

  const tgUser = ctx?.initData?.user || { id: 0, first_name: 'Guest' };
  const rawUrl = String(input?.url || '').trim();
  const forceRescan = Boolean(input?.forceRescan);
  const sendToChat = Boolean(input?.sendToChat && tgUser.id > 0);

  if (!rawUrl) {
    throw new EndpointError('Please enter a valid URL or domain to scan.', {
      code: 'EMPTY_URL',
    });
  }

  const user = await ensureUser(tgUser);
  const lang = input?.lang || user.lang || 'en';

  const res = await runFullSecurityScan({
    rawUrl,
    tgId: tgUser.id,
    forceRescan,
  });

  if (!res.ok) {
    throw new EndpointError(
      res.error === 'PRIVATE_TARGET'
        ? 'Scanning private / local network addresses is blocked (SSRF protection).'
        : 'Invalid or unsupported URL format.',
      { code: res.error || 'SCAN_ERROR' }
    );
  }

  const localizedFindings = (res.report.findings || []).map((f) => ({
    ...f,
    localizedText: formatFinding(f, lang),
  }));

  if (sendToChat && tgUser.id > 0) {
    const plainSummary = buildPlainClipboardSummary(res.report, lang);
    await safeSendMessage({
      chat_id: tgUser.id,
      text: renderScanReportHtml(res.report, 'overview', lang),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: buildScanReportKeyboard({
        scanId: res.scanId,
        report: res.report,
        activeTab: 'overview',
        lang,
        miniAppUrl: cfg.MINI_APP_URL,
        plainSummary,
      }),
    });
  }

  return {
    scanId: res.scanId,
    report: {
      ...res.report,
      findings: localizedFindings,
    },
  };
}
