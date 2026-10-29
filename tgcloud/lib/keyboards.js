import { t } from './i18n.js';

// ============================================================================
// Telegram Bot API 9.4–10.3 Colored Inline Keyboards Builder
// Official `style` enum values: 'primary' (Blue), 'success' (Green), 'danger' (Red)
// Clean Production UI — Zero sample buttons; About Us button included
// ============================================================================

const VALID_STYLES = new Set(['primary', 'success', 'danger']);

export function coloredBtn({ text, style, ...action }) {
  const button = { text: String(text), ...action };
  if (style && VALID_STYLES.has(style)) {
    button.style = style;
  }
  return button;
}

function safeCopyText(str) {
  const clean = String(str || '').trim().slice(0, 200);
  return clean || 'LinkLens';
}

// 1. First-Launch & Language Switcher Picker (Colored Buttons for FA / EN / RU)
export function buildLanguageGateKeyboard(currentLang = null) {
  return {
    inline_keyboard: [
      [
        coloredBtn({
          text: `${currentLang === 'fa' ? '· ' : ''}فارسی`,
          callback_data: 'lang:set:fa',
          style: 'success',
        }),
      ],
      [
        coloredBtn({
          text: `${currentLang === 'en' ? '· ' : ''}English`,
          callback_data: 'lang:set:en',
          style: 'primary',
        }),
      ],
      [
        coloredBtn({
          text: `${currentLang === 'ru' ? '· ' : ''}Русский`,
          callback_data: 'lang:set:ru',
          style: 'danger',
        }),
      ],
      ...(currentLang
        ? [[coloredBtn({ text: t(currentLang).btnHome, callback_data: 'nav:home', style: 'primary' })]]
        : []),
    ],
  };
}

// 2. Main LinkLens Security Hub Menu (Includes About Us; Zero Sample Buttons)
export function buildHomeKeyboard(lang = 'en') {
  const s = t(lang);
  const rows = [];

  rows.push([
    coloredBtn({ text: s.btnHistory, callback_data: 'hist:list', style: 'primary' }),
    coloredBtn({ text: s.btnStats, callback_data: 'nav:stats', style: 'success' }),
  ]);

  rows.push([
    coloredBtn({ text: s.btnLanguage, callback_data: 'lang:menu', style: 'primary' }),
    coloredBtn({ text: s.btnApiKeys, callback_data: 'keys:menu', style: 'danger' }),
  ]);

  rows.push([
    coloredBtn({ text: s.btnAbout, callback_data: 'nav:about', style: 'primary' }),
  ]);

  return { inline_keyboard: rows };
}

// 3. Dedicated About Us Keyboard (ONLY place linking directly to owner website)
export function buildAboutKeyboard(lang = 'en') {
  const s = t(lang);
  return {
    inline_keyboard: [
      [
        coloredBtn({
          text: s.btnVisitWebsite,
          url: 'https://momalekiii.github.io',
          style: 'success',
        }),
      ],
      [
        coloredBtn({ text: s.btnHome, callback_data: 'nav:home', style: 'primary' }),
        coloredBtn({ text: s.btnLanguage, callback_data: 'lang:menu', style: 'primary' }),
      ],
    ],
  };
}

// 4. Multi-Tab Interactive Security Report Keyboard (Supports in-place multi-link switching!)
export function buildScanReportKeyboard({
  scanId,
  report,
  activeTab = 'overview',
  lang = 'en',
  plainSummary = '',
  siblingScans = null,
}) {
  const s = t(lang);
  const rows = [];
  const isSafe = report.verdict === 'SAFE' || report.verdict === 'LOW_RISK';

  // If message contained multiple links, render in-place switcher row inside this SAME single message!
  if (Array.isArray(siblingScans) && siblingScans.length > 1) {
    const csvIds = siblingScans.map((x) => x.scanId).join(',');
    const switchBtns = siblingScans.map((item) => {
      const active = Number(item.scanId) === Number(scanId);
      const ic = item.verdict === 'MALICIOUS' ? 'D' : item.verdict === 'SUSPICIOUS' ? 'C' : '·';
      const style = active
        ? 'success'
        : (item.verdict === 'MALICIOUS' || item.verdict === 'SUSPICIOUS' ? 'danger' : 'primary');
      return coloredBtn({
        text: `${active ? '· ' : ''}${String(item.domain).slice(0, 18)}`,
        callback_data: `tab:${item.scanId}:overview:${csvIds}`.slice(0, 64),
        style,
      });
    });
    for (let i = 0; i < switchBtns.length; i += 2) {
      rows.push(switchBtns.slice(i, i + 2));
    }
  }

  const csvSuffix = Array.isArray(siblingScans) && siblingScans.length > 1
    ? `:${siblingScans.map((x) => x.scanId).join(',')}`
    : '';

  // Primary Action Row: Green Safe Link vs Red Defanged Hazard Warning!
  if (isSafe && /^https?:\/\//i.test(report.finalUrl) && String(report.finalUrl).length <= 1024) {
    rows.push([
      coloredBtn({
        text: s.btnOpenSafeUrl,
        url: report.finalUrl,
        style: 'success',
      }),
    ]);
  } else {
    rows.push([
      coloredBtn({
        text: s.btnCopyDefanged,
        copy_text: { text: safeCopyText(report.defangedUrl || report.finalUrl) },
        style: 'danger',
      }),
    ]);
  }

  // Direct Leakfa Incident Report Button whenever a Leakfa breach record matches!
  if (report.iran?.primaryLeakfaUrl && /^https?:\/\//i.test(report.iran.primaryLeakfaUrl)) {
    rows.push([
      coloredBtn({
        text: s.btnOpenLeakfaReport,
        url: report.iran.primaryLeakfaUrl,
        style: 'danger',
      }),
    ]);
  }

  // Interactive Multi-Layer Tabs (Green = active selected tab, Blue = switchable tab)
  if (scanId) {
    rows.push([
      coloredBtn({
        text: s.btnTabOverview,
        callback_data: `tab:${scanId}:overview${csvSuffix}`.slice(0, 64),
        style: activeTab === 'overview' ? 'success' : 'primary',
      }),
      coloredBtn({
        text: s.btnTabIran,
        callback_data: `tab:${scanId}:iran${csvSuffix}`.slice(0, 64),
        style: activeTab === 'iran' ? 'success' : 'primary',
      }),
    ]);
    rows.push([
      coloredBtn({
        text: s.btnTabEngines,
        callback_data: `tab:${scanId}:engines${csvSuffix}`.slice(0, 64),
        style: activeTab === 'engines' ? 'success' : 'primary',
      }),
      coloredBtn({
        text: s.btnTabInfra,
        callback_data: `tab:${scanId}:infra${csvSuffix}`.slice(0, 64),
        style: activeTab === 'infra' ? 'success' : 'primary',
      }),
      coloredBtn({
        text: s.btnTabHeaders,
        callback_data: `tab:${scanId}:headers${csvSuffix}`.slice(0, 64),
        style: activeTab === 'headers' ? 'success' : 'primary',
      }),
    ]);
  }

  // Copy Report + Force Re-Scan Row
  const utilRow = [];
  if (plainSummary) {
    utilRow.push(
      coloredBtn({
        text: s.btnCopySummary,
        copy_text: { text: safeCopyText(plainSummary) },
        style: 'primary',
      })
    );
  }
  if (scanId) {
    utilRow.push(
      coloredBtn({
        text: s.btnForceRescan,
        callback_data: `rescan:${scanId}`,
        style: 'danger',
      })
    );
  }
  if (utilRow.length) rows.push(utilRow);

  // Navigation Footer
  rows.push([
    coloredBtn({ text: s.btnHome, callback_data: 'nav:home', style: 'primary' }),
    coloredBtn({ text: s.btnLanguage, callback_data: 'lang:menu', style: 'success' }),
  ]);

  return { inline_keyboard: rows };
}

// 5. Scan History List Keyboard (Clean History — Zero Sample Buttons)
export function buildHistoryKeyboard(historyRows, lang = 'en') {
  const s = t(lang);
  const rows = [];

  for (const item of historyRows) {
    const isDanger = item.verdict === 'MALICIOUS' || item.verdict === 'SUSPICIOUS';
    const tag = item.verdict === 'MALICIOUS' ? 'DANGER' : item.verdict === 'SUSPICIOUS' ? 'CAUTION' : 'CLEAR';
    const label = `${tag} ${item.riskScore}/100 · ${String(item.domain).slice(0, 22)}`;
    rows.push([
      coloredBtn({
        text: label,
        callback_data: `tab:${item.id}:overview`,
        style: isDanger ? 'danger' : 'success',
      }),
    ]);
  }

  if (historyRows.length > 0) {
    rows.push([
      coloredBtn({ text: s.btnClearHistory, callback_data: 'hist:clear', style: 'danger' }),
      coloredBtn({ text: s.btnHome, callback_data: 'nav:home', style: 'primary' }),
    ]);
  } else {
    rows.push([
      coloredBtn({ text: s.btnHome, callback_data: 'nav:home', style: 'primary' }),
      coloredBtn({ text: s.btnLanguage, callback_data: 'lang:menu', style: 'success' }),
    ]);
  }

  return { inline_keyboard: rows };
}

export function buildSimpleBackKeyboard(lang = 'en', showSyncFeeds = false) {
  const s = t(lang);
  const rows = [];
  if (showSyncFeeds) {
    rows.push([
      coloredBtn({
        text: lang === 'fa' ? 'همگام‌سازی منابع' : lang === 'ru' ? 'Обновить фиды' : 'Sync feeds',
        callback_data: 'keys:sync',
        style: 'success',
      }),
    ]);
  }
  rows.push([
    coloredBtn({ text: s.btnHome, callback_data: 'nav:home', style: 'primary' }),
    coloredBtn({ text: s.btnLanguage, callback_data: 'lang:menu', style: 'success' }),
  ]);
  return { inline_keyboard: rows };
}
