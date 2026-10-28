import './styles.css';
import { UI_I18N } from './uiStrings.js';
import { callEndpoint, isRealTelegramServerless, simAction, triggerHaptic } from './apiClient.js';

const ABOUT_WEBSITE_URL = 'https://momalekiii.github.io';

const state = {
  inTelegramClient: isRealTelegramServerless(),
  viewMode: isRealTelegramServerless() ? 'miniapp' : 'split', // 'split' | 'miniapp' | 'botsim'
  loadingBoot: true,
  scanning: false,
  syncingFeeds: false,
  lang: 'en',
  langSelected: false,
  user: { firstName: 'Explorer', isAdmin: false },
  stats: { totalScans: 0, threatsBlocked: 0, globalScans: 0 },
  engines: [],
  history: [],
  activeNav: 'scanner', // 'scanner' | 'history' | 'engines' | 'about'
  activeReportTab: 'overview', // 'overview' | 'iran' | 'engines' | 'infra' | 'headers'
  urlInput: '',
  sendToChat: true,
  forceRescan: false,
  currentScanId: null,
  currentReport: null,
  toast: null,
  // Live Telegram Bot Simulator State (only active in Studio Preview)
  simMessages: [],
  simDrafts: {},
  simInput: '',
};

let toastTimer = null;
function showToast(msg) {
  state.toast = msg;
  render();
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    state.toast = null;
    render();
  }, 3000);
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function verdictColor(verdict) {
  if (verdict === 'MALICIOUS') return '#ef4444';
  if (verdict === 'SUSPICIOUS') return '#f59e0b';
  if (verdict === 'LOW_RISK') return '#3b82f6';
  return '#22c55e';
}

async function refreshBootstrap() {
  const boot = await callEndpoint('bootstrap', {});
  state.user = boot.user || state.user;
  state.langSelected = Boolean(boot.user?.langSelected);
  if (boot.user?.lang) state.lang = boot.user.lang;
  state.stats = boot.stats || state.stats;
  state.engines = boot.engines || [];
  state.history = boot.history || [];
}

async function handleSelectLanguage(langCode) {
  triggerHaptic('light');
  await callEndpoint('setLanguage', { lang: langCode });
  state.lang = langCode;
  state.langSelected = true;
  await refreshBootstrap();
  if (!state.inTelegramClient) {
    const simState = await simAction('/sim/sync-lang', { lang: langCode });
    if (simState.messages) state.simMessages = simState.messages;
  }
  render();
}

async function handleScan(rawUrlOverride = null, forceOverride = null) {
  const targetUrl = (rawUrlOverride !== null ? rawUrlOverride : state.urlInput).trim();
  if (!targetUrl || state.scanning) return;
  state.urlInput = targetUrl;
  state.scanning = true;
  state.activeNav = 'scanner';
  render();

  try {
    const res = await callEndpoint('scanLink', {
      url: targetUrl,
      lang: state.lang,
      forceRescan: forceOverride !== null ? forceOverride : state.forceRescan,
      sendToChat: state.sendToChat,
    });
    state.currentScanId = res.scanId;
    state.currentReport = res.report;
    state.activeReportTab = 'overview';
    triggerHaptic(res.report.verdict === 'MALICIOUS' ? 'error' : 'success');
    await refreshBootstrap();
  } catch (err) {
    triggerHaptic('error');
    showToast(`⚠️ ${err.message}`);
  } finally {
    state.scanning = false;
    render();
  }
}

async function openHistoryScan(scanId) {
  try {
    const res = await callEndpoint('getScan', { scanId, lang: state.lang });
    state.currentScanId = res.scanId;
    state.currentReport = res.report;
    state.activeNav = 'scanner';
    state.activeReportTab = 'overview';
    render();
  } catch (err) {
    showToast(`⚠️ ${err.message}`);
  }
}

async function sendSimMessage(textOverride = null) {
  const text = (textOverride !== null ? textOverride : state.simInput).trim();
  if (!text) return;
  if (textOverride === null) state.simInput = '';
  render();
  await simAction('/sim/message', { text });
  await refreshBootstrap();
  render();
}

async function clickSimInlineButton(btn, msgId) {
  triggerHaptic('light');
  if (btn.copy_text?.text) {
    navigator.clipboard?.writeText(btn.copy_text.text).catch(() => {});
    showToast(`${UI_I18N[state.lang].copiedToast} (${btn.copy_text.text.slice(0, 38)}…)`);
    return;
  }
  if (btn.web_app?.url) {
    try {
      const parsed = new URL(btn.web_app.url, window.location.origin);
      const scanId = Number(parsed.searchParams.get('scan') || 0);
      if (scanId) await openHistoryScan(scanId);
      if (state.viewMode === 'botsim') state.viewMode = 'split';
      render();
    } catch (_) { /* ignore */ }
    return;
  }
  if (btn.url) {
    window.open(btn.url, '_blank', 'noopener,noreferrer');
    return;
  }
  if (btn.callback_data) {
    await simAction('/sim/callback', { message_id: msgId, data: btn.callback_data });
    await refreshBootstrap();
    render();
  }
}

function renderMiniAppPane(s) {
  if (!state.langSelected) {
    const uName = esc(state.user?.firstName || 'Friend');
    return `
      <div class="miniapp-card">
        <div class="lang-gate-box">
          <div style="font-size:44px;margin-bottom:10px;">🛡</div>
          <h2 style="font-size:22px;margin-bottom:12px;">LinkLens — Deep Link Security</h2>
          <div style="display:grid;gap:8px;max-width:480px;margin:0 auto 14px;text-align:start;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:12px;padding:12px 15px;font-size:13.5px;line-height:1.6;">
            <div dir="rtl">🇮🇷 سلام <b>${uName}</b> عزیز! هر لینک یا پیام تلگرامی را بفرستید تا اصالت درگاه شاپرک، فیشینگ و نشت اطلاعات خودکار بررسی شود. لطفاً زبان خود را انتخاب کنید:</div>
            <div dir="ltr">🇬🇧 Welcome, <b>${uName}</b>! Scan any sent or forwarded link across global threat &amp; data-breach databases. Please select your language:</div>
            <div dir="ltr">🇷🇺 Привет, <b>${uName}</b>! Проверяйте любые отправленные и пересланные ссылки на фишинг, вирусы и утечки данных. Выберите язык:</div>
          </div>
          <div class="lang-gate-grid">
            <button class="colored-btn success" data-pick-lang="fa">🇮🇷 فارسی (Persian)</button>
            <button class="colored-btn primary" data-pick-lang="en">🇬🇧 English</button>
            <button class="colored-btn danger" data-pick-lang="ru">🇷🇺 Русский (Russian)</button>
          </div>
        </div>
      </div>
    `;
  }

  return `
    <div class="miniapp-card" dir="${s.dir}">
      <div class="miniapp-topbar">
        <div class="nav-tabs">
          <button class="nav-tab ${state.activeNav === 'scanner' ? 'active' : ''}" data-nav="scanner">🔍 ${esc(s.navScanner)}</button>
          <button class="nav-tab ${state.activeNav === 'history' ? 'active' : ''}" data-nav="history">📜 ${esc(s.navHistory)} (${state.history.length})</button>
          <button class="nav-tab ${state.activeNav === 'engines' ? 'active' : ''}" data-nav="engines">📡 ${esc(s.navEngines)}</button>
          <button class="nav-tab ${state.activeNav === 'about' ? 'active' : ''}" data-nav="about">ℹ️ ${esc(s.navAbout)}</button>
        </div>
        <div style="font-size:12px;color:var(--text-muted);">
          🔍 <b>${state.stats.totalScans}</b> • 🛡 <b>${state.stats.threatsBlocked}</b>
        </div>
      </div>

      ${state.activeNav === 'scanner' ? renderScannerBody(s) : ''}
      ${state.activeNav === 'history' ? renderHistoryBody(s) : ''}
      ${state.activeNav === 'engines' ? renderEnginesConfigBody(s) : ''}
      ${state.activeNav === 'about' ? renderAboutBody(s) : ''}
    </div>
  `;
}

// Dedicated About Us Page — ONLY place displaying owner copyright (`momalekiii.github.io`)!
function renderAboutBody(s) {
  return `
    <div class="detail-panel" style="display:grid;gap:14px;">
      <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:44px;height:44px;border-radius:12px;background:rgba(59,130,246,0.16);border:1px solid rgba(59,130,246,0.38);display:flex;align-items:center;justify-content:center;font-size:22px;">🛡</div>
        <div>
          <h3 style="margin:0;font-size:17px;">${esc(s.aboutHeading)}</h3>
          <div style="font-size:12px;color:var(--text-muted);">${esc(s.appBadge)}</div>
        </div>
      </div>

      <p style="margin:0;font-size:13.5px;line-height:1.7;color:var(--text-main);">
        ${esc(s.aboutIntro)}
      </p>

      <div class="kv-item" style="display:grid;gap:8px;">
        <div style="font-weight:700;font-size:13px;">🔬 ${esc(s.aboutPillarsTitle)}</div>
        ${(s.aboutPillars || []).map((line) => `
          <div style="font-size:12.5px;line-height:1.6;color:#cbd5e1;">• ${esc(line)}</div>
        `).join('')}
      </div>

      <div class="kv-item" style="font-size:12.5px;color:var(--text-muted);line-height:1.6;">
        🔒 ${esc(s.aboutPrivacy)}
      </div>

      <div class="kv-item" style="display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;padding:14px;">
        <div style="font-size:13px;font-weight:600;color:var(--text-main);">
          ${esc(s.aboutCopyrightText)}
        </div>
        <a
          class="colored-btn success"
          href="${ABOUT_WEBSITE_URL}"
          target="_blank"
          rel="noopener noreferrer"
          style="text-decoration:none;font-size:12.5px;padding:8px 14px;"
        >${esc(s.aboutWebsiteBtn)}</a>
      </div>
    </div>
  `;
}

function renderScannerBody(s) {
  const rep = state.currentReport;
  return `
    <form id="scan-form" class="scan-form">
      <input
        id="scan-url-input"
        class="scan-input mono"
        type="text"
        value="${esc(state.urlInput)}"
        placeholder="${esc(s.inputPlaceholder)}"
        autocomplete="off"
      />
      <button type="submit" class="colored-btn primary" ${state.scanning ? 'disabled' : ''}>
        ${state.scanning ? `⏳ ${esc(s.scanningBtn)}` : esc(s.scanBtn)}
      </button>
    </form>

    <div class="options-row">
      <label>
        <input type="checkbox" id="opt-send-chat" ${state.sendToChat ? 'checked' : ''} />
        <span>${esc(s.sendToChatLabel)}</span>
      </label>
      <label>
        <input type="checkbox" id="opt-force" ${state.forceRescan ? 'checked' : ''} />
        <span>${esc(s.forceFreshLabel)}</span>
      </label>
    </div>

    ${rep ? renderVisualReport(rep, s) : `
      <div class="detail-panel" style="text-align:center;padding:30px 18px;color:var(--text-muted);">
        <div style="font-size:32px;margin-bottom:8px;">${state.lang === 'fa' ? '🇮🇷 🛡 🌍' : '🛡 🌍 🔐'}</div>
        <div style="font-size:14.5px;font-weight:700;color:var(--text-main);margin-bottom:6px;">
          ${state.lang === 'fa'
            ? 'آماده بررسی خودکار لینک‌های ارسالی و پیام‌های فورواردشده در منابع ایران و جهان'
            : state.lang === 'ru'
              ? 'Многоуровневый сканер угроз и утечек данных готов к работе'
              : 'Multi-Layer Threat & Data Breach Scanner Ready'}
        </div>
        <div style="font-size:12.5px;max-width:540px;margin:0 auto;line-height:1.7;">
          ${state.lang === 'fa'
            ? '<b>اصالت درگاه شاپرک</b> • <b>مطمئن‌باش (CC-BY-4.0)</b> • <b>لیک‌فا</b> • <b>کاوه</b> • <b>Have I Been Pwned</b> • VirusTotal v3 • Google Safe Browsing • URLScan • Cloudflare DoH • RDAP • SSL'
            : '<b>VirusTotal v3</b> • <b>Google Safe Browsing</b> • <b>Have I Been Pwned</b> • <b>URLScan.io</b> • <b>Cloudflare DoH</b> • <b>IANA RDAP</b> • <b>SSL CT &amp; DOM Forensics</b>'}
        </div>
      </div>
    `}
  `;
}

function renderIranCalloutCard(rep) {
  const ir = rep.iran;
  if (!ir) return '';
  const blocks = [];

  if (state.lang === 'fa' && ir.shaparakStatus === 'VERIFIED_SHAPARAK' && ir.gatewayInfo) {
    const pspName = ir.gatewayInfo.fa || ir.gatewayInfo.en;
    blocks.push(`
      <div style="background:rgba(34,197,94,0.13);border:1px solid rgba(34,197,94,0.45);border-radius:12px;padding:12px 14px;margin-bottom:12px;">
        <div style="font-weight:700;color:#4ade80;font-size:13.5px;margin-bottom:3px;">
          ✅ درگاه پرداخت رسمی و امن شاپرک تایید شد
        </div>
        <div style="font-size:12.5px;color:#e2e8f0;">
          <b>${esc(pspName)}</b> — <code>${esc(rep.hostname)}</code> (HTTPS TLS)
        </div>
      </div>
    `);
  } else if ((state.lang === 'fa' && ir.shaparakStatus === 'FAKE_IRAN_BRAND') || ir.motmaenBashThreat || ir.apkMalwareHit) {
    blocks.push(`
      <div style="background:rgba(239,68,68,0.14);border:1px solid rgba(239,68,68,0.5);border-radius:12px;padding:12px 14px;margin-bottom:12px;">
        <div style="font-weight:700;color:#f87171;font-size:13.5px;margin-bottom:4px;">
          🚨 ${state.lang === 'fa'
            ? 'هشدار فوری فیشینگ / بدافزار سایبری!'
            : state.lang === 'ru'
              ? 'Критическая тревога: фишинг или вредонос!'
              : 'CRITICAL PHISHING / MALWARE ALERT!'}
        </div>
        <div style="font-size:12.5px;color:#fecaca;line-height:1.6;">
          ${ir.motmaenBashThreat ? `• Anti-Phishing Blacklist: <b>${esc(ir.motmaenBashThreat.threatCategory)}</b> (${esc(ir.motmaenBashThreat.matchedValue)})<br/>` : ''}
          ${ir.spoofedIranBrand ? `• Brand Impersonation: <b>${esc(ir.spoofedIranBrand)}</b><br/>` : ''}
          ${ir.apkMalwareHit ? `• Android Malware (${esc(ir.apkMalwareHit.source)}): <b>${esc((ir.apkMalwareHit.detections || []).join(', '))}</b><br/>` : ''}
          ${state.lang === 'fa'
            ? '<b>هرگز شماره کارت، CVV2، رمز دوم پویا یا فایل نصبی (.apk) این صفحه را وارد/نصب نکنید!</b>'
            : '<b>NEVER enter payment/login credentials or install .apk files from this URL!</b>'}
        </div>
      </div>
    `);
  }

  if (ir.hasBreachHistory && ir.breaches?.length) {
    const b = ir.breaches[0];
    const title = state.lang === 'fa' ? (b.nameFa || b.domain) : (b.nameEn || b.domain);
    const desc = b.source === 'Leakfa'
      ? (state.lang === 'fa' ? (b.descriptionFa || b.descriptionEn) : (b.descriptionEn || b.descriptionFa))
      : `${b.nameEn} (${b.breachDate || 'Verified'}) — ${Number(b.pwnCount || 0).toLocaleString('en-US')} accounts (${(b.dataClasses || []).join(', ')})`;

    blocks.push(`
      <div style="background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.45);border-radius:12px;padding:12px 14px;margin-bottom:12px;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;">
          <span style="font-weight:700;color:#fbbf24;font-size:13.5px;">
            🔐 ${state.lang === 'fa'
              ? `سابقه نشت اطلاعات کاربران در ${esc(b.source)}: «${esc(title)}»`
              : state.lang === 'ru'
                ? `Зафиксирована утечка данных (${esc(b.source)}): «${esc(title)}»`
                : `Documented Data Breach (${esc(b.source)}): "${esc(title)}"`}
          </span>
          ${b.companyResponse ? `<code style="font-size:11px;color:#fde68a;">Response: ${esc(b.companyResponse)}</code>` : ''}
        </div>
        <div dir="auto" style="font-size:12.5px;color:#e2e8f0;line-height:1.65;">
          ${esc(desc)}
        </div>
      </div>
    `);
  }

  return blocks.join('');
}

function renderVisualReport(rep, s) {
  const color = verdictColor(rep.verdict);
  const pct = Math.max(4, rep.riskScore);
  const isSafe = rep.verdict === 'SAFE' || rep.verdict === 'LOW_RISK';
  const cats = [
    { label: s.catIntel, val: rep.categories?.threatIntel ?? 80 },
    { label: s.catDomain, val: rep.categories?.domainTrust ?? 80 },
    { label: s.catNetwork, val: Math.min(100, rep.categories?.networkSsl ?? 80) },
    { label: s.catHeaders, val: rep.categories?.httpHardening ?? 60 },
  ];

  return `
    ${renderIranCalloutCard(rep)}

    <div class="report-hero">
      <div class="score-ring" style="background: conic-gradient(${color} ${pct * 3.6}deg, rgba(148,163,184,0.16) 0deg);">
        <div class="score-inner">
          <div class="score-num" style="color:${color};">${rep.riskScore}</div>
          <div class="score-sub">RISK / 100</div>
        </div>
      </div>

      <div>
        <div class="verdict-pill verdict-${esc(rep.verdict)}">
          Grade ${esc(rep.grade)} • ${esc(s[`verdict_${rep.verdict}`] || rep.verdict)}
        </div>
        <div class="mono" style="font-size:13px;font-weight:600;word-break:break-all;margin-bottom:4px;">
          ${esc(rep.finalUrl)}
        </div>
        <div style="font-size:12px;color:var(--text-muted);">
          Domain: <b>${esc(rep.domain)}</b> •
          ${rep.infra?.rdap?.ageDays !== null && rep.infra?.rdap?.ageDays !== undefined ? `Age: <b>${rep.infra.rdap.ageDays}d</b> • ` : ''}
          Layers Checked: <b>${rep.enginesChecked}</b> (Flagged: <b>${rep.enginesFlagged}</b>) •
          ${(rep.durationMs / 1000).toFixed(2)}s
        </div>

        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:12px;">
          ${isSafe
            ? `<a class="colored-btn success" href="${esc(rep.finalUrl)}" target="_blank" rel="noopener noreferrer">${esc(s.openSafeBtn)}</a>`
            : `<button type="button" class="colored-btn danger" data-copy="${esc(rep.defangedUrl)}">${esc(s.copyDefangedBtn)}</button>`
          }
          ${rep.iran?.primaryLeakfaUrl
            ? `<a class="colored-btn danger" href="${esc(rep.iran.primaryLeakfaUrl)}" target="_blank" rel="noopener noreferrer">${esc(s.openLeakfaBtn)}</a>`
            : ''
          }
          <button type="button" class="colored-btn primary" data-copy="${esc(rep.urlHash)}">${esc(s.copyHashBtn)}</button>
          <button type="button" class="colored-btn danger" id="btn-rescan-now">${esc(s.rescanBtn)}</button>
        </div>
      </div>
    </div>

    <div class="cat-grid">
      ${cats.map((c) => {
        const barColor = c.val >= 70 ? '#22c55e' : c.val >= 45 ? '#3b82f6' : '#ef4444';
        return `
          <div class="cat-box">
            <div style="display:flex;justify-content:space-between;font-size:12px;font-weight:600;">
              <span>${esc(c.label)}</span>
              <span style="color:${barColor};">${Math.round(c.val)}%</span>
            </div>
            <div class="cat-bar-track">
              <div class="cat-bar-fill" style="width:${Math.max(5, Math.min(100, c.val))}%;background:${barColor};"></div>
            </div>
          </div>
        `;
      }).join('')}
    </div>

    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px;">
      ${['overview', 'iran', 'engines', 'infra', 'headers'].map((tab) => {
        const labelMap = {
          overview: s.tabOverview,
          iran: s.tabIran,
          engines: s.tabEngines,
          infra: s.tabInfra,
          headers: s.tabHeaders,
        };
        return `<button type="button" class="colored-btn ${state.activeReportTab === tab ? 'success' : 'primary'}" style="padding:8px 13px;font-size:12.5px;" data-rtab="${tab}">${esc(labelMap[tab])}</button>`;
      }).join('')}
    </div>

    <div class="detail-panel">
      ${state.activeReportTab === 'overview' ? renderReportOverviewTab(rep, s) : ''}
      ${state.activeReportTab === 'iran' ? renderReportIranTab(rep) : ''}
      ${state.activeReportTab === 'engines' ? renderReportEnginesTab(rep) : ''}
      ${state.activeReportTab === 'infra' ? renderReportInfraTab(rep) : ''}
      ${state.activeReportTab === 'headers' ? renderReportHeadersTab(rep) : ''}
    </div>
  `;
}

function renderReportOverviewTab(rep, s) {
  const findings = rep.findings || [];
  return `
    <h4 style="margin-bottom:10px;font-size:14px;">⚠️ ${esc(s.findingsTitle)}</h4>
    ${findings.length === 0
      ? `<div style="color:#4ade80;font-size:13.5px;font-weight:600;">✅ ${esc(s.noFindings)}</div>`
      : findings.map((f) => `
          <div class="finding-row ${esc(f.severity)}">
            <span>${f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : 'ℹ️'}</span>
            <div>
              <div dir="auto" style="font-weight:600;">${esc(f.localizedText || f.code)}</div>
              <div class="mono" style="font-size:11px;color:var(--text-muted);">${esc(f.code)} (+${f.weight || 0} risk pts)</div>
            </div>
          </div>
        `).join('')
    }
  `;
}

function renderReportIranTab(rep) {
  const ir = rep.iran || {};
  const st = ir.feedStats || {};
  const breaches = ir.breaches || [];
  const totalApk = (st.motmaenBashApks || 979) + (st.kavehMalware || 539);
  const isFa = state.lang === 'fa';

  const cards = isFa
    ? [
        {
          name: 'تایید اصالت درگاه شاپرک (بانک مرکزی)',
          val: ir.shaparakStatus === 'VERIFIED_SHAPARAK'
            ? `🟢 تاییدشده رسمی: ${ir.gatewayInfo?.fa || ''}`
            : ir.shaparakStatus === 'VERIFIED_FACILITATOR'
              ? `🟦 پرداخت‌یار رسمی: ${ir.gatewayInfo?.fa || ''}`
              : ir.shaparakStatus === 'FAKE_IRAN_BRAND'
                ? `🔴 جعلی / فیشینگ: جعل نام «${ir.spoofedIranBrand}»`
                : '⚪ این صفحه درگاه پرداخت کارت شاپرک نیست',
        },
        {
          name: 'دیتابیس ضد فیشینگ مطمئن‌باش (CC-BY-4.0)',
          val: ir.motmaenBashThreat
            ? `🔴 شناسایی در لیست سیاه: ${ir.motmaenBashThreat.threatCategory}`
            : `🟢 پاک — بررسی در ${st.motmaenBashUrls || 301} آدرس فیشینگ ایرانی`,
        },
        {
          name: 'بدافزارهای بانکی اندروید (مطمئن‌باش + کاوه)',
          val: ir.apkMalwareHit
            ? `🔴 آلوده به بدافزار: ${(ir.apkMalwareHit.detections || []).join(', ')}`
            : `🟢 پاک — بررسی در ${totalApk} امضای تروجان بانکی`,
        },
        {
          name: 'تحلیل فرم سرقت کارت شتاب و ابلاغیه ثنا',
          val: rep.http?.dom?.hasIranCardSkimmer || rep.http?.dom?.hasIranGovApkLure
            ? '🔴 خطر فوری: فرم سرقت کارت / تله ثنا!'
            : '🟢 پاک و بدون فرم مشکوک',
        },
      ]
    : [
        {
          name: 'Anti-Phishing SHA-256 Feed',
          val: ir.motmaenBashThreat
            ? `🔴 MATCHED ${ir.motmaenBashThreat.threatCategory} (${ir.motmaenBashThreat.matchedValue})`
            : `🟢 Clean (${st.motmaenBashUrls || 301} phishing blacklist entries checked)`,
        },
        {
          name: 'APK Malware SHA-256 Signatures',
          val: ir.apkMalwareHit
            ? `🔴 MALWARE: ${(ir.apkMalwareHit.detections || []).join(', ')}`
            : `🟢 Clean (${totalApk} malware SHA-256 hashes checked)`,
        },
        {
          name: 'Payment Skimmer DOM Check',
          val: rep.http?.dom?.hasIranCardSkimmer
            ? '🔴 ACTIVE CARD SKIMMER!'
            : '🟢 Clean',
        },
      ];

  return `
    <div class="kv-grid" style="margin-bottom:14px;">
      ${cards.map((c) => `<div class="kv-item"><div class="kv-label">${esc(c.name)}</div><div class="kv-val" dir="auto">${esc(c.val)}</div></div>`).join('')}
    </div>

    <h4 style="font-size:13.5px;margin-bottom:8px;">
      ${isFa ? '🔐 سوابق نشت اطلاعات (دیتابیس لیک‌فا + Have I Been Pwned)' : '🔐 Data Breach History (Have I Been Pwned + Open Feeds)'}
    </h4>
    ${breaches.length === 0
      ? `<div style="color:#4ade80;font-size:12.5px;margin-bottom:10px;">${isFa
          ? `✅ هیچ سابقه نشت اطلاعاتی در ${st.leakfaDomains || 101} سامانه ایرانی لیک‌فا و ${st.hibpBreaches || 981} سرویس جهانی HIBP ثبت نشده است.`
          : `✅ Clean across ${st.hibpBreaches || 981} verified Have I Been Pwned global breach records.`}</div>`
      : `<div style="display:grid;gap:8px;margin-bottom:10px;">
          ${breaches.map((b) => `
            <div class="kv-item">
              <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:4px;">
                <b style="color:#fbbf24;">[${esc(b.source)}] ${esc(isFa ? (b.nameFa || b.nameEn) : (b.nameEn || b.nameFa))}</b>
                ${b.relatedUrl ? `<a href="${esc(b.relatedUrl)}" target="_blank" rel="noopener noreferrer" style="color:#60a5fa;font-size:12px;">${isFa ? 'مشاهده در لیک‌فا ↗' : 'Incident Report ↗'}</a>` : `<span class="mono" style="font-size:11px;color:var(--text-muted);">${esc(b.breachDate || '')}</span>`}
              </div>
              <div dir="auto" style="font-size:12.5px;line-height:1.6;color:#e2e8f0;">
                ${b.source === 'Leakfa'
                  ? esc(isFa ? (b.descriptionFa || b.descriptionEn) : (b.descriptionEn || b.descriptionFa))
                  : `${Number(b.pwnCount || 0).toLocaleString('en-US')} exposed records — Classes: ${esc((b.dataClasses || []).join(', '))}`
                }
              </div>
            </div>
          `).join('')}
        </div>`
    }
    <div style="font-size:11px;color:var(--text-muted);">
      📚 Attribution: <code>miladnouri/motmaenbash-data</code> (CC-BY-4.0) • <code>Nooshdaroo-Code/Kaveh</code> • <code>Leakfarsi/Leakfa-Alert</code> (MIT) • <code>haveibeenpwned.com</code>
    </div>
  `;
}

function renderReportEnginesTab(rep) {
  const e = rep.engines || {};
  const cards = [
    { name: 'VirusTotal API v3', val: e.virustotal?.status === 'ok' ? `${e.virustotal.malicious} malicious / ${e.virustotal.totalEngines} engines` : (e.virustotal?.note || e.virustotal?.status) },
    { name: 'Google Safe Browsing v4', val: e.safeBrowsing?.status === 'ok' ? (e.safeBrowsing.flagged ? `FLAGGED: ${e.safeBrowsing.threats.join(', ')}` : 'Clean (0 threats)') : (e.safeBrowsing?.note || e.safeBrowsing?.status) },
    { name: 'URLScan.io Sandbox', val: e.urlscan?.status === 'ok' ? `${e.urlscan.maliciousScans} malicious hits (${e.urlscan.mode})` : 'Unavailable' },
    { name: 'IPQualityScore AI', val: e.ipqs?.status === 'ok' ? `Risk ${e.ipqs.riskScore}/100` : (e.ipqs?.note || 'Standby') },
    { name: 'AbuseIPDB v2', val: e.abuseIpDb?.status === 'ok' ? `${e.abuseIpDb.abuseConfidenceScore}% confidence (${e.abuseIpDb.totalReports} reports)` : (e.abuseIpDb?.note || 'Standby') },
    { name: 'SHA-256 URL Hash', val: rep.urlHash },
  ];
  return `<div class="kv-grid">${cards.map((c) => `<div class="kv-item"><div class="kv-label">${esc(c.name)}</div><div class="kv-val mono">${esc(c.val)}</div></div>`).join('')}</div>`;
}

function renderReportInfraTab(rep) {
  const inf = rep.infra || {};
  const dns = inf.dns || {};
  const rdap = inf.rdap || {};
  const geo = inf.geo || {};
  const ssl = inf.ssl || {};
  const defaultRegistrar = state.lang === 'fa' ? 'محافظت‌شده / ایرنیک' : 'Registry Protected';
  const cards = [
    { name: 'Registrar (IANA RDAP)', val: rdap.registrar || defaultRegistrar },
    { name: 'Created / Expires', val: `${rdap.createdDate || '—'} → ${rdap.expiresDate || '—'} ${rdap.ageDays !== null && rdap.ageDays !== undefined ? `(${rdap.ageDays} days)` : ''}` },
    { name: 'Server IPv4 / ASN', val: `${inf.ip || '—'} ${geo.flag || ''} ${geo.country || ''} ${geo.asn || ''} ${geo.org || ''}`.trim() },
    { name: 'Nameservers (NS)', val: (dns.nsRecords || []).join(', ') || '—' },
    { name: 'Email Security (SPF / DMARC / CAA)', val: `SPF: ${dns.hasSpf ? 'YES' : 'NO'} | DMARC: ${dns.hasDmarc ? 'YES' : 'NO'} | CAA: ${dns.hasCaa ? 'YES' : 'NO'}` },
    { name: 'SSL Certificate & CT Logs', val: `${ssl.issuer || 'Standard TLS'} (${ssl.certsFound || 0} CT certs)` },
  ];
  return `<div class="kv-grid">${cards.map((c) => `<div class="kv-item"><div class="kv-label">${esc(c.name)}</div><div class="kv-val">${esc(c.val)}</div></div>`).join('')}</div>`;
}

function renderReportHeadersTab(rep) {
  const h = rep.http || {};
  const dom = h.dom || {};
  return `
    <div class="kv-grid" style="margin-bottom:12px;">
      <div class="kv-item"><div class="kv-label">HTTP Status &amp; Latency</div><div class="kv-val">${h.reachable ? `${h.httpStatus} (${h.latencyMs}ms)` : 'Unreachable'}</div></div>
      <div class="kv-item"><div class="kv-label">OWASP Header Grade</div><div class="kv-val">${esc(h.headerGrade)} (${h.headerScore}/100)</div></div>
      <div class="kv-item"><div class="kv-label">Page Title</div><div class="kv-val" dir="auto">${esc(dom.title || '—')}</div></div>
      <div class="kv-item"><div class="kv-label">DOM Threat Forensics</div><div class="kv-val">${state.lang === 'fa' ? 'فرم کارت شتاب' : 'Card Skimmer'}: ${dom.hasIranCardSkimmer ? 'ALERT' : 'Clean'} • Password Form: ${dom.hasPasswordInput ? 'Yes' : 'No'} • ClickFix: ${dom.hasClickFixTrap ? 'ALERT' : 'Clean'}</div></div>
    </div>
    <div style="font-size:12.5px;">
      <b>Present Headers:</b> ${(h.presentHeaders || []).map((x) => `<code style="margin:2px;">✅ ${esc(x.name)}</code>`).join(' ') || 'None'}
      <br/><br/>
      <b>Missing Headers:</b> ${(h.missingHeaders || []).map((x) => `<code style="margin:2px;">❌ ${esc(x)}</code>`).join(' ') || 'None!'}
    </div>
  `;
}

function renderHistoryBody(s) {
  if (!state.history.length) {
    return `<div class="detail-panel" style="text-align:center;color:var(--text-muted);">${esc(s.historyEmpty)}</div>`;
  }
  return `
    <div style="display:flex;flex-direction:column;gap:8px;margin-bottom:14px;">
      ${state.history.map((item) => {
        const danger = item.verdict === 'MALICIOUS' || item.verdict === 'SUSPICIOUS';
        return `
          <div class="kv-item" style="display:flex;justify-content:space-between;align-items:center;gap:10px;">
            <div>
              <div style="font-weight:700;font-size:13.5px;">${esc(item.domain)} <span class="mono" style="font-size:11.5px;color:var(--text-muted);">[${item.riskScore}/100 • ${esc(item.grade)}]</span></div>
              <div class="mono" style="font-size:11.5px;color:var(--text-muted);">${esc(item.inputUrl.slice(0, 70))}</div>
            </div>
            <button type="button" class="colored-btn ${danger ? 'danger' : 'success'}" style="padding:7px 12px;font-size:12px;" data-open-scan="${item.id}">
              Open →
            </button>
          </div>
        `;
      }).join('')}
    </div>
    <button type="button" class="colored-btn danger" id="btn-clear-hist">${esc(s.clearHistoryBtn)}</button>
  `;
}

function renderEnginesConfigBody(s) {
  const activeWord = state.lang === 'fa' ? 'فعال' : state.lang === 'ru' ? 'Активен' : 'Active';
  const standbyWord = state.lang === 'fa' ? 'آماده‌به‌کار' : state.lang === 'ru' ? 'Ожидание' : 'Standby';
  return `
    <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:8px;">
      <h3 style="font-size:16px;margin:0;">📡 ${esc(s.keysHeading)}</h3>
    </div>
    <p style="font-size:12.5px;color:var(--text-muted);margin-bottom:14px;">${esc(s.keysSub)}</p>

    <div style="display:grid;gap:10px;margin-bottom:8px;">
      ${state.engines.map((eng) => `
        <div class="kv-item" style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <div>
            <div style="font-weight:700;font-size:13px;">${eng.configured ? '🟢' : '⚪'} ${esc(eng.name)}</div>
            <div class="mono" style="font-size:11px;color:var(--text-muted);">${esc(eng.tier === 'live_api' ? (eng.masked || activeWord) : (eng.configured ? activeWord : standbyWord))}</div>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function renderBotSimulatorPane(s) {
  const drafts = Object.values(state.simDrafts);
  return `
    <div class="tg-sim-shell">
      <div class="tg-sim-header">
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="tg-bot-avatar">🛡</div>
          <div>
            <div style="font-weight:700;font-size:14px;">LinkLens Bot <span style="font-size:11px;color:#60a5fa;">bot</span></div>
            <div style="font-size:11px;color:#94a3b8;">${esc(s.simHeaderSub)}</div>
          </div>
        </div>
        <button type="button" class="sim-chip" id="btn-sim-reset" title="Simulate brand-new Telegram user">
          ${esc(s.simResetBtn)}
        </button>
      </div>

      <div class="tg-sim-messages" id="tg-sim-scroll">
        ${state.simMessages.map((m) => {
          const isBot = Boolean(m.from?.is_bot);
          const kbRows = m.reply_markup?.inline_keyboard || [];
          return `
            <div class="tg-msg-row ${isBot ? 'bot' : 'user'}">
              <div class="tg-bubble" dir="auto">${isBot ? m.text : esc(m.text)}</div>
              ${kbRows.length ? `
                <div class="tg-inline-kb">
                  ${kbRows.map((row, rIdx) => `
                    <div class="tg-kb-row">
                      ${row.map((b, bIdx) => `
                        <button
                          type="button"
                          class="tg-kb-btn ${b.style ? `style-${esc(b.style)}` : ''}"
                          data-msg-id="${m.message_id}"
                          data-r="${rIdx}"
                          data-b="${bIdx}"
                        >${esc(b.text)}</button>
                      `).join('')}
                    </div>
                  `).join('')}
                </div>
              ` : ''}
            </div>
          `;
        }).join('')}

        ${drafts.map((d) => `
          <div class="tg-msg-row bot">
            <div class="tg-draft-bubble">
              <div dir="auto">${d.text}</div>
              <div class="tg-draft-footer">
                <span>⚡ Live stream</span>
                ${d.can_stop ? `<button type="button" class="colored-btn danger" style="padding:4px 10px;font-size:11px;" data-stop-draft="${d.draft_id}">⏹ Stop</button>` : ''}
              </div>
            </div>
          </div>
        `).join('')}
      </div>

      <div class="tg-sim-quickbar">
        <button type="button" class="sim-chip" data-sim-send="/start">${esc(s.simCmdStart)}</button>
        <button type="button" class="sim-chip" data-sim-send="/lang">${esc(s.simCmdLang)}</button>
        <button type="button" class="sim-chip" data-sim-send="/status">/status</button>
        <button type="button" class="sim-chip" data-sim-send="/history">${esc(s.simCmdHistory)}</button>
        <button type="button" class="sim-chip" data-sim-send="/about">${esc(s.simCmdAbout)}</button>
      </div>

      <form id="sim-chat-form" class="tg-sim-composer">
        <input
          id="sim-chat-input"
          type="text"
          value="${esc(state.simInput)}"
          placeholder="${esc(s.simPlaceholder)}"
          autocomplete="off"
        />
        <button type="submit" class="colored-btn primary" style="padding:9px 15px;">${esc(s.simSend)}</button>
      </form>
    </div>
  `;
}

function render() {
  const s = UI_I18N[state.lang] || UI_I18N.en;
  const root = document.getElementById('app');

  const studioBarHtml = state.inTelegramClient ? '' : `
    <header class="studio-bar">
      <div class="brand-cluster">
        <div class="brand-logo">🛡</div>
        <div>
          <div class="brand-title">${esc(s.appTitle)}</div>
          <div class="brand-sub">${esc(s.appBadge)}</div>
        </div>
      </div>

      <div class="mode-pills">
        <button class="mode-pill ${state.viewMode === 'split' ? 'active' : ''}" data-mode="split">${esc(s.modeSplit)}</button>
        <button class="mode-pill ${state.viewMode === 'botsim' ? 'active' : ''}" data-mode="botsim">${esc(s.modeBotSim)}</button>
        <button class="mode-pill ${state.viewMode === 'miniapp' ? 'active' : ''}" data-mode="miniapp">${esc(s.modeMiniApp)}</button>
      </div>

      <div class="lang-quick-switch">
        <button class="lang-chip ${state.langSelected && state.lang === 'fa' ? 'active-fa' : ''}" data-pick-lang="fa">🇮🇷 فارسی</button>
        <button class="lang-chip ${state.langSelected && state.lang === 'en' ? 'active-en' : ''}" data-pick-lang="en">🇬🇧 EN</button>
        <button class="lang-chip ${state.langSelected && state.lang === 'ru' ? 'active-ru' : ''}" data-pick-lang="ru">🇷🇺 RU</button>
      </div>
    </header>
  `;

  const showSim = !state.inTelegramClient && (state.viewMode === 'split' || state.viewMode === 'botsim');
  const showMini = state.inTelegramClient || state.viewMode === 'split' || state.viewMode === 'miniapp';

  root.innerHTML = `
    ${studioBarHtml}
    <main class="workspace ${state.viewMode === 'split' && !state.inTelegramClient ? 'layout-split' : 'layout-single'}">
      ${showSim ? renderBotSimulatorPane(s) : ''}
      ${showMini ? renderMiniAppPane(s) : ''}
    </main>
    ${state.toast ? `<div class="toast-banner">${esc(state.toast)}</div>` : ''}
  `;

  bindEvents();
  const scroller = document.getElementById('tg-sim-scroll');
  if (scroller) scroller.scrollTop = scroller.scrollHeight;
}

function bindEvents() {
  document.querySelectorAll('[data-mode]').forEach((el) => {
    el.onclick = () => { state.viewMode = el.dataset.mode; render(); };
  });

  document.querySelectorAll('[data-pick-lang]').forEach((el) => {
    el.onclick = () => handleSelectLanguage(el.dataset.pickLang);
  });

  document.querySelectorAll('[data-nav]').forEach((el) => {
    el.onclick = () => { state.activeNav = el.dataset.nav; render(); };
  });

  document.querySelectorAll('[data-rtab]').forEach((el) => {
    el.onclick = () => { state.activeReportTab = el.dataset.rtab; render(); };
  });

  document.querySelectorAll('[data-copy]').forEach((el) => {
    el.onclick = () => {
      navigator.clipboard?.writeText(el.dataset.copy).catch(() => {});
      showToast(UI_I18N[state.lang].copiedToast);
    };
  });

  document.querySelectorAll('[data-open-scan]').forEach((el) => {
    el.onclick = () => openHistoryScan(Number(el.dataset.openScan));
  });

  const scanForm = document.getElementById('scan-form');
  if (scanForm) {
    const inp = document.getElementById('scan-url-input');
    inp.oninput = (e) => { state.urlInput = e.target.value; };
    scanForm.onsubmit = (e) => { e.preventDefault(); handleScan(); };
  }

  const optChat = document.getElementById('opt-send-chat');
  if (optChat) optChat.onchange = (e) => { state.sendToChat = e.target.checked; };

  const optForce = document.getElementById('opt-force');
  if (optForce) optForce.onchange = (e) => { state.forceRescan = e.target.checked; };

  const rescanBtn = document.getElementById('btn-rescan-now');
  if (rescanBtn && state.currentReport) {
    rescanBtn.onclick = () => handleScan(state.currentReport.inputUrl, true);
  }

  const clearBtn = document.getElementById('btn-clear-hist');
  if (clearBtn) {
    clearBtn.onclick = async () => {
      await callEndpoint('getHistory', { action: 'clear' });
      await refreshBootstrap();
      render();
    };
  }

  // Bot Simulator Bindings (active only in Studio Preview)
  const simForm = document.getElementById('sim-chat-form');
  if (simForm) {
    const simInp = document.getElementById('sim-chat-input');
    simInp.oninput = (e) => { state.simInput = e.target.value; };
    simForm.onsubmit = (e) => { e.preventDefault(); sendSimMessage(); };
  }

  document.querySelectorAll('[data-sim-send]').forEach((el) => {
    el.onclick = () => sendSimMessage(el.dataset.simSend);
  });

  const resetBtn = document.getElementById('btn-sim-reset');
  if (resetBtn) {
    resetBtn.onclick = async () => {
      const snap = await simAction('/sim/reset', {});
      state.simMessages = snap.messages || [];
      state.simDrafts = {};
      await refreshBootstrap();
      render();
    };
  }

  document.querySelectorAll('[data-stop-draft]').forEach((el) => {
    el.onclick = async () => {
      await simAction('/sim/stop-draft', { draft_id: Number(el.dataset.stopDraft) });
    };
  } );

  document.querySelectorAll('.tg-kb-btn').forEach((el) => {
    el.onclick = () => {
      const msg = state.simMessages.find((m) => m.message_id === Number(el.dataset.msgId));
      const btn = msg?.reply_markup?.inline_keyboard?.[Number(el.dataset.r)]?.[Number(el.dataset.b)];
      if (btn) clickSimInlineButton(btn, msg.message_id);
    };
  });
}

async function init() {
  try {
    window.Telegram?.WebApp?.ready?.();
    window.Telegram?.WebApp?.expand?.();
  } catch (_) { /* ignore */ }

  await refreshBootstrap();

  // Check URL query params (`?scan=12&lang=fa` or `?tab=about`) when opened via Telegram Mini App button
  const params = new URLSearchParams(window.location.search);
  if (params.get('lang') && ['fa', 'en', 'ru'].includes(params.get('lang'))) {
    state.lang = params.get('lang');
  }
  if (params.get('tab') === 'about') {
    state.activeNav = 'about';
  }
  if (params.get('scan')) {
    await openHistoryScan(Number(params.get('scan')));
  }

  if (!state.inTelegramClient) {
    const snap = await simAction('/sim/state', {});
    state.simMessages = snap.messages || [];

    // Live SSE Stream for real-time in-place message edits & bot messages!
    const es = new EventSource('/sim/events');
    es.onmessage = (ev) => {
      try {
        const payload = JSON.parse(ev.data);
        if (payload.type === 'draft') {
          if (payload.draft.cleared) {
            delete state.simDrafts[payload.draft.key];
          } else {
            state.simDrafts[payload.draft.key] = payload.draft;
          }
          render();
        } else if (payload.type === 'message') {
          state.simDrafts = {};
          const idx = state.simMessages.findIndex((m) => m.message_id === payload.message.message_id);
          if (idx === -1) state.simMessages.push(payload.message);
          render();
        } else if (payload.type === 'edit') {
          const idx = state.simMessages.findIndex((m) => m.message_id === payload.message.message_id);
          if (idx !== -1) state.simMessages[idx] = payload.message;
          render();
        } else if (payload.type === 'delete') {
          state.simMessages = state.simMessages.filter((m) => m.message_id !== Number(payload.message_id));
          render();
        } else if (payload.type === 'toast' && payload.toast?.text) {
          showToast(payload.toast.text);
        }
      } catch (_) { /* ignore */ }
    };
  }

  state.loadingBoot = false;
  render();
}

init();
