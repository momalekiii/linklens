import { t, escapeHtml, formatFinding } from './i18n.js';

// ============================================================================
// LinkLens Report Renderer — machine-console output (FA / EN / RU)
// Design rules:
//   · no emoji, no exclamation marks, no decorative noise
//   · fixed-width metric grid for EN/RU, label — value lines for RTL (fa)
//   · severity reported as uppercase words (CRITICAL / HIGH / MED / INFO)
//   · owner copyright appears only in `renderAboutMessage`
// ============================================================================

const RULE = '──────────────';

// Persian readers expect Persian numerals in prose/metrics.
const FA_DIGITS = ['۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹'];
const toFa = (value) => String(value).replace(/[0-9]/g, (d) => FA_DIGITS[Number(d)]);
const num = (lang, value) => (lang === 'fa' ? toFa(value) : String(value));
const BAR_ON = '■';
const BAR_OFF = '□';

function severityTag(s, severity) {
  switch (severity) {
    case 'critical': return s.sevCritical;
    case 'high': return s.sevHigh;
    case 'medium': return s.sevMedium;
    case 'low': return s.sevLow;
    default: return s.sevInfo;
  }
}

function clip(value, max = 26) {
  const str = String(value ?? '');
  return str.length > max ? `${str.slice(0, max - 1)}…` : str;
}

function riskBar(score) {
  const filled = Math.max(0, Math.min(10, Math.round(Number(score || 0) / 10)));
  return `${BAR_ON.repeat(filled)}${BAR_OFF.repeat(10 - filled)}`;
}

// Fixed-width `<pre>` grid keeps every value aligned like a terminal readout.
function metricGrid(rows, lang) {
  if (lang === 'fa') {
    // RTL: a monospace grid would scramble the reading order
    return rows.map(([label, value]) => `${label} — ${value}`);
  }
  const width = rows.reduce((w, [label]) => Math.max(w, label.length), 0);
  const lines = rows.map(([label, value]) => `${label.padEnd(width)}  ${value}`);
  return [`<pre>${lines.join('\n')}</pre>`];
}

function verdictOf(report, s) {
  if (report.limited && report.verdict !== 'MALICIOUS' && report.verdict !== 'SUSPICIOUS') return s.limitedVerdict;
  return s[`verdict_${report.verdict}`] || report.verdict;
}

function headline(report, s, lang) {
  if (report.limited && !report.enginesChecked) return [`<b>LINKLENS</b> · <b>${escapeHtml(s.limitedVerdict)}</b>`, escapeHtml(s.noExternalChecks)];
  const cached = report.cached ? ` · ${s.lblCached}` : '';
  return [
    `<b>LINKLENS</b> · <b>${escapeHtml(verdictOf(report, s))}</b>`,
    `${s.lblRiskScore} <code>${riskBar(report.riskScore)}</code> ${num(lang, report.riskScore)}/${num(lang, 100)} · ${s.lblGrade} <b>${escapeHtml(report.grade)}</b>${cached}`,
  ];
}

export function renderHomeMessage(lang = 'en') {
  const s = t(lang);
  return [
    s.homeTitle,
    RULE,
    s.homeSubtitle,
    '',
    s.homeChecksHeader,
    ...s.homeChecksList.map((line) => `· ${line}`),
    '',
    `<i>${s.homeTip}</i>`,
  ].join('\n');
}

export function renderAboutMessage(lang = 'en') {
  const s = t(lang);
  return [s.aboutTitle, RULE, ...(s.aboutBody || [])].join('\n');
}

export function renderDraftProgressMessage(stageNum, rawUrl, lang = 'en', extraHeader = '') {
  const s = t(lang);
  const stage = Math.min(4, Math.max(0, Number(stageNum) || 0));
  const bar = `${BAR_ON.repeat(stage)}${BAR_OFF.repeat(4 - stage)}`;
  const host = String(rawUrl || '').replace(/^https?:\/\//i, '').split('/')[0];

  return [
    extraHeader,
    s.streamHeader,
    `<code>${bar}</code> ${stage}/4`,
    `<code>${escapeHtml(clip(host, 40))}</code>`,
    '',
    `▸ ${s[`stage${stage}`] || s.stage1}`,
  ].filter(Boolean).join('\n');
}

export function buildPlainClipboardSummary(report, lang = 'en') {
  const s = t(lang);
  const verdict = verdictOf(report, s);
  const breach = report.iran?.hasBreachHistory ? ' | breach: yes' : '';
  return `LinkLens · ${verdict} · risk ${report.riskScore}/100 · grade ${report.grade} · ${report.domain}${breach} · ${report.defangedUrl}`;
}

function alertLines(report, s, lang) {
  const ir = report.iran || {};
  const out = [];

  // Payment-gateway verification is Iran-specific and shown ONLY in Farsi
  if (lang === 'fa') {
    if (ir.shaparakStatus === 'VERIFIED_SHAPARAK' && ir.gatewayInfo) {
      out.push(s.bannerShaparakVerified.replace('{psp}', escapeHtml(ir.gatewayInfo.fa || ir.gatewayInfo.en)));
    } else if (ir.shaparakStatus === 'VERIFIED_FACILITATOR' && ir.gatewayInfo) {
      out.push(s.bannerFacilitator.replace('{psp}', escapeHtml(ir.gatewayInfo.fa || ir.gatewayInfo.en)));
    } else if (ir.shaparakStatus === 'FAKE_IRAN_BRAND' && ir.spoofedIranBrand) {
      out.push(s.bannerFakeIranGateway.replace('{brand}', escapeHtml(ir.spoofedIranBrand)));
    }
  }

  if (ir.motmaenBashThreat) {
    out.push(
      s.bannerMotmaenBashHit
        .replace('{cat}', escapeHtml(ir.motmaenBashThreat.threatCategory))
        .replace('{target}', escapeHtml(ir.motmaenBashThreat.matchedValue))
    );
  }

  if (ir.hasBreachHistory && ir.breaches?.length) {
    const primary = ir.breaches[0];
    const site = lang === 'fa'
      ? (primary.nameFa || primary.domain)
      : (primary.nameEn || primary.domain);
    out.push(s.bannerLeakfaBreach.replace('{site}', escapeHtml(site)));
  }

  return out;
}

export function renderScanReportHtml(report, activeTab = 'overview', lang = 'en', siblingScans = null) {
  const s = t(lang);
  const head = [];
  if (report.limited) head.push(escapeHtml(s.limitedNotice), RULE);

  if (Array.isArray(siblingScans) && siblingScans.length > 1) {
    head.push(
      s.multiLinkSummaryHeader.replace('{count}', String(siblingScans.length)),
      ...siblingScans.map((item) => {
        const marker = Number(item.scanId) === Number(report._scanId) ? '▸' : '·';
        const tag = item.verdict === 'MALICIOUS' ? s.tagDanger
          : item.verdict === 'SUSPICIOUS' ? s.tagCaution
            : item.verdict === 'LOW_RISK' ? s.tagHygiene
              : s.limitedVerdict;
        return `${marker} <code>${escapeHtml(clip(item.domain, 28))}</code> ${tag} ${num(lang, item.riskScore)}/${num(lang, 100)}`;
      }),
      RULE
    );
  }

  head.push(...headline(report, s, lang));

  if (report.spoofAlert) {
    head.push(
      '',
      s.lblSpoofWarning
        .replace('{shown}', escapeHtml(clip(report.spoofAlert.shown, 40)))
        .replace('{actual}', escapeHtml(clip(report.spoofAlert.actual, 40)))
    );
  }

  head.push(RULE);

  if (activeTab === 'iran') return [...head, ...breachTab(report, s, lang)].join('\n');
  if (activeTab === 'engines') return [...head, ...sourceResultLines(report, lang), ...enginesTab(report, s)].join('\n');
  if (activeTab === 'infra') return [...head, ...infraTab(report, s)].join('\n');
  if (activeTab === 'headers') return [...head, ...headersTab(report, s, lang)].join('\n');

  return [...head, ...overviewTab(report, s, lang)].join('\n');
}

function overviewTab(report, s, lang) {
  const inf = report.infra || {};
  const ageDays = inf.rdap?.ageDays;
  const ageValue = ageDays !== null && ageDays !== undefined
    ? `${s.daysOld.replace('{days}', num(lang, ageDays))}${inf.rdap?.registrar ? ` · ${clip(inf.rdap.registrar, 22)}` : ''}`
    : s.unknown;

  const hostValue = inf.ip
    ? (lang === 'fa'
      ? `${inf.ip}${inf.geo?.asn ? ` · ${inf.geo.asn}` : ''}`
      : `${inf.ip}${inf.geo?.country ? ` · ${inf.geo.country}` : ''}`)
    : s.unknown;

  const tlsValue = !report.http?.reachable ? s.unknown : report.http?.httpsEnforced
    ? `HTTPS${inf.ssl?.issuer ? ` · ${clip(inf.ssl.issuer, 16)}` : ''}`
    : (s.tlsNone || 'none · plain HTTP');

  const rows = [
    [s.lblInputUrl, clip(report.inputUrl, 30)],
    [s.lblFinalUrl, report.http?.reachable ? clip(report.finalUrl, 30) : s.unknown],
    [s.lblDomainAge, clip(ageValue, 32)],
    [s.lblServerIp, clip(hostValue, 28)],
    [s.lblSslStatus, tlsValue],
    [s.lblHeadersGrade, report.http?.reachable ? `${report.http?.headerGrade || '—'} · ${num(lang, report.http?.headerScore ?? 0)}/${num(lang, 100)}` : s.unknown],
    [s.lblEngines, `${num(lang, report.enginesChecked ?? 0)} ${s.lblStatusActive} · ${num(lang, report.enginesFlagged ?? 0)} ${s.lblFlagged || 'flagged'}`],
    [s.lblScanTime, `${num(lang, ((report.durationMs || 0) / 1000).toFixed(2))}${s.secShort || 's'}`],
  ];

  const alerts = alertLines(report, s, lang);
  const body = [];

  if (alerts.length) body.push(...alerts, '');

  body.push(...metricGrid(rows, lang), '', `<b>${s.lblFindings}</b>`);

  if (!report.findings || report.findings.length === 0) {
    body.push(report.limited ? s.noExternalChecks : s.lblNoFindings);
  } else {
    const lines = report.findings
      .slice(0, 7)
      .map((f) => `${severityTag(s, f.severity)} · ${formatFinding(f, lang)}`)
      .join('\n');
    body.push(`<blockquote expandable>${lines}</blockquote>`);
  }

  return body;
}

function breachTab(report, s, lang) {
  const ir = report.iran || {};
  const stats = ir.feedStats || {};
  const apkTotal = (stats.motmaenBashApks || 979) + (stats.kavehMalware || 539);
  const fa = lang === 'fa';

  const phishing = ir.motmaenBashThreat
    ? (fa
      ? `${s.wordThreat} · ${escapeHtml(ir.motmaenBashThreat.threatCategory)}`
      : `${s.wordThreat} · ${escapeHtml(ir.motmaenBashThreat.threatCategory)}`)
    : ir.motmaenBashTrusted
      ? (fa ? `در فهرست سفید` : 'WHITELIST · trusted entry')
      : (fa
        ? `CLEAN · ${stats.motmaenBashUrls || 301} ورودی سیاه‌لیست`
        : `CLEAN · ${stats.motmaenBashUrls || 301} blacklist entries`);

  const apk = ir.apkMalwareHit
    ? `${s.wordThreat} · ${escapeHtml((ir.apkMalwareHit.detections || []).join(', '))}`
    : (fa
      ? `CLEAN · ${apkTotal} امضای بدافزار اندروید`
      : `CLEAN · ${apkTotal} android malware hashes`);

  const skimmer = report.http?.dom?.hasIranCardSkimmer
    ? (fa ? `${s.wordThreat} · فرم سرقت کارت` : `${s.wordThreat} · card skimmer form`)
    : (fa ? 'CLEAN · فرم جعلی یافت نشد' : 'CLEAN · no skimmer form');

  const gateway = ir.shaparakStatus === 'VERIFIED_SHAPARAK'
    ? (fa ? `${s.wordVerified} · ${escapeHtml(ir.gatewayInfo?.fa || '')}` : `${s.wordVerified} · official gateway`)
    : ir.shaparakStatus === 'VERIFIED_FACILITATOR'
      ? (fa ? `${s.wordLicensed} · ${escapeHtml(ir.gatewayInfo?.fa || '')}` : `${s.wordLicensed} · payment facilitator`)
      : ir.shaparakStatus === 'FAKE_IRAN_BRAND'
        ? (fa ? `THREAT · جعل نام ${escapeHtml(ir.spoofedIranBrand || '')}` : 'THREAT · brand impersonation')
        : ir.shaparakStatus === 'INSECURE_HTTP_SHAPARAK'
          ? (fa ? 'THREAT · بدون HTTPS' : 'THREAT · no HTTPS')
          : (fa ? 'NOT A GATEWAY · درگاه بانکی نیست' : 'NOT A GATEWAY');

  const lines = [
    `<b>${fa ? 'ایران — شاپرک، مطمئن‌باش، کاوه' : 'iran — shaparak, motmaenbash, kaveh'}</b>`,
    '',
  ];

  if (fa) {
    lines.push(...metricGrid([
      ['درگاه', gateway],
      ['فیشینگ', phishing],
      ['بدافزار', apk],
      ['اسکیمر', skimmer],
    ], lang));
  } else {
    lines.push(...metricGrid([
      ['GATEWAY', gateway],
      ['PHISHING', phishing],
      ['MALWARE', apk],
      ['SKIMMER', skimmer],
    ], lang));
  }

  lines.push('', `<b>${fa ? 'سابقه نشت داده — Have I Been Pwned' : 'breach history — Have I Been Pwned'}</b>`);

  if (!ir.breaches || ir.breaches.length === 0) {
    if (!ir.sources?.leakfa?.entries || !ir.sources?.hibp?.entries) lines.push(s.noExternalChecks);
    else lines.push(fa
      ? `NO MATCH · هیچ سابقه‌ای در ${stats.leakfaDomains || 0} سامانه ایرانی و ${stats.hibpBreaches || 0} نشت جهانی ثبت نشده`
      : `NO MATCH · none across ${stats.leakfaDomains || 0} regional and ${stats.hibpBreaches || 0} global breaches`);
  } else {
    for (const b of ir.breaches) {
      if (b.source === 'Leakfa') {
        const title = fa ? (b.nameFa || b.domain) : (b.nameEn || b.nameFa || b.domain);
        const desc = fa ? (b.descriptionFa || b.descriptionEn) : (b.descriptionEn || b.descriptionFa);
        lines.push(
          `LEAKFA  ${escapeHtml(title)} · ${escapeHtml(b.companyResponse || '—')}`,
          `<blockquote>${escapeHtml(clip(desc, 180))}</blockquote>`
        );
      } else {
        lines.push(
          `HIBP    ${escapeHtml(b.nameEn)} · ${escapeHtml(b.breachDate || '—')} · ${Number(b.pwnCount || 0).toLocaleString('en-US')} records`
        );
      }
    }
  }

  lines.push('', `<i>datasets: MotmaenBash (CC-BY-4.0) · Nooshdaroo Kaveh · Leakfa-Alert (MIT) · HIBP v3</i>`);
  return lines;
}

function enginesTab(report, s) {
  const e = report.engines || {};
  const vt = e.virustotal || {};
  const gsb = e.safeBrowsing || {};
  const us = e.urlscan || {};
  const abuse = e.abuseIpDb || {};
  const ipqs = e.ipqs || {};

  const standby = `— ${s.lblStatusStandby}`;

  const vtLine = vt.status === 'ok'
    ? `${vt.flagged ? 'THREAT' : 'CLEAN'} · ${vt.malicious} malicious / ${vt.suspicious} suspicious · ${vt.totalEngines} vendors`
    : vt.status === 'queued' ? 'QUEUED · re-scan in ~15s' : standby;

  const gsbLine = gsb.status === 'ok'
    ? (gsb.flagged ? `THREAT · ${escapeHtml((gsb.threats || []).join(', '))}` : 'CLEAN · 0 matches')
    : standby;

  const usLine = us.status === 'ok'
    ? `${us.flagged ? `THREAT · ${us.maliciousScans} sandbox hits` : 'CLEAN · no flagged scans'}`
    : standby;

  const ipqsLine = ipqs.status === 'ok'
    ? `${ipqs.flagged ? 'THREAT' : 'CLEAN'} · risk ${ipqs.riskScore}/100${ipqs.category ? ` · ${escapeHtml(ipqs.category)}` : ''}`
    : standby;

  const abuseLine = abuse.status === 'ok'
    ? `${abuse.flagged ? 'THREAT' : 'CLEAN'} · abuse ${abuse.abuseConfidenceScore}% · ${abuse.totalReports} reports`
    : standby;

  const lines = [
    '<b>threat intelligence</b>',
    '',
    ...metricGrid([
      ['VIRUSTOTAL', vtLine],
      ['SAFE BROWS', gsbLine],
      ['URLSCAN', usLine],
      ['IPQS AI', ipqsLine],
      ['ABUSEIPDB', abuseLine],
    ], 'en'),
    '',
    '<i>url fingerprint · sha-256</i>',
    `<code>${escapeHtml(report.urlHash)}</code>`,
  ];

  if (vt.flaggingVendors?.length) {
    lines.push('', `flagging vendors: <code>${escapeHtml(vt.flaggingVendors.join(', '))}</code>`);
  }

  return lines;
}

function infraTab(report, s) {
  const inf = report.infra || {};
  const dns = inf.dns || {};
  const rdap = inf.rdap || {};
  const ssl = inf.ssl || {};
  const geo = inf.geo || {};
  const yes = (v) => (v ? 'yes' : 'no');

  return [
    `<b>${s.btnTabInfra} · infrastructure</b>`,
    '',
    `<code>${escapeHtml(report.domain)}</code>`,
    '',
    ...metricGrid([
      ['REGISTRAR', clip(rdap.registrar || s.unknown, 26)],
      ['REGISTERED', clip(rdap.createdDate || '—', 12)],
      ['EXPIRES', clip(rdap.expiresDate || '—', 12)],
      ['AGE', rdap.ageDays !== null && rdap.ageDays !== undefined ? `${rdap.ageDays}d` : s.unknown],
      ['DNSSEC', yes(rdap.dnssec || dns.dnssecValidated)],
      ['A', clip((dns.aRecords || []).join(' ') || '—', 26)],
      ['AAAA', clip((dns.aaaaRecords || []).slice(0, 1).join(' ') || '—', 26)],
      ['NS', clip((dns.nsRecords || []).slice(0, 2).join(' ') || '—', 26)],
      ['HOSTING', clip(`${geo.country || s.unknown} ${geo.org || geo.isp || ''}`.trim(), 26)],
      ['SPF', yes(dns.hasSpf)],
      ['DMARC', yes(dns.hasDmarc)],
      ['CAA', yes(dns.hasCaa)],
      ['TLS ISSUER', clip(ssl.issuer || s.unknown, 26)],
      ['CT CERTS', `${ssl.certsFound || 0}${ssl.notAfter ? ` · until ${clip(ssl.notAfter, 11)}` : ''}`],
    ], 'en'),
  ];
}

function headersTab(report, s, lang) {
  const h = report.http || {};
  const dom = h.dom || {};
  const flag = (v, on, off) => (v ? on : off);

  const present = (h.presentHeaders || [])
    .map((x) => `· ${escapeHtml(x.name)}: <code>${escapeHtml(clip(x.value, 40))}</code>`)
    .join('\n') || '—';
  const missing = (h.missingHeaders || []).map((x) => escapeHtml(x)).join(', ') || '—';

  const domRows = [
    ['PORT', `${h.reachable ? h.httpStatus : 'unreachable'} · ${h.latencyMs || 0}ms`],
    ['TYPE', clip(h.contentType || '—', 26)],
    ['TITLE', clip(dom.title || '—', 26)],
    ['REDIRECT', h.redirected ? 'yes' : 'no'],
    ['HEADER SCORE', `${h.headerGrade || '—'} · ${h.headerScore ?? 0}/100`],
    ['PASSWORD FORM', flag(dom.hasPasswordInput, 'present', 'none')],
    ['CROSS-DOMAIN', flag(dom.hasExternalFormAction, 'THREAT', 'none')],
    ['HIDDEN IFRAME', flag(dom.hasHiddenIframe || dom.hasObfuscatedJs, 'THREAT', 'none')],
    ['CLICKFIX', flag(dom.hasClickFixTrap, 'THREAT', 'none')],
    ['CRYPTO DRAINER', flag(dom.hasCryptoDrainer, 'THREAT', 'none')],
  ];

  if (lang === 'fa') {
    domRows.push(['فرم جعلی کارت', flag(dom.hasIranCardSkimmer, 'THREAT', 'none')]);
    domRows.push(['تله ابلاغیه', flag(dom.hasIranGovApkLure, 'THREAT', 'none')]);
  } else {
    domRows.push(['CARD SKIMMER', flag(dom.hasIranCardSkimmer, 'THREAT', 'none')]);
  }

  const lines = [
    `<b>${s.btnTabHeaders} · hardening</b>`,
    '',
    ...metricGrid(domRows, 'en'),
  ];

  if (h.payloadSha256) {
    lines.push('', '<i>payload sha-256</i>', `<code>${escapeHtml(h.payloadSha256)}</code>`);
  }

  lines.push(
    '',
    `<blockquote expandable><b>present headers</b>\n${present}\n\n<b>missing headers</b>\n${missing}</blockquote>`
  );

  return lines;
}

export function renderHistoryMessage(historyRows, lang = 'en') {
  const s = t(lang);
  if (!historyRows.length) return `${s.lblHistoryTitle}\n${RULE}\n${s.lblHistoryEmpty}`;

  const lines = [s.lblHistoryTitle, RULE];
  for (const row of historyRows) {
    const tag = row.verdict === 'MALICIOUS' ? s.tagDanger
      : row.verdict === 'SUSPICIOUS' ? s.tagCaution
        : row.verdict === 'LOW_RISK' ? s.tagHygiene
          : s.limitedVerdict;
    lines.push(`· <code>${escapeHtml(clip(row.domain, 30))}</code> ${tag} ${row.riskScore}/100 ${escapeHtml(row.grade)}`);
  }
  return lines.join('\n');
}

export function renderStatsMessage(stats, lang = 'en') {
  const s = t(lang);
  return [
    s.lblStatsTitle,
    RULE,
    ...metricGrid([
      [s.lblTotalScans, String(stats.totalScans)],
      [s.lblThreatsBlocked, String(stats.threatsBlocked)],
      [s.lblGlobalScans, String(stats.globalScans)],
      [s.lblCurrentLang, s.name],
    ], lang),
  ].join('\n');
}

export function renderApiKeysMessage(engines, lang = 'en') {
  const s = t(lang);
  const rows = engines.map((eng) => {
    const state = eng.configured ? s.lblStatusActive : s.lblStatusStandby;
    const detail = eng.tier === 'live_api' && eng.masked ? `${state} · ${eng.masked}` : state;
    return [String(eng.name).toUpperCase().slice(0, 12), detail];
  });

  return [
    s.lblKeysTitle,
    RULE,
    s.lblKeysIntro,
    '',
    ...metricGrid(rows, lang),
  ].join('\n');
}

function sourceResultLines(report, lang) {
  const labels = lang === 'fa'
    ? {ok:'پاسخ دریافت شد',cached:'داده ذخیره‌شده',stale_cache:'داده قدیمی',unavailable:'در دسترس نیست',error:'خطا',none:'نتیجه‌ای ثبت نشده',irnic:'قدمت عمومی در دسترس نیست'}
    : lang === 'ru' ? {ok:'ответ получен',cached:'кэш',stale_cache:'устаревший кэш',unavailable:'недоступно',error:'ошибка',none:'нет записей'}
    : {ok:'response received',cached:'cached data',stale_cache:'stale cached data',unavailable:'unavailable',error:'error',none:'no records'};
  return Object.entries(report.sourceResults || {}).map(([name, value]) =>
    `${escapeHtml(name)} — ${escapeHtml(labels[value.status] || value.status)}${value.entries != null ? ` · ${num(lang, value.entries)}` : ''}${value.ageSeconds != null ? ` · ${num(lang, Math.floor(value.ageSeconds / 3600))}h` : ''}`
  ).concat(['']);
}
