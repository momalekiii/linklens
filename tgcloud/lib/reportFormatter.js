import { t, escapeHtml, formatFinding } from './i18n.js';

// ============================================================================
// Rich HTML Security Report & Real-Time In-Place Live Formatter (FA / EN / RU)
// Integrates Iranian Threat & Breach Intelligence (MotmaenBash, Shaparak [fa],
// Nooshdaroo Kaveh, Leakfa, Have I Been Pwned)
// Zero credit footers here — Copyright lives strictly on `renderAboutMessage`!
// ============================================================================

export function renderHomeMessage(lang = 'en') {
  const s = t(lang);
  return [
    s.homeTitle,
    '',
    s.homeSubtitle,
    '',
    s.homeChecksHeader,
    ...s.homeChecksList,
    '',
    s.homeTip,
  ].join('\n');
}

export function renderAboutMessage(lang = 'en') {
  const s = t(lang);
  return [
    s.aboutTitle,
    '━━━━━━━━━━━━━━━━━━━━',
    ...(s.aboutBody || []),
  ].join('\n');
}

export function renderDraftProgressMessage(stageNum, rawUrl, lang = 'en', extraHeader = '') {
  const s = t(lang);
  const bars = ['▱▱▱▱', '▰▱▱▱', '▰▰▱▱', '▰▰▰▱', '▰▰▰▰'];
  const stageText = s[`stage${stageNum}`] || s.stage1;
  const bar = bars[Math.min(4, Math.max(0, stageNum))] || '▰▱▱▱';

  return [
    extraHeader,
    `${s.streamHeader}  <code>[${bar}]</code>`,
    `🔗 <code>${escapeHtml(String(rawUrl).slice(0, 90))}</code>`,
    ``,
    `⏳ ${stageText}`,
  ].filter(Boolean).join('\n');
}

function buildRiskBar(score) {
  const filled = Math.round(Math.max(0, Math.min(100, score)) / 10);
  const seg = score >= 65 ? '🟥' : score >= 35 ? '🟧' : score >= 16 ? '🟦' : '🟩';
  return seg.repeat(Math.max(1, filled)) + '⬜'.repeat(Math.max(0, 10 - Math.max(1, filled)));
}

export function buildPlainClipboardSummary(report, lang = 'en') {
  const s = t(lang);
  const verdictText = s[`verdict_${report.verdict}`] || report.verdict;
  const breachNote = report.iran?.hasBreachHistory ? ' | BreachHistory: YES' : '';
  return `LinkLens [${verdictText}] | Risk ${report.riskScore}/100 (Grade ${report.grade}) | Domain: ${report.domain}${breachNote} | Target: ${report.defangedUrl}`;
}

function buildIranHighlightBanners(report, s, lang) {
  const ir = report.iran;
  if (!ir) return [];
  const banners = [];

  // Shaparak payment gateway verification is exclusive to Iran — show ONLY in Farsi (`fa`)!
  if (lang === 'fa') {
    if (ir.shaparakStatus === 'VERIFIED_SHAPARAK' && ir.gatewayInfo) {
      const pspName = ir.gatewayInfo.fa || ir.gatewayInfo.en;
      banners.push(s.bannerShaparakVerified.replace('{psp}', escapeHtml(pspName)));
    } else if (ir.shaparakStatus === 'VERIFIED_FACILITATOR' && ir.gatewayInfo) {
      const pspName = ir.gatewayInfo.fa || ir.gatewayInfo.en;
      banners.push(s.bannerFacilitator.replace('{psp}', escapeHtml(pspName)));
    } else if (ir.shaparakStatus === 'FAKE_IRAN_BRAND' && ir.spoofedIranBrand) {
      banners.push(s.bannerFakeIranGateway.replace('{brand}', escapeHtml(ir.spoofedIranBrand)));
    }
  }

  if (ir.motmaenBashThreat) {
    banners.push(
      s.bannerMotmaenBashHit
        .replace('{cat}', escapeHtml(ir.motmaenBashThreat.threatCategory))
        .replace('{target}', escapeHtml(ir.motmaenBashThreat.matchedValue))
    );
  }

  if (ir.hasBreachHistory && ir.breaches?.length) {
    const primary = ir.breaches[0];
    const siteName = lang === 'fa' ? (primary.nameFa || primary.domain) : (primary.nameEn || primary.domain);
    banners.push(s.bannerLeakfaBreach.replace('{site}', escapeHtml(siteName)));
    if (primary.source === 'Leakfa') {
      const desc = lang === 'fa'
        ? (primary.descriptionFa || primary.descriptionEn)
        : (primary.descriptionEn || primary.descriptionFa);
      if (desc) {
        banners.push(`<blockquote>📋 <b>Leakfa:</b> ${escapeHtml(desc)}</blockquote>`);
      }
    }
  }

  return banners;
}

export function renderScanReportHtml(report, activeTab = 'overview', lang = 'en', siblingScans = null) {
  const s = t(lang);
  const verdictBanner = s[`verdict_${report.verdict}`] || report.verdict;
  const headerLines = [];

  if (Array.isArray(siblingScans) && siblingScans.length > 1) {
    headerLines.push(
      s.multiLinkSummaryHeader.replace('{count}', String(siblingScans.length)),
      ...siblingScans.map((it) => {
        const ic = it.verdict === 'MALICIOUS' ? '🔴' : it.verdict === 'SUSPICIOUS' ? '🟠' : '🟢';
        const marker = Number(it.scanId) === Number(report._scanId) ? '▸ ' : '  ';
        return `${marker}${ic} <code>${escapeHtml(String(it.domain).slice(0, 32))}</code> — <b>${it.riskScore}/100</b>`;
      }),
      `━━━━━━━━━━━━━━━━━━━━`
    );
  }

  headerLines.push(
    `<b>${verdictBanner}</b>`,
    `${buildRiskBar(report.riskScore)}  <b>${report.riskScore}/100</b>  •  ${s.lblGrade}: <b>${escapeHtml(report.grade)}</b>`,
    `━━━━━━━━━━━━━━━━━━━━`
  );

  if (report.spoofAlert) {
    headerLines.push(
      s.lblSpoofWarning
        .replace('{shown}', escapeHtml(report.spoofAlert.shown))
        .replace('{actual}', escapeHtml(report.spoofAlert.actual)),
      ''
    );
  }

  if (activeTab === 'iran') {
    return [...headerLines, ...renderIranAndBreachesTab(report, s, lang)].join('\n');
  }
  if (activeTab === 'engines') {
    return [...headerLines, ...renderEnginesTab(report, s)].join('\n');
  }
  if (activeTab === 'infra') {
    return [...headerLines, ...renderInfraTab(report, s)].join('\n');
  }
  if (activeTab === 'headers') {
    return [...headerLines, ...renderHeadersDomTab(report, s, lang)].join('\n');
  }

  // Default: Overview Tab
  const iranBanners = buildIranHighlightBanners(report, s, lang);
  const ageStr = report.infra?.rdap?.ageDays !== null && report.infra?.rdap?.ageDays !== undefined
    ? `${s.daysOld.replace('{days}', String(report.infra.rdap.ageDays))}${report.infra.rdap.registrar ? ` (${escapeHtml(report.infra.rdap.registrar.slice(0, 26))})` : ''}`
    : s.unknown;

  const geo = report.infra?.geo;
  const ipStr = report.infra?.ip
    ? `<code>${escapeHtml(report.infra.ip)}</code> ${geo?.flag || ''} ${escapeHtml(geo?.country || '')} ${geo?.asn ? `(${escapeHtml(geo.asn)})` : ''}`.trim()
    : s.unknown;

  const sslStr = report.http?.httpsEnforced
    ? `🔒 HTTPS${report.infra?.ssl?.issuer ? ` • ${escapeHtml(report.infra.ssl.issuer.slice(0, 28))}` : ''}`
    : '⚠️ No TLS (Plain HTTP)';

  const body = [
    ...(iranBanners.length ? [...iranBanners, ''] : []),
    `🔗 <b>${s.lblInputUrl}:</b> <code>${escapeHtml(report.inputUrl.slice(0, 110))}</code>`,
    `🎯 <b>${s.lblFinalUrl}:</b> <code>${escapeHtml(report.finalUrl.slice(0, 110))}</code>`,
    `📅 <b>${s.lblDomainAge}:</b> ${ageStr}`,
    `🖥 <b>${s.lblServerIp}:</b> ${ipStr}`,
    `🔐 <b>${s.lblSslStatus}:</b> ${sslStr}`,
    `🛡 <b>${s.lblHeadersGrade}:</b> <b>${escapeHtml(report.http?.headerGrade || 'N/A')}</b> (${report.http?.headerScore ?? 0}/100)`,
    `🧬 <b>${s.lblEngines}:</b> <b>${report.enginesFlagged}</b> flagged / <b>${report.enginesChecked}</b> active layers`,
    `⏱ <b>${s.lblScanTime}:</b> ${(report.durationMs / 1000).toFixed(2)}s ${report.cached ? `• ${s.lblCached}` : ''}`,
    ``,
    `<b>${s.lblFindings}:</b>`,
  ];

  if (!report.findings || report.findings.length === 0) {
    body.push(s.lblNoFindings);
  } else {
    const findingsText = report.findings
      .slice(0, 7)
      .map((f) => {
        const badge = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'medium' ? '🟡' : 'ℹ️';
        return `${badge} ${formatFinding(f, lang)}`;
      })
      .join('\n');
    body.push(`<blockquote expandable>${findingsText}</blockquote>`);
  }

  return [...headerLines, ...body].join('\n');
}

function renderIranAndBreachesTab(report, s, lang) {
  const ir = report.iran || {};
  const stats = ir.feedStats || {};
  const totalApkHashes = (stats.motmaenBashApks || 979) + (stats.kavehMalware || 539);

  if (lang === 'fa') {
    const gwFa =
      ir.shaparakStatus === 'VERIFIED_SHAPARAK'
        ? `🟢 تاییدشده رسمی شاپرک — ${escapeHtml(ir.gatewayInfo?.fa || '')}`
        : ir.shaparakStatus === 'VERIFIED_FACILITATOR'
          ? `🟦 پرداخت‌یار رسمی — ${escapeHtml(ir.gatewayInfo?.fa || '')}`
          : ir.shaparakStatus === 'FAKE_IRAN_BRAND'
            ? `🔴 جعلی / فیشینگ — جعل نام «${escapeHtml(ir.spoofedIranBrand || '')}»`
            : ir.shaparakStatus === 'INSECURE_HTTP_SHAPARAK'
              ? '🔴 ناامن — بدون گواهی HTTPS'
              : '⚪ این آدرس یک درگاه پرداخت بانکی شاپرک نیست';

    const mbFa = ir.motmaenBashThreat
      ? `🔴 شناسایی قطعی در لیست سیاه (${escapeHtml(ir.motmaenBashThreat.threatCategory)})`
      : ir.motmaenBashTrusted
        ? '🟢 ثبت‌شده در فهرست سفید مطمئن‌باش'
        : `🟢 پاک در بررسی <b>${stats.motmaenBashUrls || 301}</b> دامنه فیشینگ ایرانی`;

    const apkFa = ir.apkMalwareHit
      ? `🔴 آلوده به بدافزار اندروید: ${escapeHtml((ir.apkMalwareHit.detections || []).join(', '))}`
      : `🟢 پاک در بررسی <b>${totalApkHashes}</b> امضای بدافزار بانکی و پروژه کاوه`;

    const lines = [
      `🇮🇷 <b>امنیت سایبری ایران — مطمئن‌باش، شاپرک، کاوه و لیک‌فا</b>`,
      ``,
      `• <b>اصالت درگاه شاپرک:</b> ${gwFa}`,
      `• <b>دیتابیس فیشینگ مطمئن‌باش:</b> ${mbFa}`,
      `• <b>بدافزارهای اندروید و کاوه:</b> ${apkFa}`,
      `• <b>فرم سرقت کارت شتاب / ثنا:</b> ${report.http?.dom?.hasIranCardSkimmer || report.http?.dom?.hasIranGovApkLure ? '🔴 شناسایی فرم سرقت اطلاعات!' : '🟢 هیچ فرم جعلی یافت نشد'}`,
      ``,
      `🔐 <b>سابقه نشت اطلاعات (لیک‌فا + Have I Been Pwned):</b>`,
    ];

    if (!ir.breaches || ir.breaches.length === 0) {
      lines.push(
        `✅ هیچ سابقه نشت اطلاعاتی در <b>لیک‌فا</b> (${stats.leakfaDomains || 101} سامانه ایرانی) و <b>HIBP</b> (${stats.hibpBreaches || 981} سرویس جهانی) ثبت نشده است.`
      );
    } else {
      for (const b of ir.breaches) {
        if (b.source === 'Leakfa') {
          lines.push(
            `🟠 <b>لیک‌فا — ${escapeHtml(b.nameFa || b.domain)}</b> • واکنش شرکت: <code>${escapeHtml(b.companyResponse)}</code>`,
            `<blockquote>${escapeHtml(b.descriptionFa || b.descriptionEn)}</blockquote>`
          );
        } else {
          lines.push(
            `🟡 <b>HIBP — ${escapeHtml(b.nameEn)}</b> (${escapeHtml(b.breachDate || 'N/A')}) — <b>${Number(b.pwnCount || 0).toLocaleString('en-US')}</b> رکورد`
          );
        }
      }
    }

    lines.push(``, `<i>📚 منابع داده آزاد: MotmaenBash (CC-BY-4.0) • Nooshdaroo Kaveh • Leakfa-Alert (MIT) • HIBP v3</i>`);
    return lines;
  }

  const mbLine = ir.motmaenBashThreat
    ? `🔴 <b>MATCHED (${escapeHtml(ir.motmaenBashThreat.threatCategory)})</b> — SHA-256 blacklisted!`
    : ir.motmaenBashTrusted
      ? '🟢 Verified Trusted Domain'
      : `🟢 Clean across <b>${stats.motmaenBashUrls || 301}</b> phishing blacklist entries`;

  const apkLine = ir.apkMalwareHit
    ? `🔴 <b>MALWARE DETECTED:</b> ${escapeHtml((ir.apkMalwareHit.detections || []).join(', '))} (${escapeHtml(ir.apkMalwareHit.source)})`
    : `🟢 Clean across <b>${totalApkHashes}</b> Android malware SHA-256 hashes`;

  const lines = [
    `🔐 <b>${s.btnTabIran} — Data Breaches & Threat Feeds</b>`,
    ``,
    `• <b>Anti-Phishing SHA-256 Feed:</b> ${mbLine}`,
    `• <b>APK Malware Signatures:</b> ${apkLine}`,
    `• <b>Card Skimmer DOM Check:</b> ${report.http?.dom?.hasIranCardSkimmer ? '🔴 ACTIVE CARD SKIMMER!' : '🟢 None detected'}`,
    ``,
    `🔐 <b>Data Breach History (Have I Been Pwned + Open Breach Feeds):</b>`,
  ];

  if (!ir.breaches || ir.breaches.length === 0) {
    lines.push(
      `✅ No documented data breaches found across <b>Have I Been Pwned</b> (${stats.hibpBreaches || 981} verified global breaches).`
    );
  } else {
    for (const b of ir.breaches) {
      if (b.source === 'Leakfa') {
        const title = `${b.nameEn || b.nameFa} (${b.domain})`;
        lines.push(
          `🟠 <b>[Leakfa] ${escapeHtml(title)}</b> • Response: <code>${escapeHtml(b.companyResponse)}</code>`,
          `<blockquote>${escapeHtml(b.descriptionEn || b.descriptionFa)}</blockquote>`
        );
      } else {
        lines.push(
          `🟡 <b>[HIBP] ${escapeHtml(b.nameEn)}</b> (${escapeHtml(b.breachDate || 'N/A')}) — <b>${Number(b.pwnCount || 0).toLocaleString('en-US')}</b> records [${escapeHtml((b.dataClasses || []).join(', '))}]`
        );
      }
    }
  }

  lines.push(
    ``,
    `<i>📚 Data Attribution: MotmaenBash Dataset (CC-BY-4.0) • Nooshdaroo Kaveh • Leakfa-Alert (MIT) • HIBP v3</i>`
  );

  return lines;
}

function renderEnginesTab(report, s) {
  const e = report.engines || {};
  const vt = e.virustotal || {};
  const gsb = e.safeBrowsing || {};
  const us = e.urlscan || {};
  const abuse = e.abuseIpDb || {};
  const ipqs = e.ipqs || {};

  const vtLine = vt.status === 'ok'
    ? `${vt.flagged ? '🔴' : '🟢'} <b>${vt.malicious}</b> malicious, <b>${vt.suspicious}</b> suspicious / <b>${vt.totalEngines}</b> AV vendors`
    : vt.status === 'queued'
      ? '🟡 Queued for fresh scan (tap Re-Scan in ~15s)'
      : `⚪ ${s.lblStatusStandby || 'Standby'}`;

  const gsbLine = gsb.status === 'ok'
    ? (gsb.flagged ? `🔴 FLAGGED: <b>${escapeHtml(gsb.threats.join(', '))}</b>` : '🟢 Clean (0 Google threat matches)')
    : `⚪ ${s.lblStatusStandby || 'Standby'}`;

  const usLine = us.status === 'ok'
    ? `${us.flagged ? `🔴 ${us.maliciousScans} malicious sandbox hits` : '🟢 Clean domain history'}${us.latestScan?.tlsIssuer ? ` • TLS: ${escapeHtml(us.latestScan.tlsIssuer)}` : ''}`
    : `⚪ ${s.lblStatusStandby || 'Standby'}`;

  const ipqsLine = ipqs.status === 'ok'
    ? `${ipqs.flagged ? '🔴' : '🟢'} Risk Score: <b>${ipqs.riskScore}/100</b>${ipqs.category ? ` (${escapeHtml(ipqs.category)})` : ''}`
    : `⚪ ${s.lblStatusStandby || 'Standby'}`;

  const abuseLine = abuse.status === 'ok'
    ? `${abuse.flagged ? '🔴' : '🟢'} Abuse Confidence: <b>${abuse.abuseConfidenceScore}%</b> (${abuse.totalReports} reports)`
    : `⚪ ${s.lblStatusStandby || 'Standby'}`;

  const lines = [
    `🧬 <b>${s.btnTabEngines} — Global Threat Telemetry</b>`,
    ``,
    `• <b>VirusTotal v3:</b> ${vtLine}`,
    `• <b>Google Safe Browsing v4:</b> ${gsbLine}`,
    `• <b>URLScan.io Intel:</b> ${usLine}`,
    `• <b>IPQualityScore AI:</b> ${ipqsLine}`,
    `• <b>AbuseIPDB v2:</b> ${abuseLine}`,
    ``,
    `🔑 <i>URL SHA-256 Fingerprint:</i>`,
    `<code>${escapeHtml(report.urlHash)}</code>`,
  ];

  if (vt.flaggingVendors?.length) {
    lines.push('', `<b>Flagging Vendors:</b> <code>${escapeHtml(vt.flaggingVendors.join(', '))}</code>`);
  }

  return lines;
}

function renderInfraTab(report, s) {
  const inf = report.infra || {};
  const dns = inf.dns || {};
  const rdap = inf.rdap || {};
  const ssl = inf.ssl || {};
  const geo = inf.geo || {};

  return [
    `🌐 <b>${s.btnTabInfra} — Infrastructure & Registry</b>`,
    ``,
    `• <b>Domain:</b> <code>${escapeHtml(report.domain)}</code>`,
    `• <b>Registrar (RDAP):</b> ${escapeHtml(rdap.registrar || s.unknown)}`,
    `• <b>Registered / Expires:</b> ${escapeHtml(rdap.createdDate || '—')} → ${escapeHtml(rdap.expiresDate || '—')} ${rdap.ageDays !== null && rdap.ageDays !== undefined ? `(<b>${rdap.ageDays}d</b>)` : ''}`,
    `• <b>DNSSEC Signed:</b> ${rdap.dnssec || dns.dnssecValidated ? '✅ Yes' : '⚪ Unsigned'}`,
    ``,
    `• <b>IPv4 (A):</b> <code>${escapeHtml((dns.aRecords || []).join(', ') || '—')}</code>`,
    `• <b>IPv6 (AAAA):</b> <code>${escapeHtml((dns.aaaaRecords || []).slice(0, 2).join(', ') || '—')}</code>`,
    `• <b>ASN / Hosting:</b> ${escapeHtml(`${geo.flag || ''} ${geo.country || ''} ${geo.org || geo.isp || ''}`.trim() || s.unknown)}`,
    `• <b>Nameservers (NS):</b> <code>${escapeHtml((dns.nsRecords || []).join(', ') || '—')}</code>`,
    `• <b>Email Anti-Spoof:</b> SPF ${dns.hasSpf ? '✅' : '❌'}  |  DMARC ${dns.hasDmarc ? '✅' : '❌'}  |  CAA ${dns.hasCaa ? '✅' : '⚪'}`,
    ``,
    `• <b>SSL Cert Issuer (crt.sh):</b> ${escapeHtml(ssl.issuer || s.unknown)}`,
    `• <b>CT Log Certificates:</b> ${ssl.certsFound || 0} recorded ${ssl.notAfter ? `(valid until ${escapeHtml(ssl.notAfter)})` : ''}`,
  ];
}

function renderHeadersDomTab(report, s, lang = 'en') {
  const h = report.http || {};
  const dom = h.dom || {};
  const presentList = (h.presentHeaders || []).map((x) => `✅ <b>${escapeHtml(x.name)}:</b> <code>${escapeHtml(x.value)}</code>`).join('\n') || 'None';
  const missingList = (h.missingHeaders || []).map((x) => `❌ ${escapeHtml(x)}`).join('  •  ') || 'None!';

  return [
    `🔒 <b>${s.btnTabHeaders} — HTTP Hardening & Page Inspection</b>`,
    ``,
    `• <b>HTTP Status:</b> <code>${h.reachable ? h.httpStatus : 'Unreachable'}</code> (${h.latencyMs || 0} ms) • <code>${escapeHtml(h.contentType || '')}</code>`,
    `• <b>Page Title:</b> ${escapeHtml(dom.title || '—')}`,
    `• <b>Redirected:</b> ${h.redirected ? `🔀 Yes → <code>${escapeHtml(h.finalUrl)}</code>` : 'No direct hop'}`,
    `• <b>OWASP Header Grade:</b> <b>${escapeHtml(h.headerGrade || 'N/A')}</b> (${h.headerScore ?? 0}/100)`,
    ...(h.payloadSha256 ? [`• <b>Binary Payload SHA-256:</b> <code>${escapeHtml(h.payloadSha256)}</code>`] : []),
    ``,
    `<b>DOM Anti-Phishing Forensics:</b>`,
    ...(lang === 'fa'
      ? [
          `• فرم فیشینگ شاپرک / کارت شتاب: ${dom.hasIranCardSkimmer ? '🔴 شناسایی شد!' : '✅ پاک'}`,
          `• تله بدافزار ابلاغیه ثنا / پست: ${dom.hasIranGovApkLure ? '🔴 شناسایی شد!' : '✅ پاک'}`,
        ]
      : [
          `• Card Skimmer Form: ${dom.hasIranCardSkimmer ? '🔴 DETECTED!' : '✅ Clean'}`,
        ]),
    `• Password Input Form: ${dom.hasPasswordInput ? '⚠️ Present' : '✅ None'}`,
    `• External Form Action: ${dom.hasExternalFormAction ? '🔴 Cross-Domain Post!' : '✅ Clean'}`,
    `• Hidden Iframe / Obfuscated JS: ${dom.hasHiddenIframe || dom.hasObfuscatedJs ? '🟠 Detected' : '✅ Clean'}`,
    `• ClickFix Trap / Crypto Drainer: ${dom.hasClickFixTrap || dom.hasCryptoDrainer ? '🔴 DETECTED!' : '✅ Clean'}`,
    ``,
    `<blockquote expandable><b>Present Security Headers:</b>\n${presentList}\n\n<b>Missing Headers:</b>\n${missingList}</blockquote>`,
  ];
}

export function renderHistoryMessage(historyRows, lang = 'en') {
  const s = t(lang);
  if (!historyRows.length) {
    return `${s.lblHistoryTitle}\n\n${s.lblHistoryEmpty}`;
  }
  const lines = [s.lblHistoryTitle, ''];
  for (const row of historyRows) {
    const icon = row.verdict === 'MALICIOUS' ? '🔴' : row.verdict === 'SUSPICIOUS' ? '🟠' : row.verdict === 'LOW_RISK' ? '🔵' : '🟢';
    lines.push(`${icon} <b>${escapeHtml(row.domain)}</b> — <code>${row.riskScore}/100</code> (${escapeHtml(row.grade)})`);
  }
  return lines.join('\n');
}

export function renderStatsMessage(stats, lang = 'en') {
  const s = t(lang);
  return [
    s.lblStatsTitle,
    '━━━━━━━━━━━━━━━━━━━━',
    `🔍 <b>${s.lblTotalScans}:</b> ${stats.totalScans}`,
    `🛡 <b>${s.lblThreatsBlocked}:</b> ${stats.threatsBlocked}`,
    `🌍 <b>${s.lblGlobalScans}:</b> ${stats.globalScans}`,
    `🌐 <b>${s.lblCurrentLang}:</b> ${s.flag} ${s.name}`,
  ].join('\n');
}

export function renderApiKeysMessage(engines, _miniAppUrl, lang = 'en') {
  const s = t(lang);
  const lines = [
    s.lblKeysTitle,
    '━━━━━━━━━━━━━━━━━━━━',
    s.lblKeysIntro,
    '',
  ];

  for (const eng of engines) {
    const icon = eng.configured ? '🟢' : '⚪';
    const detail = eng.tier === 'live_api'
      ? (eng.masked || s.lblStatusActive || 'Active')
      : (eng.configured ? (s.lblStatusActive || 'Active') : (s.lblStatusStandby || 'Standby'));
    lines.push(`${icon} <b>${escapeHtml(eng.name)}:</b> <code>${escapeHtml(detail)}</code>`);
  }

  return lines.join('\n');
}
