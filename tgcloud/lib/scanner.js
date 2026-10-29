import { db } from 'sdk';
import { eq, and, gte, desc } from 'sdk/db';
import { scans, scanStops } from '../schema.js';
import { getConfigMap } from './secrets.js';
import {
  parseAndValidateTarget,
  runLexicalHeuristics,
  defangUrl,
} from './urlUtils.js';
import { checkVirusTotal } from './providers/virustotal.js';
import { checkGoogleSafeBrowsing } from './providers/safeBrowsing.js';
import { checkUrlScan } from './providers/urlscan.js';
import { checkIpAndUrlReputation } from './providers/ipReputation.js';
import {
  inspectDnsPosture,
  inspectRdapDomainAge,
  inspectSslTransparency,
} from './providers/domainDnsSsl.js';
import { inspectHttpAndDom } from './providers/httpInspector.js';
import { checkIranianSecurityAndBreaches } from './providers/iranIntel.js';
import { recordUserScanStats, ensureDbReady } from './usersRepo.js';
import { parseUrlPure, boundedLayer } from './v8Runtime.js';

// Neutral fallbacks: if a source is slow or fails, the layer reports "standby"
// instead of aborting the whole scan (which used to freeze the live message).
const EMPTY_IRAN = { unavailable: true, breaches: [], feedStats: {}, hasBreachHistory: false };
const EMPTY_ENGINE = { status: 'unavailable', malicious: 0, suspicious: 0, flagged: false };
const EMPTY_DNS = { unavailable: true, aRecords: [], aaaaRecords: [], nsRecords: [], mxRecords: [], hasSpf: false, hasDmarc: false, hasCaa: false };
const EMPTY_HTTP = { reachable: false, httpsEnforced: false, dom: {}, presentHeaders: [], missingHeaders: [] };
const EMPTY_REP = { status: 'standby' };
const LAYER_BUDGET_MS = 6000;

// Built-in showcase URLs (Shaparak & Iranian presets shown exclusively in Farsi `fa`!)
export const DEMO_SAFE_URL = 'https://github.com/telegramdesktop/tdesktop';
export const DEMO_SHAPARAK_URL = 'https://bpm.shaparak.ir';
export const DEMO_LEAKFA_URL = 'https://irancell.ir';
export const DEMO_PHISH_URL = 'http://secure-shaparak-telegram-verify.xyz/sana-eblagh?redirect=https://evil-drop.top/sana.apk';
export const DEMO_GLOBAL_PORTAL_URL = 'https://cloudflare.com';
export const DEMO_GLOBAL_BREACH_URL = 'https://adobe.com';
export const DEMO_GLOBAL_PHISH_URL = 'http://secure-paypal-account-verify.xyz/login?redirect=https://evil-drop.top/update.apk';

const CACHE_TTL_SECONDS = 900; // 15-minute smart cache unless Force Re-Scan is clicked

async function isScanStopped(draftKey) {
  if (!draftKey) return false;
  try {
    const row = await db.select().from(scanStops).where(eq(scanStops.draftKey, draftKey)).get();
    return Boolean(row);
  } catch (_) {
    return false;
  }
}

export async function runFullSecurityScan({
  rawUrl,
  tgId = 0,
  spoofAlert = null,
  forceRescan = false,
  draftKey = null,
  onStage = null,
}) {
  const startedAt = Date.now();
  await ensureDbReady();
  const target = parseAndValidateTarget(rawUrl);
  if (!target.valid) {
    return { ok: false, error: target.error };
  }

  // Fast SQLite cache hit (<15m) unless forceRescan or message has unique spoofAlert
  if (!forceRescan && !spoofAlert) {
    try {
      const cutoff = Math.floor(Date.now() / 1000) - CACHE_TTL_SECONDS;
      const cached = await db.select()
        .from(scans)
        .where(and(eq(scans.normalizedUrl, target.normalizedUrl), gte(scans.createdAt, cutoff)))
        .orderBy(desc(scans.id))
        .get();

      if (cached && cached.report?.pipelineVersion === 4) {
        const clonedReport = {
          ...cached.report,
          cached: true,
          durationMs: cached.report.durationMs,
          retrievalMs: Date.now() - startedAt,
        };
        const [savedRow] = await db.insert(scans)
          .values({
            tgId: Number(tgId || 0),
            inputUrl: target.inputUrl,
            normalizedUrl: target.normalizedUrl,
            finalUrl: cached.finalUrl,
            domain: cached.domain,
            urlHash: target.urlHash,
            riskScore: cached.riskScore,
            verdict: cached.verdict,
            grade: cached.grade,
            enginesFlagged: cached.enginesFlagged,
            enginesChecked: cached.enginesChecked,
            durationMs: clonedReport.durationMs,
            report: clonedReport,
          })
          .returning()
          .run();

        if (tgId) {
          await recordUserScanStats(tgId, cached.verdict === 'SUSPICIOUS' || cached.verdict === 'MALICIOUS');
        }
        return { ok: true, scanId: savedRow.id, report: clonedReport };
      }
    } catch (_) {
      // Proceed with fresh scan if table empty/unmigrated
    }
  }

  // Stage 1: Lexical Analysis + Live HTTP Redirect Unshortening, Binary Hash & DOM Inspection
  if (onStage) await onStage(1);
  if (await isScanStopped(draftKey)) return { ok: false, error: 'STOPPED' };

  const cfg = await getConfigMap();
  const lexical = runLexicalHeuristics(target, spoofAlert);
  const httpInfo = await boundedLayer(
    () => inspectHttpAndDom(target.normalizedUrl, target.registrableDomain),
    { ...EMPTY_HTTP, finalUrl: target.normalizedUrl, finalDomain: target.registrableDomain },
    LAYER_BUDGET_MS
  );

  if (httpInfo.reachable && httpInfo.httpsEnforced) {
    lexical.findings = lexical.findings.filter((f) => f.code !== 'NO_HTTPS');
    if (target.protocol === 'http:') lexical.points = Math.max(0, lexical.points - 15);
  }

  const effectiveFinalUrl = httpInfo.finalUrl || target.normalizedUrl;
  const effectiveDomain = httpInfo.finalDomain || target.registrableDomain;
  const parsedFinalHost = parseUrlPure(effectiveFinalUrl);
  const effectiveHostname = parsedFinalHost ? parsedFinalHost.hostname.toLowerCase() : target.hostname;

  // Stage 2: Parallel Global + Iranian Threat & Breach Feeds + DNS + RDAP + SSL CT
  if (onStage) await onStage(2);
  if (await isScanStopped(draftKey)) return { ok: false, error: 'STOPPED' };

  const budget = LAYER_BUDGET_MS;
  const [iran, vt, gsb, urlscan, dns, rdap, sslRaw] = await Promise.all([
    boundedLayer(() => checkIranianSecurityAndBreaches({
      inputUrl: target.inputUrl,
      normalizedUrl: target.normalizedUrl,
      finalUrl: effectiveFinalUrl,
      initialHostname: target.hostname,
      finalHostname: effectiveHostname,
      httpsEnforced: httpInfo.httpsEnforced,
      payloadSha256: httpInfo.payloadSha256,
    }), EMPTY_IRAN, budget),
    boundedLayer(() => checkVirusTotal(effectiveFinalUrl, cfg.VIRUSTOTAL_API_KEY), EMPTY_ENGINE, budget),
    boundedLayer(() => checkGoogleSafeBrowsing([target.normalizedUrl, effectiveFinalUrl], cfg.GOOGLE_SAFE_BROWSING_KEY), EMPTY_ENGINE, budget),
    boundedLayer(() => checkUrlScan(effectiveFinalUrl, effectiveHostname, cfg.URLSCAN_API_KEY), EMPTY_ENGINE, budget),
    boundedLayer(() => inspectDnsPosture(effectiveHostname, effectiveDomain), EMPTY_DNS, budget),
    boundedLayer(() => inspectRdapDomainAge(effectiveDomain), {}, budget),
    boundedLayer(() => inspectSslTransparency(effectiveDomain), {}, budget),
  ]);

  // Stage 3: Server IP Reputation & Geolocation Telemetry
  if (onStage) await onStage(3);
  if (await isScanStopped(draftKey)) return { ok: false, error: 'STOPPED' };

  const primaryIp = dns.aRecords[0] || urlscan.latestScan?.ip || null;
  const ipRep = await boundedLayer(() => checkIpAndUrlReputation({
    url: effectiveFinalUrl,
    primaryIp,
    abuseKey: cfg.ABUSEIPDB_API_KEY,
    ipqsKey: cfg.IPQUALITYSCORE_API_KEY,
  }), EMPTY_REP, budget);

  const ssl = {
    ...sslRaw,
    issuer: sslRaw.issuer || urlscan.latestScan?.tlsIssuer || null,
  };

  // Stage 4: Synthesize Multi-Layer Findings, Category Scores & Overall Verdict
  if (onStage) await onStage(4);
  if (await isScanStopped(draftKey)) return { ok: false, error: 'STOPPED' };

  const findings = [...lexical.findings];
  let points = lexical.points;
  // Active keyless layers always checked:
  // 1) DoH DNS, 2) RDAP, 3) crt.sh SSL, 4) HTTP/DOM, 5) MotmaenBash+Shaparak, 6) Kaveh Malware, 7) Leakfa+HIBP
  let enginesChecked = [httpInfo.reachable, !dns.unavailable, rdap.ageDays != null, ssl.certsFound > 0, ...(Object.values(iran.sources || {}).map((v) => v.entries > 0))].filter(Boolean).length;
  let enginesFlagged = 0;

  // 0. Iranian Security & Gateway Intelligence Scoring (MotmaenBash + Shaparak + Kaveh + Leakfa/HIBP)
  if (iran.motmaenBashThreat) {
    enginesFlagged++;
    const cat = iran.motmaenBashThreat.threatCategory;
    const w = cat === 'PHISHING' ? 78 : cat === 'SCAM' ? 72 : cat === 'PONZI' ? 68 : 55;
    points += w;
    findings.push({
      code: 'MOTMAENBASH_THREAT',
      severity: 'critical',
      weight: w,
      params: {
        category: cat,
        target: iran.motmaenBashThreat.matchedValue,
      },
    });
  }

  if (iran.apkMalwareHit) {
    enginesFlagged++;
    points += 85;
    findings.push({
      code: 'IRAN_APK_MALWARE',
      severity: 'critical',
      weight: 85,
      params: {
        source: iran.apkMalwareHit.source,
        family: (iran.apkMalwareHit.detections || []).join(', '),
      },
    });
  }

  if (iran.shaparakStatus === 'VERIFIED_SHAPARAK') {
    // Verified official Central Bank of Iran (`*.shaparak.ir`) over HTTPS!
    // Reduce false-positive header/WHOIS noise since `.ir` NIC doesn't expose public RDAP age
    points = Math.max(0, points - 10);
  } else if (iran.shaparakStatus === 'INSECURE_HTTP_SHAPARAK') {
    enginesFlagged++;
    points += 55;
    findings.push({
      code: 'SHAPARAK_HTTP_DOWNGRADE',
      severity: 'high',
      weight: 55,
      params: { host: effectiveHostname },
    });
  } else if (iran.shaparakStatus === 'FAKE_IRAN_BRAND') {
    enginesFlagged++;
    // Avoid double-counting if lexical BRAND_TYPOSQUAT already fired on `shaparak`
    const extraWeight = findings.some((f) => f.code === 'BRAND_TYPOSQUAT') ? 35 : 74;
    points += extraWeight;
    findings.push({
      code: 'FAKE_IRAN_GATEWAY_BRAND',
      severity: 'critical',
      weight: extraWeight,
      params: { brand: iran.spoofedIranBrand },
    });
  }

  // Zero-day live HTML DOM Iranian card skimmer & judicial/postal APK trap
  if (httpInfo.dom?.hasIranCardSkimmer) {
    enginesFlagged++;
    points += 85;
    findings.push({
      code: 'IRAN_DOM_CARD_SKIMMER',
      severity: 'critical',
      weight: 85,
    });
  }
  if (httpInfo.dom?.hasIranGovApkLure) {
    enginesFlagged++;
    points += 75;
    findings.push({
      code: 'IRAN_GOV_APK_LURE',
      severity: 'critical',
      weight: 75,
    });
  }

  // Leakfa & Have I Been Pwned Breach Advisory:
  // IMPORTANT: Breached sites (e.g. Irancell, Tapsi, Wallex, Adobe) are LEGITIMATE websites whose
  // historical user database leaked — NOT fake phishing clones! Add a gentle +6 hygiene advisory
  // so users are clearly warned to rotate passwords & enable 2FA without false-flagging the domain as phishing!
  if (iran.leakfaMatched) {
    const lf = iran.breaches.find((b) => b.source === 'Leakfa');
    points += 6;
    findings.push({
      code: 'LEAKFA_BREACH_HISTORY',
      severity: 'medium',
      weight: 6,
      params: {
        siteFa: lf?.nameFa || effectiveDomain,
        siteEn: lf?.nameEn || effectiveDomain,
      },
    });
  } else if (iran.hibpMatched) {
    const hb = iran.breaches.find((b) => b.source === 'HaveIBeenPwned');
    points += 5;
    findings.push({
      code: 'HIBP_BREACH_HISTORY',
      severity: 'medium',
      weight: 5,
      params: {
        site: hb?.nameEn || effectiveDomain,
        count: hb?.pwnCount ? hb.pwnCount.toLocaleString('en-US') : 'multiple',
        date: hb?.breachDate || 'documented',
      },
    });
  }

  // 1. Global Threat Intel Engines Scoring
  if (vt.status === 'ok' || vt.status === 'queued') enginesChecked++;
  if (vt.malicious > 0) {
    enginesFlagged++;
    const w = vt.malicious >= 3 ? 65 : 42;
    points += w;
    findings.push({ code: 'VT_MALICIOUS', severity: 'critical', weight: w, params: { n: vt.malicious } });
  } else if (vt.suspicious > 0) {
    enginesFlagged++;
    points += 24;
    findings.push({ code: 'VT_SUSPICIOUS', severity: 'medium', weight: 24, params: { n: vt.suspicious } });
  }

  if (gsb.status === 'ok') enginesChecked++;
  if (gsb.flagged) {
    enginesFlagged++;
    points += 70;
    findings.push({
      code: 'GSB_THREAT',
      severity: 'critical',
      weight: 70,
      params: { threat: gsb.threats.join(', ') },
    });
  }

  if (urlscan.status === 'ok') enginesChecked++;
  if (urlscan.flagged) {
    enginesFlagged++;
    points += 45;
    findings.push({
      code: 'URLSCAN_MALICIOUS',
      severity: 'high',
      weight: 45,
      params: { n: urlscan.maliciousScans },
    });
  }

  if (ipRep.ipqs?.status === 'ok') enginesChecked++;
  if (ipRep.ipqs?.flagged) {
    enginesFlagged++;
    points += 40;
    findings.push({
      code: 'IPQS_HIGH_RISK',
      severity: 'high',
      weight: 40,
      params: { n: ipRep.ipqs.riskScore },
    });
  }

  if (ipRep.abuseIpDb?.status === 'ok') enginesChecked++;
  if (ipRep.abuseIpDb?.flagged) {
    enginesFlagged++;
    points += 25;
    findings.push({
      code: 'ABUSEIPDB_FLAG',
      severity: 'medium',
      weight: 25,
      params: { n: ipRep.abuseIpDb.abuseConfidenceScore, r: ipRep.abuseIpDb.totalReports },
    });
  }

  // 2. Domain Age & RDAP Trust Scoring
  if (rdap.ageDays !== null && rdap.ageDays !== undefined) {
    if (rdap.ageDays <= 14) {
      enginesFlagged++;
      points += 35;
      findings.push({ code: 'NEW_DOMAIN_CRITICAL', severity: 'high', weight: 35, params: { n: rdap.ageDays } });
    } else if (rdap.ageDays <= 60) {
      points += 16;
      findings.push({ code: 'NEW_DOMAIN_WARN', severity: 'medium', weight: 16, params: { n: rdap.ageDays } });
    } else if (rdap.ageDays >= 1825 && points < 40) {
      points = Math.max(0, points - 6);
    }
  }

  // 3. HTTP Redirects, Headers & Page DOM Threats
  if (httpInfo.crossDomainRedirect) {
    points += 12;
    findings.push({
      code: 'CROSS_DOMAIN_REDIRECT',
      severity: 'low',
      weight: 12,
      params: { hops: '1+', dest: effectiveDomain },
    });
  }

  if (httpInfo.dom?.hasClickFixTrap) {
    enginesFlagged++;
    points += 65;
    findings.push({ code: 'CLICKFIX_TRAP', severity: 'critical', weight: 65 });
  }
  if (httpInfo.dom?.hasCryptoDrainer) {
    enginesFlagged++;
    points += 55;
    findings.push({ code: 'CRYPTO_DRAINER', severity: 'critical', weight: 55 });
  }
  if (httpInfo.dom?.hasObfuscatedJs) {
    points += 22;
    findings.push({ code: 'OBFUSCATED_JS', severity: 'medium', weight: 22 });
  }
  if (httpInfo.dom?.hasHiddenIframe) {
    points += 18;
    findings.push({ code: 'HIDDEN_IFRAME', severity: 'medium', weight: 18 });
  }
  if (httpInfo.dom?.hasPasswordInput && (points >= 25 || httpInfo.dom.hasExternalFormAction)) {
    points += 25;
    findings.push({ code: 'PASSWORD_FORM', severity: 'high', weight: 25 });
  }
  if (httpInfo.reachable && httpInfo.missingHeaders.length >= 4 && iran.shaparakStatus !== 'VERIFIED_SHAPARAK') {
    points += 5;
    findings.push({
      code: 'WEAK_HEADERS',
      severity: 'info',
      weight: 5,
      params: { missing: httpInfo.missingHeaders.slice(0, 3).join(', ') },
    });
  }
  if (!dns.unavailable && !dns.isIpLiteral && !dns.hasDmarc && !dns.nxdomain && iran.shaparakStatus !== 'VERIFIED_SHAPARAK') {
    findings.push({ code: 'NO_EMAIL_AUTH', severity: 'info', weight: 2 });
    points += 2;
  }

  if (lexical.points >= 35) enginesFlagged++;

  const riskScore = Math.max(0, Math.min(100, Math.round(points)));
  const verdict =
    riskScore >= 65 ? 'MALICIOUS' :
    riskScore >= 35 ? 'SUSPICIOUS' :
    riskScore >= 16 ? 'LOW_RISK' : 'SAFE';

  const grade =
    riskScore <= 8 ? 'A+' :
    riskScore <= 18 ? 'A' :
    riskScore <= 34 ? 'B' :
    riskScore <= 55 ? 'C' :
    riskScore <= 75 ? 'D' : 'F';

  // Sort findings most severe first
  findings.sort((a, b) => (b.weight || 0) - (a.weight || 0));

  const durationMs = Date.now() - startedAt;

  const report = {
    pipelineVersion: 4,
    limited: true,
    sourceResults: {
      motmaenbash: iran.sources?.motmaenbash || {status: 'unavailable'},
      leakfa: iran.sources?.leakfa || {status: 'unavailable'},
      kaveh: iran.sources?.kaveh || {status: 'unavailable'},
      hibp: iran.sources?.hibp || {status: 'unavailable'},
      dns: {status: dns.unavailable ? 'unavailable' : 'ok'},
      rdap: {status: rdap.status || 'unavailable'},
      certificates: {status: sslRaw.status || 'unavailable'},
      http: {status: httpInfo.reachable ? 'ok' : 'unavailable'},
      urlscan: {status: urlscan.status || 'unavailable', httpStatus: urlscan.httpStatus},
    },
    coverage: { timersAvailable: typeof globalThis.setTimeout === 'function', checked: enginesChecked },
    inputUrl: target.inputUrl,
    normalizedUrl: target.normalizedUrl,
    finalUrl: effectiveFinalUrl,
    defangedUrl: defangUrl(effectiveFinalUrl),
    domain: effectiveDomain,
    hostname: effectiveHostname,
    urlHash: target.urlHash,
    riskScore,
    verdict,
    grade,
    enginesFlagged,
    enginesChecked,
    durationMs,
    cached: false,
    scannedAtIso: new Date().toISOString(),
    spoofAlert,
    categories: {
      threatIntel: Math.max(
        0,
        100 - Math.min(
          100,
          (vt.malicious * 35) +
          (gsb.flagged ? 80 : 0) +
          (urlscan.flagged ? 50 : 0) +
          (ipRep.ipqs?.flagged ? 50 : 0) +
          (iran.motmaenBashThreat ? 90 : 0) +
          (iran.apkMalwareHit ? 95 : 0)
        )
      ),
      domainTrust: iran.shaparakStatus === 'VERIFIED_SHAPARAK'
        ? 99
        : iran.shaparakStatus === 'FAKE_IRAN_BRAND'
          ? 8
          : rdap.ageDays !== null
            ? (rdap.ageDays > 365 ? 96 : rdap.ageDays > 60 ? 78 : rdap.ageDays > 14 ? 45 : 15)
            : (lexical.points > 25 ? 25 : 80),
      networkSsl: Math.min(100, (httpInfo.httpsEnforced ? 60 : 15) + (ssl.certsFound > 0 ? 25 : 0) + (dns.hasSpf || dns.hasDmarc ? 15 : 5)),
      httpHardening: httpInfo.reachable ? httpInfo.headerScore : (iran.shaparakStatus === 'VERIFIED_SHAPARAK' ? 85 : 50),
    },
    iran,
    engines: {
      virustotal: vt,
      safeBrowsing: gsb,
      urlscan,
      abuseIpDb: ipRep.abuseIpDb,
      ipqs: ipRep.ipqs,
    },
    infra: {
      ip: primaryIp,
      geo: ipRep.geo,
      dns,
      rdap,
      ssl,
    },
    http: httpInfo,
    lexical: {
      isShortener: lexical.isShortener,
      tld: lexical.tld,
      subdomainDepth: lexical.subdomainDepth,
      urlLength: lexical.urlLength,
    },
    findings,
  };

  let scanId = 0;
  try {
    const [saved] = await db.insert(scans)
      .values({
        tgId: Number(tgId || 0),
        inputUrl: target.inputUrl,
        normalizedUrl: target.normalizedUrl,
        finalUrl: effectiveFinalUrl,
        domain: effectiveDomain,
        urlHash: target.urlHash,
        riskScore,
        verdict,
        grade,
        enginesFlagged,
        enginesChecked,
        durationMs,
        report,
      })
      .returning()
      .run();
    scanId = saved?.id || 0;
  } catch (_) {
    // Allow running statelessly even before `npx tgcloud migrate`
  }

  if (tgId) {
    await recordUserScanStats(tgId, verdict === 'SUSPICIOUS' || verdict === 'MALICIOUS');
  }

  return { ok: true, scanId, report };
}
