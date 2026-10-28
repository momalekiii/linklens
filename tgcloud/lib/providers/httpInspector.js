import { fetch } from 'sdk';
import { getRegistrableDomain, withTimeout } from '../urlUtils.js';
import { parseUrlPure, utf8Encode, utf8Decode, sha256HexPure } from '../v8Runtime.js';

// ============================================================================
// Live HTTP Unshortener, OWASP Security Headers, Binary SHA-256 & DOM Scanner
// 100% Pure V8 Isolate Compatible — Zero AbortController, TextDecoder or WebCrypto!
// ============================================================================

const SECURITY_HEADERS = [
  { key: 'strict-transport-security', label: 'HSTS', points: 25 },
  { key: 'content-security-policy', label: 'CSP', points: 25 },
  { key: 'x-frame-options', label: 'X-Frame-Options', points: 15 },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', points: 15 },
  { key: 'referrer-policy', label: 'Referrer-Policy', points: 10 },
  { key: 'permissions-policy', label: 'Permissions-Policy', points: 10 },
];

const MAX_BINARY_HASH_BYTES = 10 * 1024 * 1024; // Stream-hash APK/DEX binaries up to 10 MB

export async function inspectHttpAndDom(normalizedUrl, initialDomain) {
  const started = Date.now();
  try {
    const res = await withTimeout(
      fetch(normalizedUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; LinkLensSecurityScanner/1.2)',
          Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'fa-IR,fa;q=0.9,en-US;q=0.8,ru;q=0.7',
        },
      }),
      4200,
      'HTTP probe timeout'
    );

    const latencyMs = Date.now() - started;
    const finalUrl = res.url || normalizedUrl;
    let finalDomain = initialDomain;
    let finalHostname = initialDomain;
    let finalProtocol = 'https:';
    let finalPathname = '/';

    const parsedFinal = parseUrlPure(finalUrl);
    if (parsedFinal) {
      finalHostname = parsedFinal.hostname.toLowerCase();
      finalDomain = getRegistrableDomain(finalHostname);
      finalProtocol = parsedFinal.protocol;
      finalPathname = parsedFinal.pathname || '/';
    }

    const presentHeaders = [];
    const missingHeaders = [];
    let headerScore = 0;

    for (const h of SECURITY_HEADERS) {
      const val = res.headers.get(h.key);
      if (val) {
        presentHeaders.push({ name: h.label, value: String(val).slice(0, 90) });
        headerScore += h.points;
      } else {
        missingHeaders.push(h.label);
      }
    }

    const cspVal = res.headers.get('content-security-policy') || '';
    if (!res.headers.get('x-frame-options') && /frame-ancestors/i.test(cspVal)) {
      headerScore = Math.min(100, headerScore + 15);
      const idx = missingHeaders.indexOf('X-Frame-Options');
      if (idx !== -1) missingHeaders.splice(idx, 1);
    }

    const headerGrade =
      headerScore >= 85 ? 'A+' :
      headerScore >= 70 ? 'A' :
      headerScore >= 55 ? 'B' :
      headerScore >= 35 ? 'C' :
      headerScore >= 15 ? 'D' : 'F';

    const contentType = res.headers.get('content-type') || '';
    const contentDisposition = res.headers.get('content-disposition') || '';
    const serverHeader = res.headers.get('server') || null;

    const isBinaryApkOrPayload =
      /android\.package-archive|octet-stream|application\/zip/i.test(contentType) ||
      /\.(apk|xapk|dex|exe|msi|scr)\b/i.test(finalPathname) ||
      /\.(apk|xapk|dex|exe)\b/i.test(contentDisposition);

    let payloadSha256 = null;
    let payloadBytes = 0;

    let domSignals = {
      title: null,
      hasPasswordInput: false,
      hasExternalFormAction: false,
      hasHiddenIframe: false,
      hasObfuscatedJs: false,
      hasClickFixTrap: false,
      hasCryptoDrainer: false,
      hasIranCardSkimmer: false,
      hasIranGovApkLure: false,
      metaRefreshRedirect: null,
      externalScriptsCount: 0,
    };

    if (/text\/html|application\/xhtml/i.test(contentType) && !isBinaryApkOrPayload) {
      let snippet = '';
      if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
        for await (const chunk of res.body) {
          snippet += typeof chunk === 'string' ? chunk : utf8Decode(chunk);
          if (snippet.length >= 131072) break;
        }
      } else {
        snippet = (await res.text()).slice(0, 131072);
      }
      domSignals = analyzeHtmlSnippet(snippet, finalDomain, finalHostname, finalProtocol);
    } else if (isBinaryApkOrPayload && res.ok) {
      try {
        const chunks = [];
        let total = 0;
        let withinCap = true;
        if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') {
          for await (const chunk of res.body) {
            const bytes = chunk instanceof Uint8Array ? chunk : utf8Encode(String(chunk));
            total += bytes.byteLength;
            if (total > MAX_BINARY_HASH_BYTES) {
              withinCap = false;
              break;
            }
            chunks.push(bytes);
          }
        } else if (typeof res.arrayBuffer === 'function') {
          const buf = new Uint8Array(await res.arrayBuffer());
          if (buf.byteLength <= MAX_BINARY_HASH_BYTES) {
            chunks.push(buf);
            total = buf.byteLength;
          } else {
            withinCap = false;
          }
        }
        if (withinCap && total > 0) {
          const full = new Uint8Array(total);
          let offset = 0;
          for (const c of chunks) {
            full.set(c, offset);
            offset += c.byteLength;
          }
          payloadSha256 = sha256HexPure(full);
          payloadBytes = total;
        }
      } catch (_) {
        // Ignore stream abort on large binary payloads
      }
    }

    const redirected = finalUrl.replace(/\/$/, '') !== normalizedUrl.replace(/\/$/, '');
    const crossDomainRedirect = redirected && finalDomain !== initialDomain;

    return {
      reachable: true,
      httpStatus: res.status,
      latencyMs,
      finalUrl,
      finalDomain,
      finalHostname,
      httpsEnforced: finalProtocol === 'https:',
      redirected,
      crossDomainRedirect,
      contentType: contentType.split(';')[0].trim() || 'unknown',
      payloadSha256,
      payloadBytes,
      server: serverHeader,
      headerScore,
      headerGrade,
      presentHeaders,
      missingHeaders,
      dom: domSignals,
    };
  } catch (err) {
    return {
      reachable: false,
      error: String(err?.message || err),
      latencyMs: Date.now() - started,
      finalUrl: normalizedUrl,
      finalDomain: initialDomain,
      finalHostname: initialDomain,
      httpsEnforced: normalizedUrl.startsWith('https://'),
      redirected: false,
      crossDomainRedirect: false,
      contentType: 'unreachable',
      payloadSha256: null,
      payloadBytes: 0,
      server: null,
      headerScore: 0,
      headerGrade: 'N/A',
      presentHeaders: [],
      missingHeaders: SECURITY_HEADERS.map((h) => h.label),
      dom: {},
    };
  }
}

export function analyzeHtmlSnippet(html, pageDomain, finalHostname = '', finalProtocol = 'https:') {
  const titleMatch = html.match(/<title[^>]*>([\s\S]{1,140}?)<\/title>/i);
  const title = titleMatch ? titleMatch[1].replace(/\s+/g, ' ').trim() : null;

  const hasPasswordInput = /<input[^>]+type\s*=\s*["']?password["']?/i.test(html);
  const hasHiddenIframe = /<iframe[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?[01]["']?\s+height\s*=\s*["']?[01]["']?)/i.test(html);
  const hasObfuscatedJs = /(?:eval\s*\(\s*(?:atob|unescape|function\s*\(p,a,c,k,e)|String\.fromCharCode\s*\((?:[^)]{40,})\))/i.test(html);

  const hasClickFixTrap = /(?:powershell(?:\.exe)?\s+-(?:w\s+hidden|enc|e\s)|mshta(?:\.exe)?\s+https?:|Win\s*\+\s*R[\s\S]{0,120}(?:Ctrl\s*\+\s*V|paste))/i.test(html);

  const hasCryptoDrainer = /(?:eth_sendTransaction|eth_signTypedData_v4|seaport|setApprovalForAll)/i.test(html)
    && !['opensea.io', 'uniswap.org', 'metamask.io', '1inch.io', 'aave.com'].includes(pageDomain);

  const isOfficialShaparak = finalProtocol === 'https:' && /^[a-z0-9-]+\.shaparak\.ir$/i.test(finalHostname);
  const hasShetabCardField = /(?:شماره\s*کارت|کارت\s*بانکی)/i.test(html);
  const hasCvv2AndDynamicPin = /cvv2/i.test(html) && /(?:رمز\s*دوم|رمز\s*پویا|درخواست\s*رمز)/i.test(html);
  const hasIranCardSkimmer = !isOfficialShaparak && hasShetabCardField && hasCvv2AndDynamicPin;

  const isOfficialIranGov = /\.(?:gov\.ir|adliran\.ir|post\.ir|police\.ir)$/i.test(finalHostname) || /^(?:adliran\.ir|post\.ir)$/i.test(finalHostname);
  const mentionsIranGovLure = /(?:ابلاغیه\s*(?:الکترونیک|قضایی|ثنا)?|سامانه\s*ثنا|قوه\s*قضاییه|سهام\s*عدالت|یارانه\s*معیشتی|مرسوله\s*پستی)/i.test(html);
  const pushesApkOrSmallFee = /(?:\.apk["'\s>?]|دانلود\s*(?:برنامه|اپلیکیشن)|۵,?۰۰۰\s*تومان|5,?000\s*تومان|۲۰,?۰۰۰\s*تومان|هزینه\s*تمبر)/i.test(html);
  const hasIranGovApkLure = !isOfficialIranGov && mentionsIranGovLure && pushesApkOrSmallFee;

  let hasExternalFormAction = false;
  const formMatches = html.matchAll(/<form[^>]+action\s*=\s*["'](https?:\/\/[^"']+)["']/gi);
  for (const m of formMatches) {
    const parsedAction = parseUrlPure(m[1]);
    if (parsedAction) {
      const formHost = getRegistrableDomain(parsedAction.hostname);
      if (formHost && formHost !== pageDomain) {
        hasExternalFormAction = true;
        break;
      }
    }
  }

  const refreshMatch = html.match(/<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+url\s*=\s*([^"'>\s]+)/i);
  const scriptMatches = html.match(/<script[^>]+src\s*=/gi) || [];

  return {
    title,
    hasPasswordInput,
    hasExternalFormAction,
    hasHiddenIframe,
    hasObfuscatedJs,
    hasClickFixTrap,
    hasCryptoDrainer,
    hasIranCardSkimmer,
    hasIranGovApkLure,
    metaRefreshRedirect: refreshMatch ? refreshMatch[1] : null,
    externalScriptsCount: scriptMatches.length,
  };
}
