import {
  safeTimeout,
  base64UrlNoPad,
  sha256HexPure,
  parseUrlPure,
  parseQueryEntriesPure,
} from './v8Runtime.js';

// ============================================================================
// Pure V8 URL Extraction, Normalization, SSRF Protection, Hashing & Heuristics
// 100% Pure ECMAScript — ZERO host globals (`URL`, `btoa`, `TextEncoder`, etc.)
// ============================================================================

const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
  'ac.ir', 'co.ir', 'gov.ir', 'id.ir', 'net.ir', 'org.ir', 'sch.ir',
  'com.ru', 'net.ru', 'org.ru', 'pp.ru',
  'com.au', 'net.au', 'org.au',
  'co.jp', 'com.br', 'com.tr', 'com.ua', 'co.in', 'com.cn', 'com.de',
]);

const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'cutt.ly', 'rb.gy', 'rebrand.ly', 'shorturl.at', 's.id', 'tiny.cc',
  'v.gd', 'bl.ink', 'clck.ru', 'vk.cc', 'yun.ir', 'b2n.ir', 'zaya.io', 'ril.ink',
]);

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'buzz', 'click', 'loan', 'work', 'gq', 'tk', 'ml', 'cf', 'ga',
  'icu', 'cfd', 'sbs', 'quest', 'rest', 'cam', 'monster', 'hair', 'makeup',
  'shop', 'vip', 'win', 'bid', 'zip', 'mov',
]);

const COMMON_BARE_TLDS = new Set([
  'com', 'org', 'net', 'io', 'co', 'ai', 'ir', 'ru', 'su', 'me', 'app', 'dev',
  'info', 'biz', 'xyz', 'top', 'online', 'site', 'shop', 'store', 'tech', 'cloud',
  'link', 'click', 'live', 'pro', 'tv', 'cc', 'gg', 'ly', 'gl', 'gd', 'gy', 'at',
  'id', 'ink', 'uk', 'de', 'fr', 'nl', 'eu', 'us', 'ca', 'au', 'in', 'jp', 'cn',
  'tr', 'ae', 'uz', 'kz', 'by', 'ua', 'ge', 'am', 'az', 'gov', 'edu', 'mil',
  'icu', 'cfd', 'sbs', 'buzz', 'loan', 'work', 'gq', 'tk', 'ml', 'cf', 'ga', 'vip', 'zip',
]);

const DANGEROUS_EXTENSIONS = [
  '.exe', '.scr', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.hta',
  '.js', '.jar', '.apk', '.dmg', '.pkg', '.iso', '.img', '.lnk', '.cpl',
];

const REDIRECT_PARAM_NAMES = new Set([
  'url', 'u', 'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnurl',
  'return_to', 'next', 'dest', 'destination', 'goto', 'out', 'target', 'continue', 'view',
]);

const PROTECTED_BRANDS = [
  { name: 'Telegram / Fragment', tokens: ['telegram', 'fragment', 'tonkeeper', 't-me'], legit: ['telegram.org', 't.me', 'fragment.com', 'tonkeeper.com', 'ton.org', 'tgcloud.ai'] },
  { name: 'Banking / Payment Gateway', tokens: ['shaparak', 'mellat', 'bmi-ir', 'blubank', 'samanbank', 'pasargad'], legit: ['shaparak.ir', 'behpardakht.com', 'bmi.ir', 'sb24.ir', 'blubank.com', 'bpi.ir', 'sep.ir', 'pec.ir'] },
  { name: 'Nobitex / Iranian Crypto', tokens: ['nobitex', 'wallex', 'ramzinex', 'bitpin'], legit: ['nobitex.ir', 'wallex.ir', 'ramzinex.com', 'bitpin.ir'] },
  { name: 'Digikala', tokens: ['digikala'], legit: ['digikala.com'] },
  { name: 'Sber / T-Bank / Gosuslugi', tokens: ['sberbank', 'gosuslugi', 'tinkoff', 'tbank', 'yoomoney'], legit: ['sberbank.ru', 'sber.ru', 'gosuslugi.ru', 'tbank.ru', 'tinkoff.ru', 'yoomoney.ru'] },
  { name: 'Yandex / VK', tokens: ['yandex', 'vkontakte'], legit: ['yandex.ru', 'yandex.com', 'ya.ru', 'vk.com'] },
  { name: 'PayPal', tokens: ['paypal'], legit: ['paypal.com', 'paypalobjects.com'] },
  { name: 'Binance / Crypto Wallet', tokens: ['binance', 'metamask', 'trustwallet', 'coinbase'], legit: ['binance.com', 'metamask.io', 'trustwallet.com', 'coinbase.com'] },
  { name: 'Google / Gmail', tokens: ['google', 'gmail', 'googleaccount'], legit: ['google.com', 'googleapis.com', 'googleusercontent.com', 'gmail.com', 'youtube.com', 'youtu.be'] },
  { name: 'Microsoft / Office365', tokens: ['microsoft', 'office365', 'onedrive', 'outlook'], legit: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'sharepoint.com', 'github.com'] },
  { name: 'Apple iCloud', tokens: ['icloud', 'appleid'], legit: ['apple.com', 'icloud.com'] },
  { name: 'Steam', tokens: ['steamcommunity', 'steampowered'], legit: ['steamcommunity.com', 'steampowered.com'] },
];

export function withTimeout(promise, ms = 6500, label = 'Timeout') {
  return safeTimeout(promise, ms, label);
}

export function utf8ToBase64UrlNoPad(str) {
  return base64UrlNoPad(str);
}

export function sha256Hex(message) {
  return sha256HexPure(message);
}

// Strips invisible RTL/LTR/ZWNJ chars & refangs obfuscated URLs (`hxxps://foo[.]com`)
export function refangUrl(raw) {
  return String(raw || '')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '')
    .trim()
    .replace(/^[<«"“'‘(\[]+|[>»"”'’)\]]+$/g, '')
    .replace(/hxxps:\/\//gi, 'https://')
    .replace(/hxxp:\/\//gi, 'http://')
    .replace(/\[\s*https\s*\]\s*:\s*\/\//gi, 'https://')
    .replace(/\[\s*http\s*\]\s*:\s*\/\//gi, 'http://')
    .replace(/\[(\.|:)\]/g, '$1')
    .replace(/\((\.|:)\)/g, '$1')
    .replace(/\{(\.|:)\}/g, '$1')
    .replace(/\[:\/\/\]/g, '://');
}

export function defangUrl(urlStr) {
  return String(urlStr || '')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/\./g, '[.]');
}

export function getRegistrableDomain(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/\.$/, '');
  if (!host || isRawIp(host)) return host;
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const last2 = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_TLDS.has(last2) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${last2}`;
  }
  return last2;
}

export function isRawIp(hostname) {
  const clean = String(hostname || '').replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return true;
  if (clean.includes(':')) return true;
  return false;
}

export function isPrivateOrReservedHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '').trim();
  if (!h) return true;
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.lan')) {
    return true;
  }
  if (h === '::1' || h === '0:0:0:0:0:0:0:1' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) {
    return true;
  }
  const ipv4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4) {
    const [, a, b] = ipv4.map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

function cleanCandidateToken(rawToken) {
  return refangUrl(rawToken)
    .replace(/[),.;!?،؛؟»"'\]}>]+$/g, '')
    .trim();
}

function scanEntitiesAndText(text, entities, candidates, spoofState) {
  const rawText = String(text || '');
  const ents = Array.isArray(entities) ? entities : [];
  let workingText = rawText;

  for (const ent of ents) {
    if (!ent) continue;
    if (ent.type === 'text_link' && ent.url) {
      const visibleSlice = rawText.slice(ent.offset, ent.offset + ent.length).trim();
      const actualClean = cleanCandidateToken(ent.url);
      if (actualClean) {
        const looksLikeDomain = /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i.test(visibleSlice);
        if (looksLikeDomain && !spoofState.alert) {
          const shownParsed = parseUrlPure(/^https?:\/\//i.test(visibleSlice) ? visibleSlice : `https://${visibleSlice}`);
          const realParsed = parseUrlPure(/^https?:\/\//i.test(actualClean) ? actualClean : `https://${actualClean}`);
          if (shownParsed && realParsed) {
            const shownReg = getRegistrableDomain(shownParsed.hostname);
            const realReg = getRegistrableDomain(realParsed.hostname);
            if (shownReg && realReg && shownReg !== realReg) {
              spoofState.alert = { shown: visibleSlice, actual: actualClean };
            }
          }
        }
        candidates.push(actualClean);
      }
    } else if (ent.type === 'url') {
      const slice = cleanCandidateToken(rawText.slice(ent.offset, ent.offset + ent.length));
      if (slice) candidates.push(slice);
    }

    // Blank out already-extracted entity spans so regex passes never split subdomains inside them!
    if (
      (ent.type === 'text_link' || ent.type === 'url') &&
      typeof ent.offset === 'number' &&
      typeof ent.length === 'number' &&
      ent.offset >= 0 &&
      ent.length > 0
    ) {
      workingText =
        workingText.slice(0, ent.offset) +
        ' '.repeat(ent.length) +
        workingText.slice(ent.offset + ent.length);
    }
  }

  // Scan remaining text for explicit `http(s)://...` URLs first, blanking them out before `bareRegex` runs!
  let normalizedBody = workingText
    .replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '')
    .replace(/hxxps:\/\//gi, 'https://')
    .replace(/hxxp:\/\//gi, 'http://')
    .replace(/\[(\.|:)\]/g, '$1')
    .replace(/\((\.|:)\)/g, '$1');

  normalizedBody = normalizedBody.replace(/https?:\/\/[^\s<>«»"“”'‘’`]+/gi, (m) => {
    const c = cleanCandidateToken(m);
    if (c) candidates.push(c);
    return ' '.repeat(m.length);
  });

  // Strict boundary excludes `:`, `/`, `.`, `@`, `_`, `-` so subdomains/paths are NEVER split into multiple URLs!
  const bareRegex = /(?:^|[^a-z0-9@/:._-])((?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,24})(?::\d{2,5})?(?:\/[^\s<>«»"“”'‘’`]*)?)/gi;
  let match;
  while ((match = bareRegex.exec(normalizedBody)) !== null) {
    const token = cleanCandidateToken(match[1]);
    if (!token) continue;
    const hostPart = token.split('/')[0].split(':')[0].toLowerCase();
    const tld = hostPart.split('.').pop() || '';
    if (COMMON_BARE_TLDS.has(tld) || tld.startsWith('xn--')) {
      candidates.push(token);
    }
  }
}

function collectButtonUrls(replyMarkup, candidates) {
  const rows = replyMarkup?.inline_keyboard;
  if (!Array.isArray(rows)) return;
  for (const row of rows) {
    if (!Array.isArray(row)) continue;
    for (const btn of row) {
      if (btn?.url) candidates.push(cleanCandidateToken(btn.url));
      if (btn?.web_app?.url) candidates.push(cleanCandidateToken(btn.web_app.url));
      if (btn?.login_url?.url) candidates.push(cleanCandidateToken(btn.login_url.url));
    }
  }
}

// Universal Link Extractor across ALL Telegram Message & Forwarded Post structures:
// text, caption, entities, caption_entities, quote, link_preview_options,
// external_reply, inline_keyboard URL buttons, and reply_to_message!
export function extractLinksFromMessage(message) {
  if (!message || typeof message !== 'object') {
    return { urls: [], spoofAlert: null };
  }

  const candidates = [];
  const spoofState = { alert: null };

  // 1. Primary text + entities
  if (message.text || message.entities) {
    scanEntitiesAndText(message.text || '', message.entities || [], candidates, spoofState);
  }

  // 2. Media caption + caption_entities (forwarded photos, videos, APKs, documents, etc.)
  if (message.caption || message.caption_entities) {
    scanEntitiesAndText(message.caption || '', message.caption_entities || [], candidates, spoofState);
  }

  // 3. Quoted excerpt (`message.quote`)
  if (message.quote?.text || message.quote?.entities) {
    scanEntitiesAndText(message.quote.text || '', message.quote.entities || [], candidates, spoofState);
  }

  // 4. Hidden / explicit link preview URLs (`link_preview_options` & `external_reply`)
  if (message.link_preview_options?.url) {
    candidates.push(cleanCandidateToken(message.link_preview_options.url));
  }
  if (message.external_reply?.link_preview_options?.url) {
    candidates.push(cleanCandidateToken(message.external_reply.link_preview_options.url));
  }

  // 5. Inline URL buttons inside forwarded channel/bot posts (`reply_markup.inline_keyboard`)
  collectButtonUrls(message.reply_markup, candidates);

  // 6. Fallback: if user replied directly to another message containing a link
  if (candidates.length === 0 && message.reply_to_message) {
    const rep = message.reply_to_message;
    if (rep.text || rep.entities) {
      scanEntitiesAndText(rep.text || '', rep.entities || [], candidates, spoofState);
    }
    if (rep.caption || rep.caption_entities) {
      scanEntitiesAndText(rep.caption || '', rep.caption_entities || [], candidates, spoofState);
    }
    if (rep.link_preview_options?.url) {
      candidates.push(cleanCandidateToken(rep.link_preview_options.url));
    }
    collectButtonUrls(rep.reply_markup, candidates);
  }

  // Validate & deduplicate preserving order
  const seenNorm = new Set();
  const urls = [];
  for (const rawCandidate of candidates) {
    if (!rawCandidate) continue;
    const parsedCheck = parseAndValidateTarget(rawCandidate);
    if (parsedCheck.valid) {
      if (!seenNorm.has(parsedCheck.normalizedUrl)) {
        seenNorm.add(parsedCheck.normalizedUrl);
        urls.push(rawCandidate);
      }
    } else if (parsedCheck.error === 'PRIVATE_TARGET') {
      if (!seenNorm.has(rawCandidate)) {
        seenNorm.add(rawCandidate);
        urls.push(rawCandidate);
      }
    }
  }

  return { urls, spoofAlert: spoofState.alert };
}

export function parseAndValidateTarget(rawInput) {
  const refanged = refangUrl(rawInput);
  if (!refanged) {
    return { valid: false, error: 'EMPTY' };
  }
  const withProto = /^[a-z][a-z0-9+.-]*:\/\//i.test(refanged) ? refanged : `https://${refanged}`;
  const parsed = parseUrlPure(withProto);
  if (!parsed) {
    return { valid: false, error: 'INVALID_URL' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'UNSUPPORTED_PROTOCOL' };
  }
  if (!parsed.hostname || (!parsed.hostname.includes('.') && !isRawIp(parsed.hostname))) {
    return { valid: false, error: 'INVALID_HOST' };
  }
  if (isPrivateOrReservedHost(parsed.hostname)) {
    return { valid: false, error: 'PRIVATE_TARGET' };
  }

  const normalizedUrl = parsed.href;
  const hostname = parsed.hostname.toLowerCase();
  const registrableDomain = getRegistrableDomain(hostname);

  return {
    valid: true,
    inputUrl: String(rawInput).trim(),
    normalizedUrl,
    defanged: defangUrl(normalizedUrl),
    protocol: parsed.protocol,
    hostname,
    registrableDomain,
    pathname: parsed.pathname,
    search: parsed.search,
    hasUserInfo: Boolean(parsed.username || parsed.password),
    port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    urlHash: sha256HexPure(normalizedUrl),
    vtUrlId: base64UrlNoPad(normalizedUrl),
  };
}

export function runLexicalHeuristics(targetInfo, spoofAlert = null) {
  const findings = [];
  let lexicalPoints = 0;

  if (spoofAlert) {
    findings.push({
      code: 'SPOOFED_ENTITY',
      severity: 'critical',
      weight: 55,
      params: { shown: spoofAlert.shown, actual: spoofAlert.actual },
    });
    lexicalPoints += 55;
  }

  const { hostname, registrableDomain, protocol, pathname, search, hasUserInfo } = targetInfo;
  const parts = hostname.split('.');
  const tld = parts[parts.length - 1] || '';

  if (hasUserInfo) {
    findings.push({ code: 'USERINFO_TRICK', severity: 'high', weight: 35 });
    lexicalPoints += 35;
  }

  if (isRawIp(hostname)) {
    findings.push({ code: 'RAW_IP_HOST', severity: 'high', weight: 30 });
    lexicalPoints += 30;
  }

  if (hostname.includes('xn--')) {
    findings.push({ code: 'PUNYCODE_HOMOGRAPH', severity: 'high', weight: 28 });
    lexicalPoints += 28;
  }

  if (protocol === 'http:') {
    findings.push({ code: 'NO_HTTPS', severity: 'medium', weight: 15 });
    lexicalPoints += 15;
  }

  if (SHORTENER_DOMAINS.has(registrableDomain)) {
    findings.push({ code: 'URL_SHORTENER', severity: 'low', weight: 8 });
    lexicalPoints += 8;
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    findings.push({ code: 'SUSPICIOUS_TLD', severity: 'medium', weight: 14, params: { tld } });
    lexicalPoints += 14;
  }

  const lowerPath = pathname.toLowerCase();
  for (const ext of DANGEROUS_EXTENSIONS) {
    if (lowerPath.endsWith(ext)) {
      findings.push({ code: 'DANGEROUS_EXTENSION', severity: 'high', weight: 32, params: { ext } });
      lexicalPoints += 32;
      break;
    }
  }

  const normalizedFull = `${hostname}${pathname}`.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l');
  for (const brand of PROTECTED_BRANDS) {
    if (brand.legit.includes(registrableDomain)) continue;
    const hit = brand.tokens.find((tok) => normalizedFull.includes(tok));
    if (hit) {
      findings.push({
        code: 'BRAND_TYPOSQUAT',
        severity: 'high',
        weight: 38,
        params: { brand: brand.name },
      });
      lexicalPoints += 38;
      break;
    }
  }

  if (search) {
    const entries = parseQueryEntriesPure(search);
    for (const [k, v] of entries) {
      if (REDIRECT_PARAM_NAMES.has(k.toLowerCase()) && /^(https?:)?\/\//i.test(v)) {
        findings.push({
          code: 'OPEN_REDIRECT_PARAM',
          severity: 'medium',
          weight: 16,
          params: { param: k },
        });
        lexicalPoints += 16;
        break;
      }
    }
  }

  return {
    points: Math.min(85, lexicalPoints),
    isShortener: SHORTENER_DOMAINS.has(registrableDomain),
    tld,
    subdomainDepth: Math.max(0, parts.length - registrableDomain.split('.').length),
    urlLength: targetInfo.normalizedUrl.length,
    findings,
  };
}
