// ============================================================================
// Pure ECMAScript (ES2022) V8 Isolate Runtime Utilities
// Uses EXCLUSIVELY core V8 intrinsics (String, RegExp, Array, Uint8Array,
// Uint32Array, DataView, Math, Date, Promise, JSON, encodeURIComponent).
// ZERO dependency on host APIs: NO `URL`, NO `URLSearchParams`, NO `btoa`,
// NO `TextEncoder`, NO `TextDecoder`, NO `crypto.subtle`, NO `AbortController`!
// ============================================================================

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function safeTimeout(promise, ms = 6000, label = 'Timeout') {
  const g = typeof globalThis !== 'undefined' ? globalThis : {};
  if (typeof g.setTimeout !== 'function') {
    return Promise.resolve(promise);
  }
  let timer;
  const race = new Promise((_, reject) => {
    timer = g.setTimeout(() => reject(new Error(label)), ms);
  });
  return Promise.race([Promise.resolve(promise), race]).finally(() => {
    if (typeof g.clearTimeout === 'function' && timer) {
      g.clearTimeout(timer);
    }
  });
}


// Resolve to `fallback` on rejection or after `ms` — a scan stage must never
// hang or abort because one external source is slow or unreachable.
export function withFallback(promise, fallback, ms = 8000) {
  const g = typeof globalThis !== 'undefined' ? globalThis : {};
  const settled = Promise.resolve(promise).catch(() => fallback);
  if (typeof g.setTimeout !== 'function') return settled;
  let timer;
  const deadline = new Promise((resolve) => {
    timer = g.setTimeout(() => resolve(fallback), ms);
  });
  return Promise.race([settled, deadline]).finally(() => {
    if (typeof g.clearTimeout === 'function' && timer) g.clearTimeout(timer);
  });
}

// Pure JS UTF-8 String -> Uint8Array (handles full Unicode BMP + Astral planes)
export function utf8Encode(str) {
  const s = String(str ?? '');
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let code = s.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < s.length) {
      const low = s.charCodeAt(i + 1);
      if (low >= 0xdc00 && low <= 0xdfff) {
        code = ((code - 0xd800) << 10) + (low - 0xdc00) + 0x10000;
        i++;
      }
    }
    if (code < 0x80) {
      out.push(code);
    } else if (code < 0x800) {
      out.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      out.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      out.push(
        0xf0 | (code >> 18),
        0x80 | ((code >> 12) & 0x3f),
        0x80 | ((code >> 6) & 0x3f),
        0x80 | (code & 0x3f)
      );
    }
  }
  return new Uint8Array(out);
}

// Pure JS Uint8Array -> UTF-8 String (for HTML DOM inspection without TextDecoder)
export function utf8Decode(bytes) {
  if (typeof bytes === 'string') return bytes;
  if (!(bytes instanceof Uint8Array)) return String(bytes ?? '');
  const chunks = [];
  let current = [];
  const len = bytes.length;
  let i = 0;
  while (i < len) {
    const b0 = bytes[i++];
    let cp;
    if (b0 < 0x80) {
      cp = b0;
    } else if ((b0 & 0xe0) === 0xc0 && i < len) {
      cp = ((b0 & 0x1f) << 6) | (bytes[i++] & 0x3f);
    } else if ((b0 & 0xf0) === 0xe0 && i + 1 < len) {
      cp = ((b0 & 0x0f) << 12) | ((bytes[i++] & 0x3f) << 6) | (bytes[i++] & 0x3f);
    } else if ((b0 & 0xf8) === 0xf0 && i + 2 < len) {
      cp =
        ((b0 & 0x07) << 18) |
        ((bytes[i++] & 0x3f) << 12) |
        ((bytes[i++] & 0x3f) << 6) |
        (bytes[i++] & 0x3f);
    } else {
      cp = 0xfffd;
    }
    if (cp <= 0xffff) {
      current.push(cp);
    } else {
      cp -= 0x10000;
      current.push(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
    }
    if (current.length >= 4096) {
      chunks.push(String.fromCharCode(...current));
      current = [];
    }
  }
  if (current.length) chunks.push(String.fromCharCode(...current));
  return chunks.join('');
}

// Pure JS Base64 & Base64URL (no padding) without `btoa`
export function base64UrlNoPad(input) {
  const bytes = input instanceof Uint8Array ? input : utf8Encode(String(input ?? ''));
  let result = '';
  const len = bytes.length;
  for (let i = 0; i < len; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < len ? bytes[i + 1] : 0;
    const b2 = i + 2 < len ? bytes[i + 2] : 0;
    result += BASE64_CHARS[b0 >> 2];
    result += BASE64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
    if (i + 1 < len) result += BASE64_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)];
    if (i + 2 < len) result += BASE64_CHARS[b2 & 0x3f];
  }
  return result.replace(/\+/g, '-').replace(/\//g, '_');
}

// Pure JS FIPS 180-4 SHA-256 accepting BOTH String and Uint8Array
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

export function sha256HexPure(input) {
  const msgBytes = input instanceof Uint8Array ? input : utf8Encode(String(input ?? ''));
  const bitLen = msgBytes.length * 8;
  const padLen = (msgBytes.length + 9 + 63) & ~63;
  const buf = new Uint8Array(padLen);
  buf.set(msgBytes);
  buf[msgBytes.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  view.setUint32(padLen - 4, bitLen >>> 0, false);

  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);

  for (let offset = 0; offset < padLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K256[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
  }

  return [h0, h1, h2, h3, h4, h5, h6, h7]
    .map((v) => v.toString(16).padStart(8, '0'))
    .join('');
}

// Pure JS RFC-3986 HTTP(S) URL Parser (replaces `new URL(...)` everywhere in V8 isolates!)
export function parseUrlPure(rawUrl) {
  const input = String(rawUrl ?? '').trim();
  const m = input.match(/^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(\/[^?#]*)?(\?[^#]*)?(#.*)?$/i);
  if (!m) return null;

  const protocol = `${m[1].toLowerCase()}:`;
  const authority = m[2] || '';
  if (!authority) return null;

  let username = '';
  let password = '';
  let hostPort = authority;
  const atIdx = authority.lastIndexOf('@');
  if (atIdx !== -1) {
    const userInfo = authority.slice(0, atIdx);
    hostPort = authority.slice(atIdx + 1);
    const colonIdx = userInfo.indexOf(':');
    if (colonIdx !== -1) {
      username = userInfo.slice(0, colonIdx);
      password = userInfo.slice(colonIdx + 1);
    } else {
      username = userInfo;
    }
  }

  let hostname = '';
  let port = '';
  if (hostPort.startsWith('[')) {
    const closeBracket = hostPort.indexOf(']');
    if (closeBracket === -1) return null;
    hostname = hostPort.slice(0, closeBracket + 1).toLowerCase();
    const rest = hostPort.slice(closeBracket + 1);
    if (rest.startsWith(':')) port = rest.slice(1);
  } else {
    const colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx !== -1) {
      hostname = hostPort.slice(0, colonIdx).toLowerCase();
      port = hostPort.slice(colonIdx + 1);
    } else {
      hostname = hostPort.toLowerCase();
    }
  }

  if (!hostname || (port && !/^\d{1,5}$/.test(port))) return null;
  if ((protocol === 'https:' && port === '443') || (protocol === 'http:' && port === '80')) {
    port = '';
  }

  const pathname = m[3] || '/';
  const search = m[4] || '';
  const hash = m[5] || '';
  const host = port ? `${hostname}:${port}` : hostname;
  const authPrefix = username
    ? `${username}${password ? `:${password}` : ''}@`
    : '';
  const href = `${protocol}//${authPrefix}${host}${pathname}${search}${hash}`;

  return {
    protocol,
    username,
    password,
    hostname,
    port,
    host,
    origin: `${protocol}//${host}`,
    pathname,
    search,
    hash,
    href,
    toString() {
      return href;
    },
  };
}

// Pure JS Query String Parser (replaces `new URLSearchParams(search)`)
export function parseQueryEntriesPure(search) {
  const s = String(search || '').replace(/^\?/, '');
  if (!s) return [];
  const entries = [];
  for (const part of s.split('&')) {
    if (!part) continue;
    const eqIdx = part.indexOf('=');
    const rawK = eqIdx === -1 ? part : part.slice(0, eqIdx);
    const rawV = eqIdx === -1 ? '' : part.slice(eqIdx + 1);
    let k = rawK.replace(/\+/g, ' ');
    let v = rawV.replace(/\+/g, ' ');
    try { k = decodeURIComponent(k); } catch (_) {}
    try { v = decodeURIComponent(v); } catch (_) {}
    entries.push([k, v]);
  }
  return entries;
}

// Lazy execution is essential: never start unbounded network work in an isolate
// without a usable deadline. Fail closed to an explicitly limited assessment.
export function boundedLayer(start, fallback, ms = 2000) {
  if (typeof globalThis.setTimeout !== 'function') {
    // Telegram's SDK owns request execution in timerless isolates. Do not silently
    // disable functional sources merely because browser timers are absent.
    return Promise.resolve().then(start).catch(() => fallback);
  }
  try { return withFallback(Promise.resolve().then(start), fallback, ms); }
  catch (_) { return Promise.resolve(fallback); }
}
