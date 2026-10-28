// ============================================================================
// Dual-Mode Transport Layer:
// 1. Production Telegram Serverless Mini App (`https://app<id>.tgcloud.ai`):
//    Uses native `Telegram.WebApp.Serverless.call(name, input, callback)` with
//    automatic fallback to direct `POST /api/<name>` (`Authorization: TMA ...`).
// 2. Local Studio / Arena Live Preview (`localhost`, `127.0.0.1`, `*.e2b.app`):
//    Uses relative `POST /api/<name>` + live Bot Simulator (`/sim/*`).
// ============================================================================

export function isStudioPreviewHost() {
  const host = String(window.location?.hostname || '').toLowerCase();
  if (host.endsWith('.tgcloud.ai')) return false;
  return (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host.endsWith('.e2b.app') ||
    host.endsWith('.local')
  );
}

export function isRealTelegramServerless() {
  const tg = window.Telegram?.WebApp;
  if (tg && tg.initData && typeof tg.Serverless?.call === 'function') {
    return true;
  }
  return !isStudioPreviewHost();
}

export function triggerHaptic(type = 'light') {
  try {
    const hf = window.Telegram?.WebApp?.HapticFeedback;
    if (!hf) return;
    if (type === 'success' || type === 'warning' || type === 'error') {
      hf.notificationOccurred(type);
    } else {
      hf.impactOccurred(type);
    }
  } catch (_) {
    // ignore outside Telegram client
  }
}

export function callEndpoint(name, input = {}) {
  const tg = window.Telegram?.WebApp;
  if (tg && tg.initData && typeof tg.Serverless?.call === 'function') {
    return new Promise((resolve, reject) => {
      tg.Serverless.call(name, input, (err, result) => {
        if (err) {
          reject(new Error(err.message || 'Endpoint error'));
          return;
        }
        resolve(result);
      });
    });
  }

  const headers = { 'Content-Type': 'application/json' };
  if (tg?.initData) {
    try {
      headers.Authorization = `TMA ${window.btoa(tg.initData)}`;
    } catch (_) {
      // ignore non-ASCII fallback
    }
  }

  return fetch(`/api/${encodeURIComponent(name)}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(input || {}),
  }).then(async (res) => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.ok === false) {
      throw new Error(data.description || data.error || `HTTP ${res.status}`);
    }
    return data.result !== undefined ? data.result : data;
  });
}

// Simulator API Helpers (active solely in Studio Preview mode)
export async function simAction(path, payload = {}) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  return res.json();
}
