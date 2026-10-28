import { fetch } from 'sdk';
import { withTimeout } from '../urlUtils.js';

// ============================================================================
// URLScan.io Threat Sandbox & Historical Intelligence Provider
// Uses public search immediately AND active unlisted scan submission with key!
// ============================================================================

export async function checkUrlScan(url, hostname, apiKey) {
  const headers = { Accept: 'application/json' };
  if (apiKey) headers['API-Key'] = apiKey;

  try {
    const searchUrl = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(`page.domain:${hostname}`)}&size=5`;
    const res = await withTimeout(
      fetch(searchUrl, { method: 'GET', headers }),
      5500,
      'URLScan timeout'
    );

    let historicalMalicious = 0;
    let latestScan = null;
    let screenshot = null;

    if (res.ok) {
      const json = await res.json();
      const results = Array.isArray(json?.results) ? json.results : [];
      for (const item of results) {
        if (!latestScan) {
          latestScan = {
            uuid: item._id,
            scannedAt: item.task?.time || null,
            country: item.page?.country || null,
            server: item.page?.server || null,
            ip: item.page?.ip || null,
            asnname: item.page?.asnname || null,
            tlsIssuer: item.page?.tlsIssuer || null,
            reportUrl: `https://urlscan.io/result/${item._id}/`,
          };
          screenshot = item.screenshot || `https://urlscan.io/screenshots/${item._id}.png`;
        }
        if (item.verdicts?.overall?.malicious || (item.verdicts?.overall?.score ?? 0) >= 50) {
          historicalMalicious++;
        }
      }
    }

    // If API key is configured and no recent scan exists, trigger an unlisted live sandbox scan!
    let submittedResultUrl = null;
    if (apiKey && !latestScan) {
      const subRes = await withTimeout(
        fetch('https://urlscan.io/api/v1/scan/', {
          method: 'POST',
          headers: { 'API-Key': apiKey, Accept: 'application/json' },
          body: fetch.body.json({ url, visibility: 'unlisted' }),
        }),
        4500,
        'URLScan submit timeout'
      ).catch(() => null);
      if (subRes && subRes.ok) {
        const subJson = await subRes.json();
        submittedResultUrl = subJson?.result || null;
      }
    }

    return {
      provider: 'URLScan.io',
      status: 'ok',
      mode: apiKey ? 'api_authenticated' : 'public_intel',
      flagged: historicalMalicious > 0,
      maliciousScans: historicalMalicious,
      latestScan,
      screenshot,
      submittedResultUrl,
    };
  } catch (err) {
    return {
      provider: 'URLScan.io',
      status: 'error',
      error: String(err?.message || err),
      flagged: false,
      maliciousScans: 0,
      latestScan: null,
      screenshot: null,
    };
  }
}
