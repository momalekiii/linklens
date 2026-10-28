import { fetch } from 'sdk';
import { utf8ToBase64UrlNoPad, withTimeout } from '../urlUtils.js';

// ============================================================================
// VirusTotal API v3 Provider — 90+ Antivirus & Malicious URL Engines
// Endpoint: https://www.virustotal.com/api/v3/urls/{url_id}
// ============================================================================

export async function checkVirusTotal(url, apiKey) {
  if (!apiKey) {
    return {
      provider: 'VirusTotal v3',
      status: 'unconfigured',
      flagged: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      totalEngines: 0,
      note: 'Standby',
    };
  }

  const urlId = utf8ToBase64UrlNoPad(url);
  const headers = { 'x-apikey': apiKey, Accept: 'application/json' };

  try {
    let res = await withTimeout(
      fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, { method: 'GET', headers }),
      6500,
      'VT lookup timeout'
    );

    // If never scanned before on VT, submit for fresh scan immediately
    if (res.status === 404) {
      await withTimeout(
        fetch('https://www.virustotal.com/api/v3/urls', {
          method: 'POST',
          headers: { 'x-apikey': apiKey },
          body: fetch.body.form({ url }),
        }),
        4500,
        'VT submit timeout'
      ).catch(() => null);

      return {
        provider: 'VirusTotal v3',
        status: 'queued',
        flagged: false,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        totalEngines: 0,
        note: 'Submitted for fresh VirusTotal multi-engine analysis; re-scan in ~15s for full vendor tally.',
      };
    }

    if (!res.ok) {
      return {
        provider: 'VirusTotal v3',
        status: 'error',
        httpStatus: res.status,
        flagged: false,
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        totalEngines: 0,
      };
    }

    const json = await res.json();
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const totalEngines = malicious + suspicious + harmless + undetected;

    const flaggingVendors = [];
    const results = attrs.last_analysis_results || {};
    for (const [vendor, detail] of Object.entries(results)) {
      if (detail?.category === 'malicious' || detail?.category === 'suspicious') {
        flaggingVendors.push(`${vendor} (${detail.result || detail.category})`);
        if (flaggingVendors.length >= 6) break;
      }
    }

    return {
      provider: 'VirusTotal v3',
      status: 'ok',
      flagged: malicious > 0 || suspicious > 0,
      malicious,
      suspicious,
      harmless,
      undetected,
      totalEngines,
      reputation: attrs.reputation ?? 0,
      categories: Object.values(attrs.categories || {}).slice(0, 4),
      flaggingVendors,
      lastAnalysisUnix: attrs.last_analysis_date || null,
    };
  } catch (err) {
    return {
      provider: 'VirusTotal v3',
      status: 'error',
      error: String(err?.message || err),
      flagged: false,
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      totalEngines: 0,
    };
  }
}
