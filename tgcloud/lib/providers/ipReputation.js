import { fetch } from 'sdk';
import { withTimeout } from '../urlUtils.js';

// ============================================================================
// IP Geolocation / ASN Intelligence + AbuseIPDB v2 + IPQualityScore URL AI
// ============================================================================

export async function checkIpAndUrlReputation({ url, primaryIp, abuseKey, ipqsKey }) {
  const [geoRes, abuseRes, ipqsRes] = await Promise.all([
    primaryIp ? lookupIpWhois(primaryIp) : Promise.resolve(null),
    primaryIp ? checkAbuseIpDb(primaryIp, abuseKey) : Promise.resolve({ provider: 'AbuseIPDB v2', status: abuseKey ? 'no_ip' : 'unconfigured', flagged: false }),
    checkIpQualityScore(url, ipqsKey),
  ]);

  return {
    geo: geoRes,
    abuseIpDb: abuseRes,
    ipqs: ipqsRes,
  };
}

async function lookupIpWhois(ip) {
  try {
    const res = await withTimeout(
      fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      }),
      4500,
      'ipwho.is timeout'
    );
    if (!res.ok) return { ip };
    const data = await res.json();
    if (data?.success === false) return { ip };
    return {
      ip,
      country: data.country || null,
      countryCode: data.country_code || null,
      flag: data.flag?.emoji || '',
      city: data.city || null,
      asn: data.connection?.asn ? `AS${data.connection.asn}` : null,
      org: data.connection?.org || data.connection?.isp || null,
      isp: data.connection?.isp || null,
    };
  } catch (_) {
    return { ip };
  }
}

async function checkAbuseIpDb(ip, apiKey) {
  if (!apiKey) {
    return {
      provider: 'AbuseIPDB v2',
      status: 'unconfigured',
      flagged: false,
      abuseConfidenceScore: 0,
      totalReports: 0,
      note: 'Standby',
    };
  }
  try {
    const res = await withTimeout(
      fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
        method: 'GET',
        headers: { Key: apiKey, Accept: 'application/json' },
      }),
      5000,
      'AbuseIPDB timeout'
    );
    if (!res.ok) {
      return { provider: 'AbuseIPDB v2', status: 'error', httpStatus: res.status, flagged: false };
    }
    const json = await res.json();
    const d = json?.data || {};
    const score = Number(d.abuseConfidenceScore || 0);
    return {
      provider: 'AbuseIPDB v2',
      status: 'ok',
      flagged: score >= 25,
      abuseConfidenceScore: score,
      totalReports: Number(d.totalReports || 0),
      usageType: d.usageType || null,
      isTor: Boolean(d.isTor),
    };
  } catch (err) {
    return { provider: 'AbuseIPDB v2', status: 'error', error: String(err?.message || err), flagged: false };
  }
}

async function checkIpQualityScore(url, apiKey) {
  if (!apiKey) {
    return {
      provider: 'IPQualityScore AI',
      status: 'unconfigured',
      flagged: false,
      riskScore: 0,
      note: 'Standby',
    };
  }
  try {
    const endpoint = `https://www.ipqualityscore.com/api/json/url/${encodeURIComponent(apiKey)}/${encodeURIComponent(url)}`;
    const res = await withTimeout(fetch(endpoint, { method: 'GET' }), 5500, 'IPQS timeout');
    if (!res.ok) {
      return { provider: 'IPQualityScore AI', status: 'error', httpStatus: res.status, flagged: false };
    }
    const d = await res.json();
    if (!d?.success) {
      return { provider: 'IPQualityScore AI', status: 'error', flagged: false };
    }
    const riskScore = Number(d.risk_score || 0);
    return {
      provider: 'IPQualityScore AI',
      status: 'ok',
      flagged: Boolean(d.unsafe || d.phishing || d.malware || riskScore >= 75),
      riskScore,
      phishing: Boolean(d.phishing),
      malware: Boolean(d.malware),
      suspicious: Boolean(d.suspicious),
      parking: Boolean(d.parking),
      category: d.category || null,
    };
  } catch (err) {
    return { provider: 'IPQualityScore AI', status: 'error', error: String(err?.message || err), flagged: false };
  }
}
