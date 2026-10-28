import { fetch } from 'sdk';
import { isRawIp, withTimeout } from '../urlUtils.js';

// ============================================================================
// Domain, DNS Posture & SSL Certificate Transparency Intelligence
// 1. Cloudflare DNS-over-HTTPS (A, AAAA, MX, NS, SPF, DMARC, CAA)
// 2. Official IANA RDAP Registry API (Registrar, Exact Age in Days, DNSSEC)
// 3. crt.sh Certificate Transparency Logs (Issuer, Validity, Issuance Count)
// ============================================================================

async function dohQuery(name, type) {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await withTimeout(
      fetch(url, { method: 'GET', headers: { Accept: 'application/dns-json' } }),
      4000,
      `DoH ${type} timeout`
    );
    if (!res.ok) return { status: -1, answers: [] };
    const data = await res.json();
    return {
      status: data.Status ?? 0,
      dnssecValidated: Boolean(data.AD),
      answers: Array.isArray(data.Answer) ? data.Answer : [],
    };
  } catch (_) {
    return { status: -1, answers: [] };
  }
}

export async function inspectDnsPosture(hostname, registrableDomain) {
  if (isRawIp(hostname)) {
    return {
      isIpLiteral: true,
      aRecords: hostname.includes(':') ? [] : [hostname],
      aaaaRecords: hostname.includes(':') ? [hostname] : [],
      mxRecords: [],
      nsRecords: [],
      hasSpf: false,
      hasDmarc: false,
      hasCaa: false,
      dnssecValidated: false,
      nxdomain: false,
    };
  }

  const [aRes, aaaaRes, mxRes, nsRes, txtRes, dmarcRes, caaRes] = await Promise.all([
    dohQuery(hostname, 'A'),
    dohQuery(hostname, 'AAAA'),
    dohQuery(registrableDomain, 'MX'),
    dohQuery(registrableDomain, 'NS'),
    dohQuery(registrableDomain, 'TXT'),
    dohQuery(`_dmarc.${registrableDomain}`, 'TXT'),
    dohQuery(registrableDomain, 'CAA'),
  ]);

  const aRecords = aRes.answers.filter((a) => a.type === 1).map((a) => a.data);
  const aaaaRecords = aaaaRes.answers.filter((a) => a.type === 28).map((a) => a.data);
  const mxRecords = mxRes.answers.map((a) => a.data).slice(0, 4);
  const nsRecords = nsRes.answers.map((a) => a.data.replace(/\.$/, '')).slice(0, 4);
  const txtStrings = txtRes.answers.map((a) => String(a.data || '').replace(/^"|"$/g, ''));
  const dmarcStrings = dmarcRes.answers.map((a) => String(a.data || '').replace(/^"|"$/g, ''));
  const caaRecords = caaRes.answers.map((a) => a.data).slice(0, 4);

  const spfRecord = txtStrings.find((s) => s.toLowerCase().includes('v=spf1')) || null;
  const dmarcRecord = dmarcStrings.find((s) => s.toLowerCase().includes('v=dmarc1')) || null;

  return {
    isIpLiteral: false,
    nxdomain: aRes.status === 3 && aaaaRes.status === 3,
    dnssecValidated: Boolean(aRes.dnssecValidated || nsRes.dnssecValidated),
    aRecords,
    aaaaRecords,
    mxRecords,
    nsRecords,
    hasSpf: Boolean(spfRecord),
    spfRecord,
    hasDmarc: Boolean(dmarcRecord),
    dmarcRecord,
    hasCaa: caaRecords.length > 0,
    caaRecords,
  };
}

export async function inspectRdapDomainAge(registrableDomain) {
  if (isRawIp(registrableDomain)) {
    return { status: 'skipped_ip', ageDays: null, registrar: null, createdDate: null, expiresDate: null, dnssec: false };
  }
  if (String(registrableDomain || '').toLowerCase().endsWith('.ir')) {
    return {
      status: 'irnic',
      domain: registrableDomain,
      registrar: 'IRNIC (.ir National Registry)',
      ageDays: null,
      createdDate: null,
      expiresDate: null,
      dnssec: false,
      statuses: [],
    };
  }

  try {
    const res = await withTimeout(
      fetch(`https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`, {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; LinkLensSecurity/1.1)',
          Accept: 'application/rdap+json, application/json, */*',
        },
      }),
      4200,
      'RDAP timeout'
    );
    if (!res.ok) {
      return { status: 'unavailable', httpStatus: res.status, ageDays: null, registrar: null };
    }
    const data = await res.json();
    const events = Array.isArray(data?.events) ? data.events : [];
    const regEvent = events.find((e) => e.eventAction === 'registration');
    const expEvent = events.find((e) => e.eventAction === 'expiration');

    let createdDate = regEvent?.eventDate || null;
    let ageDays = null;
    if (createdDate) {
      const ts = Date.parse(createdDate);
      if (!Number.isNaN(ts)) {
        ageDays = Math.max(0, Math.floor((Date.now() - ts) / 86400000));
      }
    }

    // Extract registrar name from vCard entities if present
    let registrar = null;
    const entities = Array.isArray(data?.entities) ? data.entities : [];
    const regEntity = entities.find((en) => Array.isArray(en.roles) && en.roles.includes('registrar'));
    const fnEntry = regEntity?.vcardArray?.[1]?.find?.((item) => item[0] === 'fn');
    if (fnEntry && fnEntry[3]) registrar = String(fnEntry[3]);

    return {
      status: 'ok',
      domain: data?.ldhName || registrableDomain,
      registrar,
      createdDate: createdDate ? createdDate.slice(0, 10) : null,
      expiresDate: expEvent?.eventDate ? expEvent.eventDate.slice(0, 10) : null,
      ageDays,
      dnssec: Boolean(data?.secureDNS?.delegationSigned),
      statuses: Array.isArray(data?.status) ? data.status.slice(0, 4) : [],
    };
  } catch (err) {
    return {
      status: 'error',
      error: String(err?.message || err),
      ageDays: null,
      registrar: null,
    };
  }
}

export async function inspectSslTransparency(registrableDomain) {
  if (isRawIp(registrableDomain)) {
    return { status: 'skipped_ip', certsFound: 0, issuer: null, validUntil: null };
  }
  try {
    const res = await withTimeout(
      fetch(`https://crt.sh/?q=${encodeURIComponent(registrableDomain)}&output=json`, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      }),
      3200,
      'crt.sh timeout'
    );
    if (!res.ok) {
      return { status: 'unavailable', certsFound: 0, issuer: null };
    }
    const list = await res.json();
    if (!Array.isArray(list) || list.length === 0) {
      return { status: 'none', certsFound: 0, issuer: null };
    }

    const latest = list[0];
    const issuerRaw = String(latest.issuer_name || '');
    const cnMatch = issuerRaw.match(/O=([^,]+)/) || issuerRaw.match(/CN=([^,]+)/);
    const issuer = cnMatch ? cnMatch[1].replace(/^"|"$/g, '').trim() : issuerRaw.slice(0, 48);

    return {
      status: 'ok',
      certsFound: list.length,
      issuer,
      commonName: latest.common_name || registrableDomain,
      notBefore: latest.not_before ? String(latest.not_before).slice(0, 10) : null,
      notAfter: latest.not_after ? String(latest.not_after).slice(0, 10) : null,
    };
  } catch (_) {
    return { status: 'unavailable', certsFound: 0, issuer: null };
  }
}
