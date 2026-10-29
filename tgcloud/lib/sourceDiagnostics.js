import { parseAndValidateTarget } from './urlUtils.js';
import { inspectDnsPosture, inspectRdapDomainAge, inspectSslTransparency } from './providers/domainDnsSsl.js';
import { inspectHttpAndDom } from './providers/httpInspector.js';
import { checkUrlScan } from './providers/urlscan.js';
import { ensureMotmaenBashIndex, ensureLeakfaIndex, ensureKavehIndex, ensureHibpIndex } from './providers/iranIntel.js';

// Run exactly one named source per CLI call, so a slow source is identifiable.
// No tokens and no complete private target URLs are logged.
export async function diagnoseSources(input) {
  const target = parseAndValidateTarget(input.url || 'https://example.com');
  if (!target.valid) return {ok:false, error:target.error};
  const jobs = {
    motmaenbash: () => ensureMotmaenBashIndex(Boolean(input.refresh)),
    leakfa: () => ensureLeakfaIndex(Boolean(input.refresh)),
    kaveh: () => ensureKavehIndex(Boolean(input.refresh)),
    hibp: () => ensureHibpIndex(Boolean(input.refresh)),
    dns: () => inspectDnsPosture(target.hostname, target.registrableDomain),
    rdap: () => inspectRdapDomainAge(target.registrableDomain),
    certificates: () => inspectSslTransparency(target.registrableDomain),
    http: () => inspectHttpAndDom(target.normalizedUrl, target.registrableDomain),
    urlscan: () => checkUrlScan(target.normalizedUrl, target.hostname, null),
  };
  const name = String(input.source || '');
  if (!jobs[name]) return {ok:false, error:'Choose a source', sources:Object.keys(jobs)};
  const start = Date.now();
  console.info('source-check-start', name);
  try {
    const data = await jobs[name]();
    const count = data.count ?? (data.urlThreatCount != null ? data.urlThreatCount + data.apkThreatCount : null);
    const status = count != null ? (count > 0 ? 'data_available' : 'unavailable')
      : name === 'dns' ? (data.unavailable ? 'unavailable' : 'ok')
      : name === 'http' ? (data.reachable ? 'ok' : 'unavailable') : data.status || 'unknown';
    const result = {source:name, status, durationMs:Date.now()-start, entries:count, syncedAt:data.syncedAt || null, httpStatus:data.httpStatus || null, error:data.error || null, ageDays:data.ageDays ?? null, certificates:data.certsFound ?? null};
    console.info('source-check-finish', result);
    return result;
  } catch(e) {
    const result = {source:name,status:'error',durationMs:Date.now()-start,error:String(e?.message || e)};
    console.error('source-check-failed', result);
    return result;
  }
}
