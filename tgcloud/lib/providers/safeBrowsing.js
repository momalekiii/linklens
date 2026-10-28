import { fetch } from 'sdk';
import { withTimeout } from '../urlUtils.js';

// ============================================================================
// Google Safe Browsing Lookup API v4
// Checks MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE & PHA simultaneously
// ============================================================================

export async function checkGoogleSafeBrowsing(urlsToCheck, apiKey) {
  if (!apiKey) {
    return {
      provider: 'Google Safe Browsing v4',
      status: 'unconfigured',
      flagged: false,
      threats: [],
      note: 'Standby',
    };
  }

  const uniqueUrls = [...new Set(urlsToCheck.filter(Boolean))];
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;

  try {
    const res = await withTimeout(
      fetch(endpoint, {
        method: 'POST',
        body: fetch.body.json({
          client: { clientId: 'linklens-tgcloud', clientVersion: '1.0.0' },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: uniqueUrls.map((url) => ({ url })),
          },
        }),
      }),
      5500,
      'GSB timeout'
    );

    if (!res.ok) {
      return {
        provider: 'Google Safe Browsing v4',
        status: 'error',
        httpStatus: res.status,
        flagged: false,
        threats: [],
      };
    }

    const data = await res.json();
    const matches = Array.isArray(data?.matches) ? data.matches : [];
    const threats = [...new Set(matches.map((m) => m.threatType))];

    return {
      provider: 'Google Safe Browsing v4',
      status: 'ok',
      flagged: threats.length > 0,
      threats,
      matchedCount: matches.length,
    };
  } catch (err) {
    return {
      provider: 'Google Safe Browsing v4',
      status: 'error',
      error: String(err?.message || err),
      flagged: false,
      threats: [],
    };
  }
}
