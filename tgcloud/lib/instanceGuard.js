import { EndpointError } from 'sdk';
import { sha256HexPure } from './v8Runtime.js';

// ============================================================================
// Official LinkLens Instance Verification Guard (`instanceGuard.js`)
// ============================================================================
// PURPOSE (PUBLIC SECURITY AUDIT & ANTI-CLONE PROTECTION):
// LinkLens publishes its complete scanner, database, and UI source code openly
// so security researchers and users can verify that zero tracking, link theft,
// or hidden data collection exists anywhere in the codebase.
//
// To prevent unauthorized third-party bot clones, every runtime handler verifies
// that the active deployment possesses the owner's 256-bit secret activation key
// matching the one-way SHA-256 commitment below.
// ============================================================================

export const OFFICIAL_SEAL_SHA256 =
  '5c89fbf615fd221f4ba02f1fc65c5fc189accc3fcbbb35533a8e6de812bcd377';

export function verifyActivationKey(candidateKey) {
  if (!candidateKey || typeof candidateKey !== 'string') return false;
  const digest = sha256HexPure(`linklens-official-v1:${candidateKey.trim()}`);
  return digest === OFFICIAL_SEAL_SHA256;
}

export function isInstanceActivated(cfg = {}) {
  return verifyActivationKey(cfg?.INSTANCE_ACTIVATION_KEY);
}

export function assertAuthorizedInstance(cfg = {}) {
  if (!isInstanceActivated(cfg)) {
    throw new EndpointError(
      'Unauthorized deployment: this repository is published strictly for public security audit.',
      { code: 'UNAUTHORIZED_INSTANCE' }
    );
  }
}

export const UNAUTHORIZED_CLONE_MESSAGE =
  '<b>UNAUTHORIZED INSTANCE</b>\n\n' +
  'This source code is published exclusively for <b>public security &amp; privacy auditing</b>.\n' +
  'Cloning or hosting unauthorized copies of LinkLens is prohibited.';
