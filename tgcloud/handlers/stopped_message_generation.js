import { db } from 'sdk';
import { sql } from 'sdk/db';
import { scanStops } from '../schema.js';

// ============================================================================
// handlers/stopped_message_generation.js — Bot API 10.3 Stop Button Handler
// Triggered natively when a user presses "Stop" during `sendMessageDraft`!
// ============================================================================

export default async function (stoppedEvent) {
  const chatId = stoppedEvent?.chat?.id;
  const draftId = stoppedEvent?.draft_id;
  if (!chatId || !draftId) return;

  const draftKey = `${chatId}:${draftId}`;
  try {
    await db.insert(scanStops)
      .values({ draftKey, stoppedAt: sql`(unixepoch())` })
      .onConflictDoNothing({ target: scanStops.draftKey })
      .run();
  } catch (_) {
    // Safe fallback if migration hasn't run yet
  }
}
