import { extractLinksFromMessage } from '../lib/urlUtils.js';
import { inferBestLanguage } from '../lib/usersRepo.js';
import { executeMultiLinkChatScan } from '../lib/chatFlow.js';
import { getConfigMap } from '../lib/secrets.js';
import { isInstanceActivated } from '../lib/instanceGuard.js';

// ============================================================================
// handlers/channel_post.js — Auto-scans links in channels where bot is added
// ============================================================================

export default async function (post) {
  if (!post?.chat?.id) return;
  const cfg = await getConfigMap();
  if (!isInstanceActivated(cfg)) return;

  const { urls, spoofAlert } = extractLinksFromMessage(post);
  if (!urls.length) return;

  const lang = inferBestLanguage(null, {}, post.text || post.caption || '');
  await executeMultiLinkChatScan({
    chatId: post.chat.id,
    chatType: post.chat.type || 'channel',
    tgId: post.chat.id,
    urls,
    spoofAlert,
    lang,
  });
}
