// ============================================================================
// LinkLens Trilingual Localization Engine — Persian (fa), English (en), Russian (ru)
// Complete localization including Iranian Security (MotmaenBash, Shaparak [fa only],
// Nooshdaroo Kaveh) and Data Breach Intelligence (Leakfa + Have I Been Pwned)
// Owner Copyright appears EXCLUSIVELY on the About Us page (`aboutCopyrightHtml`)
// ============================================================================

export const SUPPORTED_LANGS = ['fa', 'en', 'ru'];

export function isValidLang(code) {
  return SUPPORTED_LANGS.includes(code);
}

export function isRtl(lang) {
  return lang === 'fa';
}

export function renderLanguageGateText(firstName = '', hasPendingUrl = false) {
  const safeName = escapeHtml(firstName || 'Friend');
  const pendingNotice = hasPendingUrl
    ? [
        '',
        '\u200F🔗 <b>لینک شما دریافت شد!</b> به محض انتخاب زبان، اسکن امنیتی آغاز می‌شود.',
        '🔗 <b>Link detected!</b> Right after you choose your language, the full scan starts automatically.',
        '🔗 <b>Ссылка получена!</b> Сразу после выбора языка запустится полная проверка.',
      ].join('\n')
    : '';

  return [
    `🛡 <b>LinkLens — Deep Link &amp; Breach Security Scanner</b>`,
    ``,
    `\u200F🇮🇷 سلام <b>${safeName}</b> عزیز! هر لینک یا پیام مشکوک تلگرامی را بفرستید یا فوروارد کنید تا اصالت درگاه شاپرک، فیشینگ و نشت اطلاعات آن خودکار بررسی شود. لطفاً زبان خود را انتخاب کنید:`,
    ``,
    `🇬🇧 Welcome, <b>${safeName}</b>! Send any link or forward any message from anywhere on Telegram for instant phishing, malware, and data-breach analysis. Please select your language:`,
    ``,
    `🇷🇺 Привет, <b>${safeName}</b>! Отправьте любую ссылку или перешлите любое сообщение из Telegram для автоматической проверки на фишинг, вирусы и утечки данных. Выберите язык:`,
    pendingNotice,
  ].filter(Boolean).join('\n');
}

export const STRINGS = {
  en: {
    code: 'en',
    flag: '🇬🇧',
    name: 'English',
    dir: 'ltr',
    langSavedToast: '✅ Language set to English!',
    chooseLangPrompt: '🌐 <b>Select Language</b>\nChoose the language for all LinkLens security reports, alerts, and menus:',
    homeTitle: '🛡 <b>LinkLens Security Center</b>',
    homeSubtitle: 'Send <b>any URL</b> or <b>forward any message from anywhere in Telegram</b> — LinkLens automatically extracts links from the message and updates your live report right in chat.',
    homeChecksHeader: '🔬 <b>What LinkLens Scans Live:</b>',
    homeChecksList: [
      '• <b>🧬 Global Threat Intel APIs:</b> VirusTotal (90+ engines), Google Safe Browsing, URLScan.io, AbuseIPDB &amp; IPQualityScore',
      '• <b>🔐 Website Data Breach History:</b> Live <b>Have I Been Pwned</b> global breach database + open regional breach feeds',
      '• <b>🛡 Anti-Phishing &amp; Malware Feeds:</b> SHA-256 blacklist matching against verified phishing portals, scams &amp; malicious APKs',
      '• <b>🌐 DNS, WHOIS Age &amp; TLS:</b> Cloudflare DoH (SPF/DMARC/CAA), IANA RDAP domain creation age &amp; crt.sh Certificate Transparency',
      '• <b>🔒 HTTP, Redirects &amp; DOM:</b> Unshortens chains, audits OWASP headers, catches card skimmers, ClickFix &amp; crypto drainers',
    ],
    homeTip: '💡 <i>Tip: Forward suspicious posts, captions, or messages straight here — LinkLens automatically detects hidden hyperlinks, inline button URLs, and disguised traps!</i>',

    // About Us Page (ONLY place where owner copyright appears)
    aboutTitle: 'ℹ️ <b>About LinkLens</b>',
    aboutBody: [
      '<b>LinkLens</b> is an instant multi-layer URL threat, phishing, malware, and data-breach scanner built natively on <b>Telegram Serverless</b>.',
      '',
      '🔬 <b>Security Architecture:</b>',
      '• Real-time URL unshortening, HTTP OWASP header auditing &amp; DOM skimmer/ClickFix detection',
      '• Multi-engine threat intelligence (VirusTotal v3, Google Safe Browsing v4, URLScan.io, AbuseIPDB, IPQualityScore)',
      '• Infrastructure telemetry (Cloudflare DoH DNS, IANA RDAP domain age &amp; crt.sh SSL logs)',
      '• Open threat &amp; breach datasets: <i>Have I Been Pwned</i>, <i>MotmaenBash</i> (CC-BY-4.0), <i>Nooshdaroo Kaveh</i> &amp; <i>Leakfa-Alert</i> (MIT)',
      '',
      '🔒 <b>Privacy:</b> Submitted links are analyzed solely to generate your security report.',
      '',
      '━━━━━━━━━━━━━━━━━━━━',
      '© 2026 <a href="https://momalekiii.github.io">momalekiii.github.io</a> — All rights reserved.',
    ],
    btnVisitWebsite: '🌐 Website (momalekiii.github.io)',

    // Buttons (Zero sample buttons)
    btnOpenMiniApp: '🌐 Web Scanner (Mini App)',
    btnOpenScanInApp: '🌐 Open Report in Mini App',
    btnHistory: '📜 Scan History',
    btnStats: '📊 My Stats',
    btnLanguage: '🌐 Language',
    btnApiKeys: '📡 System Status',
    btnAbout: 'ℹ️ About Us',
    btnHome: '🏠 Main Menu',
    btnBack: '◀️ Back',
    btnOpenSafeUrl: '🟢 Verified Safe — Open Link',
    btnCopyDefanged: '⛔ High Risk — Copy Defanged URL',
    btnOpenLeakfaReport: '🔐 View Breach Incident Report',
    btnTabOverview: '🛡 Overview',
    btnTabIran: '🔐 Breaches & Feeds',
    btnTabEngines: '🧬 Threat APIs',
    btnTabInfra: '🌐 DNS / SSL / WHOIS',
    btnTabHeaders: '🔒 Headers & DOM',
    btnCopySummary: '📋 Copy Summary',
    btnForceRescan: '🔄 Force Re-Scan',
    btnClearHistory: '🗑 Clear History',
    btnShareInline: '📤 Scan in Another Chat',

    // Real-Time In-Place Live Progress Stages (1 single message updated live!)
    streamHeader: '🔍 <b>LinkLens Live Deep Scan</b>',
    stage0: '0/4 Initializing isolated security probe…',
    stage1: '1/4 Unshortening redirects, hashing payload &amp; inspecting DOM traps…',
    stage2: '2/4 Querying VirusTotal, Safe Browsing, HIBP &amp; phishing/malware feeds…',
    stage3: '3/4 Inspecting Cloudflare DoH DNS, RDAP domain age &amp; SSL CT logs…',
    stage4: '4/4 Finalizing risk score &amp; interactive security report…',
    scanStopped: '⏹ <b>Live scan stopped by user.</b> Send or forward any link whenever you are ready to scan again.',
    multiLinkProgress: '🔎 <b>Scanning link {idx} of {total} in forwarded message…</b>',
    multiLinkSummaryHeader: '📎 <b>Detected {count} links in message</b> (tap any link button below to switch):',

    // Verdicts
    verdict_SAFE: '🟢 SAFE TO VISIT',
    verdict_LOW_RISK: '🔵 LOW RISK / BREACH HYGIENE NOTE',
    verdict_SUSPICIOUS: '🟠 SUSPICIOUS — EXERCISE CAUTION',
    verdict_MALICIOUS: '🔴 DANGEROUS / PHISHING OR MALWARE',

    // Gateway & Breach Banners
    bannerShaparakVerified: '✅ <b>VERIFIED PAYMENT GATEWAY:</b> {psp} — Verified HTTPS payment portal.',
    bannerFacilitator: '🟦 <b>Licensed Payment Facilitator:</b> {psp}',
    bannerFakeIranGateway: '🚨 <b>CRITICAL PHISHING ALERT:</b> Counterfeit portal impersonating <b>{brand}</b>! NEVER enter payment or login credentials!',
    bannerMotmaenBashHit: '🚨 <b>CONFIRMED PHISHING / SCAM THREAT ({cat}):</b> Matched verified SHA-256 blacklist entry for <code>{target}</code>!',
    bannerLeakfaBreach: '🔐 <b>DATA BREACH ADVISORY ({site}):</b> Legitimate site, but historical user records were exposed in a documented breach. Never reuse old passwords &amp; enable 2FA!',

    // Report Labels
    lblRiskScore: 'Risk Score',
    lblGrade: 'Security Grade',
    lblInputUrl: 'Submitted Link',
    lblFinalUrl: 'Final Destination',
    lblDomainAge: 'Domain Age',
    lblServerIp: 'Server IP & Geo',
    lblSslStatus: 'SSL / TLS',
    lblHeadersGrade: 'HTTP Headers',
    lblEngines: 'Active Security Layers',
    lblScanTime: 'Scan Time',
    lblCached: '⚡ Cached (<15m)',
    lblFindings: '⚠️ Key Security & Breach Findings',
    lblNoFindings: '✅ Clean across all active threat, phishing, infrastructure &amp; data-breach layers.',
    lblRedirectChain: '🔀 Redirect Chain',
    lblSpoofWarning: '🚨 <b>LINK SPOOF DETECTED IN MESSAGE!</b> Visible link text claimed <code>{shown}</code>, but actually points to <code>{actual}</code>!',
    lblNoUrlFound: '🔎 No link was found in that message.\n\nSend any URL directly or forward any Telegram message containing a link, caption link, or inline button link — LinkLens will detect and scan it automatically.',
    lblBlockedPrivate: '🛡 <b>Blocked Internal / Local Target:</b> Scanning private, loopback, or internal network addresses is disabled for SSRF security.',
    lblHistoryTitle: '📜 <b>Your Recent LinkLens Scans</b>',
    lblHistoryEmpty: '📭 You haven’t scanned any links yet. Send any link or forward any message from Telegram to scan automatically!',
    lblHistoryCleared: '🗑 Scan history cleared.',
    lblStatsTitle: '📊 <b>Your LinkLens Security Telemetry</b>',
    lblTotalScans: 'Total Links Scanned',
    lblThreatsBlocked: 'Suspicious / Malicious Caught',
    lblGlobalScans: 'Bot-Wide Total Scans',
    lblCurrentLang: 'Active Language',
    lblKeysTitle: '📡 <b>Live Security & Breach Intelligence Status</b>',
    lblKeysIntro: 'Real-time status of LinkLens anti-phishing, breach intelligence, infrastructure, and global threat layers:',
    lblStatusActive: 'Active',
    lblStatusStandby: 'Standby',
    lblAdminClaimed: '👑 Administrator access confirmed.',
    lblNotAdmin: '🔒 This command is restricted to the bot administrator.',
    lblKeySaved: '✅ Saved key <b>{key}</b> successfully! All future scans will query it immediately.',
    lblFeedsSynced: '🔄 <b>Live Threat &amp; Breach Feeds Synced!</b>\n• Anti-Phishing Feed: <b>{urls}</b> phishing URLs + <b>{apks}</b> banking trojans\n• Regional Breaches: <b>{leakfa}</b> breached domains\n• Malware Signatures: <b>{kaveh}</b> malware hashes\n• Have I Been Pwned: <b>{hibp}</b> global breaches',
    daysOld: '{days} days old',
    unknown: 'Unknown / Registry Protected',
  },

  fa: {
    code: 'fa',
    flag: '🇮🇷',
    name: 'فارسی',
    dir: 'rtl',
    langSavedToast: '✅ زبان ربات به فارسی تنظیم شد!',
    chooseLangPrompt: '🌐 <b>انتخاب زبان ربات</b>\nزبان نمایش گزارش‌های امنیتی، هشدارهای فیشینگ/نشت داده و دکمه‌های LinkLens را انتخاب کنید:',
    homeTitle: '🛡 <b>مرکز امنیت لینک و بررسی نشت اطلاعات LinkLens</b>',
    homeSubtitle: 'هر <b>لینک، درگاه پرداخت یا پیام حاوی لینک</b> را بفرستید یا مستقیماً از هر کانال، گروه یا چتی به اینجا <b>فوروارد کنید</b> — ربات به صورت زنده در یک پیام واحد لینک را بررسی و نتیجه را نمایش می‌دهد.',
    homeChecksHeader: '🔬 <b>منابع و لایه‌های بررسی زنده در LinkLens:</b>',
    homeChecksList: [
      '• <b>🇮🇷 امنیت سایبری ایران و درگاه شاپرک:</b> دیتابیس <b>مطمئن‌باش (MotmaenBash)</b>، پروژه <b>کاوه (نوشدارو)</b>، تایید اصالت درگاه‌های رسمی <b>شاپرک</b> و تشخیص هوشمند فرم‌های سرقت کارت و بدافزارهای <code>.apk</code> (ثنا، سهام عدالت، پست)',
      '• <b>🔐 بررسی سابقه نشت اطلاعات (Data Breach):</b> استعلام زنده از دیتابیس رسمی <b>لیک‌فا (Leakfa)</b> برای سایت‌های ایرانی + سرویس جهانی <b>Have I Been Pwned</b>',
      '• <b>🧬 موتورهای ضدبدافزار بین‌المللی:</b> VirusTotal (+۹۰ آنتی‌ویروس)، Google Safe Browsing، URLScan.io، AbuseIPDB و IPQualityScore',
      '• <b>🌐 شبکه، DNS، قدمت دامنه و SSL:</b> بررسی Cloudflare DoH، قدمت ثبت دامنه (RDAP) و تاریخچه گواهی امنیتی (crt.sh)',
      '• <b>🔒 تحلیل ریدایرکت، هدرها و کد صفحه:</b> باز کردن لینک‌های کوتاه‌شده ایرانی/خارجی، هدرهای OWASP، شناسایی ClickFix و Drainer',
    ],
    homeTip: '💡 <i>نکته: کافیست هر پست یا پیام مشکوک را به ربات فوروارد کنید — حتی لینک‌های پنهان‌شده روی متن، کپشن عکس/فایل یا دکمه‌های شیشه‌ای خودکار استخراج و بررسی می‌شوند!</i>',

    // About Us Page (ONLY place where owner copyright appears)
    aboutTitle: 'ℹ️ <b>درباره LinkLens</b>',
    aboutBody: [
      '<b>LinkLens</b> سامانه هوشمند بررسی چندلایه امنیت لینک، اصالت درگاه پرداخت شاپرک، شناسایی فیشینگ/بدافزار و بررسی سابقه نشت اطلاعات است که به صورت بومی روی زیرساخت <b>Telegram Serverless</b> اجرا می‌شود.',
      '',
      '🔬 <b>لایه‌های تحلیل امنیتی:</b>',
      '• باز کردن لینک‌های کوتاه‌شده، بررسی هدرهای امنیتی OWASP و تشخیص فرم‌های سرقت کارت بانکی و ClickFix',
      '• استعلام همزمان از موتورهای جهانی (VirusTotal، Google Safe Browsing، URLScan.io، AbuseIPDB و IPQualityScore)',
      '• بررسی زیرساخت شبکه، رکوردهای DNS، قدمت دامنه (RDAP) و گواهی‌های SSL/TLS',
      '• منابع داده باز: <i>مطمئن‌باش</i> (CC-BY-4.0)، <i>لیک‌فا</i> (MIT)، <i>پروژه کاوه نوشدارو</i> و <i>Have I Been Pwned</i>',
      '',
      '🔒 <b>حریم خصوصی:</b> لینک‌های ارسالی صرفاً جهت تولید گزارش امنیتی لحظه‌ای بررسی می‌شوند.',
      '',
      '━━━━━━━━━━━━━━━━━━━━',
      '© ۲۰۲۶ <a href="https://momalekiii.github.io">momalekiii.github.io</a> — تمامی حقوق محفوظ است.',
    ],
    btnVisitWebsite: '🌐 وب‌سایت رسمی (momalekiii.github.io)',

    // Buttons (Zero sample buttons)
    btnOpenMiniApp: '🌐 وب‌اسکنر (مینی‌اپ)',
    btnOpenScanInApp: '🌐 مشاهده گزارش در مینی‌اپ',
    btnHistory: '📜 تاریخچه اسکن‌ها',
    btnStats: '📊 آمار من',
    btnLanguage: '🌐 تغییر زبان',
    btnApiKeys: '📡 وضعیت سرویس‌ها',
    btnAbout: 'ℹ️ درباره ما',
    btnHome: '🏠 منوی اصلی',
    btnBack: '◀️ بازگشت',
    btnOpenSafeUrl: '🟢 لینک امن است — باز کردن سایت',
    btnCopyDefanged: '⛔ خطرناک — کپی آدرس خنثی‌شده',
    btnOpenLeakfaReport: '🔐 مشاهده روایت کامل نشت در لیک‌فا',
    btnTabOverview: '🛡 خلاصه کلیدی',
    btnTabIran: '🇮🇷 مطمئن‌باش و لیک‌فا',
    btnTabEngines: '🧬 موتورهای جهانی',
    btnTabInfra: '🌐 شبکه / DNS / SSL',
    btnTabHeaders: '🔒 هدرها و کد صفحه',
    btnCopySummary: '📋 کپی خلاصه گزارش',
    btnForceRescan: '🔄 اسکن مجدد زنده',
    btnClearHistory: '🗑 پاکسازی تاریخچه',
    btnShareInline: '📤 اشتراک‌گذاری اسکنر',

    // Real-Time In-Place Live Progress Stages (1 single message updated live!)
    streamHeader: '🔍 <b>اسکن عمیق زنده در LinkLens</b>',
    stage0: '۰/۴ آماده‌سازی اسکنر امنیتی…',
    stage1: '۱/۴ باز کردن تغییر مسیرها، محاسبه هش SHA-256 و بررسی فرم‌های درگاه کارت…',
    stage2: '۲/۴ استعلام زنده از مطمئن‌باش، لیک‌فا، کاوه، HIBP، VirusTotal و Safe Browsing…',
    stage3: '۳/۴ واکاوی رکوردهای DNS، قدمت دامنه (RDAP) و گواهی‌های امنیتی SSL/TLS…',
    stage4: '۴/۴ جمع‌بندی نهایی امتیاز ریسک و صدور گزارش امنیتی…',
    scanStopped: '⏹ <b>اسکن زنده توسط شما متوقف شد.</b> هر زمان آماده بودید لینک یا پیام بعدی را بفرستید.',
    multiLinkProgress: '🔎 <b>در حال بررسی لینک {idx} از {total} در پیام…</b>',
    multiLinkSummaryHeader: '📎 <b>{count} لینک در این پیام شناسایی شد</b> (برای مشاهده جزئیات هر لینک روی دکمه آن بزنید):',

    // Verdicts
    verdict_SAFE: '🟢 امن و مورد تایید',
    verdict_LOW_RISK: '🔵 دامنه معتبر (دارای هشدار بهداشت رمز / جزئی)',
    verdict_SUSPICIOUS: '🟠 مشکوک — با احتیاط کامل عمل کنید',
    verdict_MALICIOUS: '🔴 خطر فوری! فیشینگ / درگاه جعلی یا بدافزار',

    // Iranian Gateway & Breach Banners
    bannerShaparakVerified: '✅ <b>درگاه پرداخت رسمی و امن شاپرک تایید شد:</b> <b>{psp}</b> — اتصال امن HTTPS در شبکه رسمی شاپرک بانک مرکزی.',
    bannerFacilitator: '🟦 <b>درگاه پرداخت‌یار (واسط) معتبر:</b> <b>{psp}</b> — دقت کنید در مرحله ورود شماره کارت و رمز پویا، آدرس مرورگر حتماً باید به <code>https://*.shaparak.ir</code> تغییر کند.',
    bannerFakeIranGateway: '🚨 <b>هشدار فوری فیشینگ ایرانی:</b> این آدرس در حال جعل عنوان <b>«{brand}»</b> روی دامنه غیررسمی است! <b>هرگز شماره کارت، CVV2 و رمز دوم پویا یا فایل نصبی را وارد/دانلود نکنید!</b>',
    bannerMotmaenBashHit: '🚨 <b>شناسایی قطعی در دیتابیس مطمئن‌باش ({cat}):</b> هش SHA-256 آدرس <code>{target}</code> در لیست سیاه تهدیدات سایبری ایران ثبت شده است!',
    bannerLeakfaBreach: '🔐 <b>هشدار سابقه نشت اطلاعات در لیک‌فا ({site}):</b> این وب‌سایت جعلی نیست، اما اطلاعات کاربران آن قبلاً دچار نشت داده شده است! اگر در این سایت حساب دارید، رمز عبور خود را عوض کنید و تایید دومرحله‌ای را فعال نمایید.',

    // Report Labels
    lblRiskScore: 'امتیاز ریسک',
    lblGrade: 'رتبه امنیتی',
    lblInputUrl: 'لینک ارسالی',
    lblFinalUrl: 'مقصد نهایی',
    lblDomainAge: 'قدمت دامنه',
    lblServerIp: 'آی‌پی و سرور',
    lblSslStatus: 'وضعیت SSL/TLS',
    lblHeadersGrade: 'هدرهای امنیتی',
    lblEngines: 'لایه‌های امنیتی فعال',
    lblScanTime: 'زمان بررسی',
    lblCached: '⚡ کش سریع',
    lblFindings: '⚠️ یافته‌های امنیتی، شاپرک و نشت داده',
    lblNoFindings: '✅ تمام بررسی‌های امنیتی ایران (مطمئن‌باش/شاپرک/لیک‌فا) و جهان بدون هیچ مورد مشکوکی تایید شدند.',
    lblRedirectChain: '🔀 مسیر تغییر مسیر (Redirect)',
    lblSpoofWarning: '🚨 <b>هشدار جعل لینک در پیام!</b> متن ظاهری لینک <code>{shown}</code> نمایش داده شده اما در واقع به <code>{actual}</code> منتهی می‌شود!',
    lblNoUrlFound: '🔎 لینکی در این پیام پیدا نشد!\n\nکافیست هر آدرس اینترنتی را بفرستید یا هر پیام حاوی لینک را از کانال‌ها، گروه‌ها یا چت‌های تلگرام به اینجا فوروارد کنید تا خودکار بررسی شود.',
    lblBlockedPrivate: '🛡 <b>مسدود شد:</b> اسکن آدرس‌های شبکه داخلی و لوکال (Localhost/Private IP) به دلایل امنیتی مجاز نیست.',
    lblHistoryTitle: '📜 <b>آخرین اسکن‌های شما در LinkLens</b>',
    lblHistoryEmpty: '📭 هنوز هیچ لینکی اسکن نکرده‌اید! یک لینک بفرستید یا هر پیامی حاوی لینک را به ربات فوروارد کنید تا خودکار اسکن شود.',
    lblHistoryCleared: '🗑 تاریخچه اسکن‌های شما پاک شد.',
    lblStatsTitle: '📊 <b>آمار امنیتی حساب شما در LinkLens</b>',
    lblTotalScans: 'تعداد لینک‌های اسکن‌شده شما',
    lblThreatsBlocked: 'لینک‌های مشکوک / فیشینگ شناسایی‌شده',
    lblGlobalScans: 'کل اسکن‌های انجام‌شده در ربات',
    lblCurrentLang: 'زبان فعلی',
    lblKeysTitle: '📡 <b>وضعیت سرویس‌ها و دیتابیس‌های امنیتی</b>',
    lblKeysIntro: 'وضعیت لحظه‌ای لایه‌های ضد فیشینگ، اصالت شاپرک، نشت اطلاعات و موتورهای امنیتی فعال:',
    lblStatusActive: 'فعال',
    lblStatusStandby: 'آماده‌به‌کار',
    lblAdminClaimed: '👑 دسترسی مدیریت تایید شد.',
    lblNotAdmin: '🔒 این دستور فقط مخصوص مدیر اصلی ربات است.',
    lblKeySaved: '✅ کلید <b>{key}</b> با موفقیت ذخیره شد و از همین لحظه در اسکن‌ها فعال است!',
    lblFeedsSynced: '🔄 <b>به‌روزرسانی زنده دیتابیس‌های امنیتی انجام شد!</b>\n• دیتابیس مطمئن‌باش: <b>{urls}</b> لینک فیشینگ/کلاهبرداری + <b>{apks}</b> بدافزار بانکی اندروید\n• دیتابیس لیک‌فا (Leakfa): <b>{leakfa}</b> سامانه و سایت دارای سابقه نشت اطلاعات\n• پروژه کاوه (نوشدارو): <b>{kaveh}</b> امضای بدافزار\n• سرویس جهانی HIBP: <b>{hibp}</b> رکورد نشت داده',
    daysOld: '{days} روز قدمت',
    unknown: 'نامشخص / محافظت‌شده (ایرنیک)',
  },

  ru: {
    code: 'ru',
    flag: '🇷🇺',
    name: 'Русский',
    dir: 'ltr',
    langSavedToast: '✅ Язык переключён на русский!',
    chooseLangPrompt: '🌐 <b>Выбор языка</b>\nВыберите язык отчётов безопасности, проверки утечек и кнопок LinkLens:',
    homeTitle: '🛡 <b>Центр безопасности ссылок и утечек LinkLens</b>',
    homeSubtitle: 'Отправьте <b>любую ссылку</b> или <b>перешлите любое сообщение из Telegram</b> — LinkLens автоматически проверит её и обновит живой отчёт прямо в одном сообщении.',
    homeChecksHeader: '🔬 <b>Что проверяет LinkLens в реальном времени:</b>',
    homeChecksList: [
      '• <b>🧬 Глобальные Threat Intel API:</b> VirusTotal (90+ антивирусов), Google Safe Browsing, URLScan.io, AbuseIPDB, IPQualityScore',
      '• <b>🔐 История утечек данных (Data Breaches):</b> Мировая база <b>Have I Been Pwned</b> + открытые базы утечек',
      '• <b>🛡 Защита от фишинга и троянов:</b> Проверка SHA-256 по базам фишинга, скама и вредоносных APK-файлов',
      '• <b>🌐 Сеть, DNS, возраст WHOIS и SSL:</b> Cloudflare DoH (SPF/DMARC/CAA), возраст домена RDAP и журналы Certificate Transparency (crt.sh)',
      '• <b>🔒 Редиректы, заголовки и DOM:</b> Раскрытие коротких ссылок, OWASP-заголовки, детектор кард-скиммеров, ClickFix и крипто-дрейнеров',
    ],
    homeTip: '💡 <i>Совет: Просто пересылайте подозрительные посты и сообщения прямо сюда — бот автоматически извлекает даже скрытые гиперссылки и ссылки из кнопок!</i>',

    // About Us Page (ONLY place where owner copyright appears)
    aboutTitle: 'ℹ️ <b>О проекте LinkLens</b>',
    aboutBody: [
      '<b>LinkLens</b> — многоуровневый сканер ссылок на фишинг, вредоносный код и утечки баз данных, работающий на платформе <b>Telegram Serverless</b>.',
      '',
      '🔬 <b>Архитектура проверки:</b>',
      '• Раскрытие коротких ссылок, аудит OWASP-заголовков и детекция кард-скиммеров / ClickFix',
      '• Глобальные движки угроз (VirusTotal v3, Google Safe Browsing v4, URLScan.io, AbuseIPDB, IPQualityScore)',
      '• Сетевая аналитика (Cloudflare DoH DNS, возраст домена IANA RDAP и сертификаты crt.sh)',
      '• Открытые базы угроз и утечек: <i>Have I Been Pwned</i>, <i>MotmaenBash</i> (CC-BY-4.0), <i>Nooshdaroo Kaveh</i> и <i>Leakfa-Alert</i> (MIT)',
      '',
      '🔒 <b>Конфиденциальность:</b> Отправленные ссылки анализируются исключительно для формирования отчёта.',
      '',
      '━━━━━━━━━━━━━━━━━━━━',
      '© 2026 <a href="https://momalekiii.github.io">momalekiii.github.io</a> — Все права защищены.',
    ],
    btnVisitWebsite: '🌐 Веб-сайт (momalekiii.github.io)',

    // Buttons (Zero sample buttons)
    btnOpenMiniApp: '🌐 Веб-сканер (Mini App)',
    btnOpenScanInApp: '🌐 Открыть отчёт в Mini App',
    btnHistory: '📜 История проверок',
    btnStats: '📊 Статистика',
    btnLanguage: '🌐 Язык',
    btnApiKeys: '📡 Статус систем',
    btnAbout: 'ℹ️ О нас',
    btnHome: '🏠 Главное меню',
    btnBack: '◀️ Назад',
    btnOpenSafeUrl: '🟢 Безопасно — Открыть ссылку',
    btnCopyDefanged: '⛔ Опасно — Скопировать обезвреженный URL',
    btnOpenLeakfaReport: '🔐 Отчёт об утечке данных',
    btnTabOverview: '🛡 Обзор',
    btnTabIran: '🔐 Утечки и базы',
    btnTabEngines: '🧬 Антивирусы / API',
    btnTabInfra: '🌐 DNS / SSL / WHOIS',
    btnTabHeaders: '🔒 Заголовки и код',
    btnCopySummary: '📋 Скопировать отчёт',
    btnForceRescan: '🔄 Пересканировать',
    btnClearHistory: '🗑 Очистить историю',
    btnShareInline: '📤 Проверить в другом чате',

    // Real-Time In-Place Live Progress Stages (1 single message updated live!)
    streamHeader: '🔍 <b>Живое глубокое сканирование LinkLens</b>',
    stage0: '0/4 Инициализация изолированного сканера…',
    stage1: '1/4 Раскрытие редиректов, расчёт SHA-256 и анализ DOM-ловушек…',
    stage2: '2/4 Запрос к VirusTotal, Safe Browsing, HIBP и базам фишинга/вредоносного ПО…',
    stage3: '3/4 Анализ DNS (Cloudflare DoH), возраста домена (RDAP) и SSL-сертификатов…',
    stage4: '4/4 Итоговая оценка риска и формирование отчёта…',
    scanStopped: '⏹ <b>Сканирование остановлено пользователем.</b> Отправьте или перешлите ссылку, когда будете готовы.',
    multiLinkProgress: '🔎 <b>Проверка ссылки {idx} из {total} в сообщении…</b>',
    multiLinkSummaryHeader: '📎 <b>Найдено ссылок в сообщении: {count}</b> (нажмите на кнопку ниже для переключения):',

    // Verdicts
    verdict_SAFE: '🟢 БЕЗОПАСНАЯ ССЫЛКА',
    verdict_LOW_RISK: '🔵 НИЗКИЙ РИСК / БЫЛИ УТЕЧКИ ДАННЫХ',
    verdict_SUSPICIOUS: '🟠 ПОДОЗРИТЕЛЬНО — БУДЬТЕ ОСТОРОЖНЫ',
    verdict_MALICIOUS: '🔴 ОПАСНО! ФИШИНГ ИЛИ ВРЕДОНОСНЫЙ САЙТ',

    // Gateway & Breach Banners
    bannerShaparakVerified: '✅ <b>ПОДТВЕРЖДЁННЫЙ ПЛАТЁЖНЫЙ ШЛЮЗ:</b> <b>{psp}</b>',
    bannerFacilitator: '🟦 <b>Лицензированный платёжный агрегатор:</b> <b>{psp}</b>',
    bannerFakeIranGateway: '🚨 <b>КРИТИЧЕСКАЯ ТРЕВОГА (ФИШИНГ):</b> Подделка под <b>«{brand}»</b> на неофициальном домене! Никогда не вводите платёжные данные!',
    bannerMotmaenBashHit: '🚨 <b>УГРОЗА В БАЗЕ АНТИФИШИНГА ({cat}):</b> SHA-256 совпал с чёрным списком для <code>{target}</code>!',
    bannerLeakfaBreach: '🔐 <b>ВНИМАНИЕ: УТЕЧКА ДАННЫХ ({site}):</b> Сам сайт настоящий, но ранее у сервиса произошла утечка базы пользователей. Смените старый пароль и включите 2FA!',

    // Report Labels
    lblRiskScore: 'Уровень риска',
    lblGrade: 'Класс защиты',
    lblInputUrl: 'Исходный URL',
    lblFinalUrl: 'Конечный адрес',
    lblDomainAge: 'Возраст домена',
    lblServerIp: 'IP и локация',
    lblSslStatus: 'SSL / TLS',
    lblHeadersGrade: 'HTTP-заголовки',
    lblEngines: 'Активные слои защиты',
    lblScanTime: 'Время проверки',
    lblCached: '⚡ Из кэша',
    lblFindings: '⚠️ Выявленные угрозы и утечки данных',
    lblNoFindings: '✅ Все активные модули проверки ссылок и баз утечек пройдены — угроз не обнаружено.',
    lblRedirectChain: '🔀 Цепочка редиректов',
    lblSpoofWarning: '🚨 <b>ОБНАРУЖЕНА ПОДМЕНА ССЫЛКИ!</b> Видимый текст показывал <code>{shown}</code>, но реально ведёт на <code>{actual}</code>!',
    lblNoUrlFound: '🔎 В сообщении не найдено ссылок.\n\nОтправьте любую ссылку напрямую или перешлите любое сообщение из Telegram — бот автоматически извлечёт и проверит все ссылки.',
    lblBlockedPrivate: '🛡 <b>Заблокировано:</b> Сканирование локальных и внутренних сетевых адресов запрещено защитой от SSRF.',
    lblHistoryTitle: '📜 <b>Последние проверенные ссылки</b>',
    lblHistoryEmpty: '📭 История проверок пуста. Отправьте любую ссылку или перешлите сообщение из Telegram!',
    lblHistoryCleared: '🗑 История сканирований очищена.',
    lblStatsTitle: '📊 <b>Ваша статистика LinkLens</b>',
    lblTotalScans: 'Проверено вами ссылок',
    lblThreatsBlocked: 'Выявлено угроз / подозрительных',
    lblGlobalScans: 'Всего проверок в боте',
    lblCurrentLang: 'Текущий язык',
    lblKeysTitle: '📡 <b>Статус систем безопасности и баз данных</b>',
    lblKeysIntro: 'Текущий статус модулей антифишинга, истории утечек, сетевой аналитики и глобальных угроз:',
    lblStatusActive: 'Активен',
    lblStatusStandby: 'Ожидание',
    lblAdminClaimed: '👑 Права администратора подтверждены.',
    lblNotAdmin: '🔒 Эта команда доступна только главному администратору бота.',
    lblKeySaved: '✅ Ключ <b>{key}</b> успешно сохранён и сразу активен для новых проверок!',
    lblFeedsSynced: '🔄 <b>Базы угроз и утечек синхронизированы!</b>\n• Антифишинг: <b>{urls}</b> фишинг-ссылок + <b>{apks}</b> APK-троянов\n• Региональные утечки: <b>{leakfa}</b> сайтов\n• Сигнатуры вредоносного ПО: <b>{kaveh}</b> хэшей\n• Have I Been Pwned: <b>{hibp}</b> мировых утечек',
    daysOld: '{days} дн.',
    unknown: 'Скрыто / Защищено реестром',
  },
};

export function t(lang) {
  return STRINGS[lang] || STRINGS.en;
}

export function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Localizes structured security finding codes cleanly into Persian / English / Russian
const FINDING_TEXT = {
  MOTMAENBASH_THREAT: {
    en: 'CRITICAL: Flagged in verified anti-phishing threat database as {category} ({target})!',
    fa: 'خطر فوری: ثبت‌شده در لیست سیاه «مطمئن‌باش» به عنوان سایت مخرب ({category} — {target})!',
    ru: 'КРИТИЧНО: Найдено в проверенной базе угроз как {category} ({target})!',
  },
  IRAN_APK_MALWARE: {
    en: 'CRITICAL: Malicious Android banking trojan / spyware signature matched in {source} ({family})!',
    fa: 'خطر فوری: فایل/بسته اندرویدی آلوده به تروجان بانکی/جاسوسی در {source} شناسایی شد ({family})!',
    ru: 'КРИТИЧНО: Обнаружен банковский Android-троян в базе {source} ({family})!',
  },
  FAKE_IRAN_GATEWAY_BRAND: {
    en: 'Counterfeit portal impersonating "{brand}" on an unofficial domain — do NOT enter card or login details!',
    fa: 'درگاه یا سامانه جعلی با سوءاستفاده از نام «{brand}» روی دامنه غیررسمی — هرگز اطلاعات کارت یا حساب وارد نکنید!',
    ru: 'Поддельный портал, мимикрирующий под «{brand}» на чужом домене — не вводите данные карты!',
  },
  SHAPARAK_HTTP_DOWNGRADE: {
    en: 'Payment gateway {host} accessed over unencrypted HTTP instead of HTTPS — do not enter card details!',
    fa: 'اتصال ناامن HTTP (بدون قفل HTTPS) روی آدرس پرداخت {host} — هرگز اطلاعات کارت وارد نکنید!',
    ru: 'Платёжный адрес {host} открыт по незашифрованному HTTP вместо HTTPS!',
  },
  IRAN_DOM_CARD_SKIMMER: {
    en: 'CRITICAL: Unofficial domain actively skimming bank card credentials (Card + CVV2 + OTP form)!',
    fa: 'خطر فوری سرقت حساب بانکی: فرم فیشینگ دریافت شماره کارت، CVV2 و رمز پویا خارج از شبکه رسمی شاپرک!',
    ru: 'КРИТИЧНО: Фишинговая форма кражи банковских карт (CVV2 + одноразовый код)!',
  },
  IRAN_GOV_APK_LURE: {
    en: 'CRITICAL: Phishing lure impersonating official public notice to push malicious APK / fee scam!',
    fa: 'خطر فوری: تله کلاهبرداری «ابلاغیه ثنا / پست / سهام عدالت» برای نصب بدافزار یا سرقت موجودی حساب!',
    ru: 'КРИТИЧНО: Фальшивое официальное уведомление, распространяющее APK-троян или фишинг!',
  },
  LEAKFA_BREACH_HISTORY: {
    en: 'Leakfa Breach Advisory: "{siteEn}" previously suffered a documented data breach — rotate reused passwords & enable 2FA.',
    fa: 'هشدار نشت اطلاعات در «لیک‌فا»: سامانه «{siteFa}» دارای سابقه نشت اطلاعات کاربران است — از رمز عبور تکراری استفاده نکنید و تایید دومرحله‌ای را فعال کنید.',
    ru: 'База Leakfa: сервис «{siteEn}» ранее подвергался утечке данных — смените старые пароли и включите 2FA.',
  },
  HIBP_BREACH_HISTORY: {
    en: 'Have I Been Pwned Advisory: "{site}" had a verified breach ({count} accounts, {date}) — practice strong password hygiene.',
    fa: 'گزارش Have I Been Pwned: وب‌سایت «{site}» سابقه نشت داده تاییدشده دارد ({count} حساب در تاریخ {date}) — رمزهای مشترک را تغییر دهید.',
    ru: 'Have I Been Pwned: у сервиса «{site}» зафиксирована утечка ({count} аккаунтов, {date}) — обновите пароль.',
  },
  SPOOFED_ENTITY: {
    en: 'Disguised hyperlink text! The clickable label impersonates a different domain.',
    fa: 'جعل هایپرلینک! متن قابل کلیک دامنه دیگری را جعل کرده است.',
    ru: 'Подмена гиперссылки! Видимый текст маскируется под другой домен.',
  },
  VT_MALICIOUS: {
    en: 'VirusTotal flagged this URL as malicious ({n} security vendors).',
    fa: 'سرویس VirusTotal این لینک را مخرب تشخیص داد ({n} موتور امنیتی).',
    ru: 'VirusTotal пометил ссылку как вредоносную ({n} антивирусных движков).',
  },
  VT_SUSPICIOUS: {
    en: 'VirusTotal marked this URL suspicious ({n} security vendors).',
    fa: 'سرویس VirusTotal این لینک را مشکوک علامت‌گذاری کرد ({n} موتور).',
    ru: 'VirusTotal отметил ссылку как подозрительную ({n} движков).',
  },
  GSB_THREAT: {
    en: 'Google Safe Browsing confirmed threat match: {threat}!',
    fa: 'هشدار رسمی Google Safe Browsing: شناسایی تهدید {threat}!',
    ru: 'Google Safe Browsing подтвердил угрозу: {threat}!',
  },
  URLSCAN_MALICIOUS: {
    en: 'URLScan.io verdict flagged malicious/phishing activity (score {n}).',
    fa: 'تحلیلگر URLScan.io فعالیت مخرب/فیشینگ گزارش کرد (امتیاز {n}).',
    ru: 'Песочница URLScan.io выявила вредоносную активность (оценка {n}).',
  },
  IPQS_HIGH_RISK: {
    en: 'IPQualityScore AI flagged elevated URL threat risk ({n}/100).',
    fa: 'هوش مصنوعی IPQualityScore ریسک بالای لینک را تشخیص داد ({n}/۱۰۰).',
    ru: 'IPQualityScore AI выявил высокий риск ссылки ({n}/100).',
  },
  ABUSEIPDB_FLAG: {
    en: 'Hosting IP has {n}% abuse confidence in AbuseIPDB ({r} reports).',
    fa: 'آی‌پی سرور در AbuseIPDB دارای {n}٪ سابقه سوءاستفاده است ({r} گزارش).',
    ru: 'IP хостинга имеет {n}% уровень жалоб в AbuseIPDB ({r} репортов).',
  },
  NEW_DOMAIN_CRITICAL: {
    en: 'Extremely young domain ({n} days old) — classic newly-registered phishing indicator!',
    fa: 'دامنه بسیار تازه‌ثبت ({n} روز قدمت) — نشانه رایج صفحات فیشینگ و کلاهبرداری!',
    ru: 'Сверхновый домен ({n} дн.) — типичный признак свежего фишингового сайта!',
  },
  NEW_DOMAIN_WARN: {
    en: 'Recently registered domain ({n} days old) — verify authenticity before entering data.',
    fa: 'دامنه به‌تازگی ثبت شده ({n} روز قدمت) — پیش از وارد کردن اطلاعات هویت سایت را بررسی کنید.',
    ru: 'Недавно зарегистрированный домен ({n} дн.) — проверьте подлинность сайта.',
  },
  PUNYCODE_HOMOGRAPH: {
    en: 'IDN Punycode (xn--) domain detected — often abused for visual lookalike attacks!',
    fa: 'دامنه بین‌المللی Punycode (xn--) شناسایی شد — رایج در حملات تشابه ظاهری حروف!',
    ru: 'Обнаружен IDN Punycode-домен (xn--) — часто используется для визуальной подмены!',
  },
  BRAND_TYPOSQUAT: {
    en: 'Brand impersonation / lookalike pattern mimicking "{brand}" on unrelated domain!',
    fa: 'الگوی جعل برند / تشابه اسمی با «{brand}» روی دامنه غیررسمی شناسایی شد!',
    ru: 'Подозрение на мимикрию под бренд «{brand}» на стороннем домене!',
  },
  RAW_IP_HOST: {
    en: 'URL uses a raw IP address instead of a domain name — frequent malware delivery pattern.',
    fa: 'آدرس به جای نام دامنه از آی‌پی مستقیم استفاده می‌کند — الگوی پرتکرار توزیع بدافزار.',
    ru: 'Используется прямой IP-адрес вместо домена — частый признак раздачи вредоносного ПО.',
  },
  USERINFO_TRICK: {
    en: 'URL embeds "@" credential syntax before host — browser navigation deception trick!',
    fa: 'کاراکتر فریبنده «@» در ساختار لینک — تکنیک کلاسیک فریب کاربر در مرورگر!',
    ru: 'В URL встроен символ «@» перед хостом — классический приём обмана в адресной строке!',
  },
  NO_HTTPS: {
    en: 'Cleartext HTTP without TLS encryption — traffic can be intercepted or modified.',
    fa: 'اتصال ناامن HTTP بدون رمزنگاری SSL/TLS — اطلاعات در مسیر قابل شنود است.',
    ru: 'Незащищённый протокол HTTP без шифрования TLS — трафик может перехватываться.',
  },
  DANGEROUS_EXTENSION: {
    en: 'Direct executable / installer payload URL ({ext}) — high malware infection risk!',
    fa: 'لینک دانلود مستقیم فایل اجرایی/نصبی ({ext}) — خطر بالای آلودگی به بدافزار!',
    ru: 'Прямая ссылка на исполняемый/установочный файл ({ext}) — высокий риск заражения!',
  },
  OPEN_REDIRECT_PARAM: {
    en: 'URL query carries an external redirect parameter ({param}) that may bounce to a trap.',
    fa: 'پارامتر تغییر مسیر خارجی ({param}) در آدرس وجود دارد که می‌تواند به سایت مخرب هدایت شود.',
    ru: 'Параметр открытого редиректа ({param}) может перенаправить на вредоносный ресурс.',
  },
  URL_SHORTENER: {
    en: 'Link uses a URL shortener service masking the true destination domain.',
    fa: 'لینک با سرویس کوتاه‌کننده پوشانده شده و مقصد واقعی در ظاهر آن مشخص نیست.',
    ru: 'Ссылка скрыта сервисом сокращения URL и маскирует конечный домен.',
  },
  CROSS_DOMAIN_REDIRECT: {
    en: 'Redirect chain switched domains ({hops} hop(s)) to {dest}.',
    fa: 'مسیر لینک با {hops} تغییر مسیر به دامنه متفاوت {dest} منتقل شد.',
    ru: 'Цепочка редиректов сменила домен ({hops} пер.) на {dest}.',
  },
  PASSWORD_FORM: {
    en: 'Page contains an active password/credential login form — never enter credentials unless verified!',
    fa: 'صفحه دارای فرم ورود رمز عبور است — تا اطمینان صددرصد از اصالت دامنه هیچ اطلاعاتی وارد نکنید!',
    ru: 'На странице обнаружена форма ввода пароля — убедитесь в подлинности домена!',
  },
  OBFUSCATED_JS: {
    en: 'Heavily obfuscated inline JavaScript detected (eval/atob/charCode patterns).',
    fa: 'اسکریپت‌های مبهم‌سازی‌شده (eval/atob) در کدهای صفحه شناسایی شد.',
    ru: 'Обнаружен обфусцированный JavaScript-код (паттерны eval/atob/fromCharCode).',
  },
  CLICKFIX_TRAP: {
    en: 'CRITICAL: Fake CAPTCHA / terminal command paste trap (ClickFix malware pattern) detected!',
    fa: 'خطر فوری: الگوی کپچای جعلی و اجرای دستور (حمله ClickFix) در صفحه شناسایی شد!',
    ru: 'КРИТИЧНО: Обнаружена фальшивая CAPTCHA / ловушка вставки команд (атака ClickFix)!',
  },
  CRYPTO_DRAINER: {
    en: 'Web3 wallet signature / approval script detected on untrusted domain (potential drainer)!',
    fa: 'اسکریپت اتصال و تایید تراکنش کیف‌پول رمزارز در دامنه ناشناس شناسایی شد (احتمال Drainer)!',
    ru: 'Обнаружен скрипт подписи криптокошелька на недоверенном домене (возможный дрейнер)!',
  },
  HIDDEN_IFRAME: {
    en: 'Hidden zero-pixel / offscreen iframe found inside page markup.',
    fa: 'آیفریم مخفی (Hidden Iframe) در کدهای HTML صفحه مشاهده شد.',
    ru: 'В коде страницы обнаружен скрытый нулевой iframe.',
  },
  WEAK_HEADERS: {
    en: 'Missing key HTTP security headers ({missing}) — weaker protection against XSS/clickjacking.',
    fa: 'برخی هدرهای امنیتی استاندارد تنظیم نشده‌اند ({missing}).',
    ru: 'Отсутствуют важные защитные HTTP-заголовки ({missing}).',
  },
  NO_EMAIL_AUTH: {
    en: 'Domain lacks DMARC anti-spoofing record in DNS.',
    fa: 'دامنه فاقد رکورد امنیتی DMARC در DNS برای جلوگیری از جعل ایمیل است.',
    ru: 'У домена отсутствует защитная DNS-запись DMARC.',
  },
  SUSPICIOUS_TLD: {
    en: 'High-abuse TLD (.{tld}) statistically prevalent in phishing & disposable campaigns.',
    fa: 'پسوند دامنه (.{tld}) جزو پسوندهای پرریسک در کمپین‌های فیشینگ است.',
    ru: 'Доменная зона (.{tld}) часто используется в фишинговых и одноразовых кампаниях.',
  },
};

export function formatFinding(finding, lang = 'en') {
  const dict = FINDING_TEXT[finding.code];
  let tpl = dict ? (dict[lang] || dict.en) : (finding.message || finding.code);
  if (finding.params) {
    for (const [k, v] of Object.entries(finding.params)) {
      tpl = tpl.replace(`{${k}}`, escapeHtml(String(v)));
    }
  }
  return tpl;
}
