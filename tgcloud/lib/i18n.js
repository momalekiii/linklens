// ============================================================================
// LinkLens Localization Engine — Persian (fa) · English (en) · Russian (ru)
// Interface language: machine-console. No emoji, terse labels, uppercase keys.
// Owner copyright appears EXCLUSIVELY on the About screen.
// ============================================================================

export const SUPPORTED_LANGS = ['fa', 'en', 'ru'];

export function isValidLang(code) {
  return SUPPORTED_LANGS.includes(code);
}

export function isRtl(lang) {
  return lang === 'fa';
}

// The gate is shown before a language is chosen, so it is rendered in the
// language Telegram reports for the client (`language_code`), not in English.
const GATE_TEXT = {
  en: {
    engine: 'link &amp; breach analysis engine',
    operator: 'operator',
    select: 'select interface language',
    received: 'link received — the scan starts once you pick a language',
  },
  fa: {
    engine: 'بررسی لینک و سابقه نشت اطلاعات',
    operator: 'کاربر',
    select: 'زبان خود را انتخاب کنید',
    received: 'لینک دریافت شد — به‌محض انتخاب زبان، بررسی شروع می‌شود',
  },
  ru: {
    engine: 'анализ ссылок и утечек данных',
    operator: 'пользователь',
    select: 'выберите язык интерфейса',
    received: 'ссылка получена — проверка начнётся после выбора языка',
  },
};

export function renderLanguageGateText(firstName = '', hasPendingUrl = false, lang = 'en') {
  const g = GATE_TEXT[lang] || GATE_TEXT.en;
  const safeName = escapeHtml(firstName || (lang === 'fa' ? 'دوست عزیز' : lang === 'ru' ? 'друг' : 'friend'));
  const rtl = lang === 'fa' ? '\u200F' : '';
  const lines = [
    '<b>LINKLENS</b>',
    `${rtl}${g.engine}`,
    '',
    `${rtl}${g.operator}: ${safeName}`,
    `${rtl}${g.select}`,
  ];
  if (hasPendingUrl) lines.push('', `${rtl}${g.received}`);
  return lines.join('\n');
}

export const STRINGS = {
  en: {
    noExternalChecks: 'External verification incomplete. No detected local warning is not evidence of safety.',
    limitedVerdict: 'Limited assessment — safety not verified',
    limitedNotice: 'Only completed checks are shown. Unavailable checks are not clean results. This is not a guarantee of safety.',

    code: 'en',
    flag: '',
    name: 'English',
    dir: 'ltr',

    langSavedToast: 'Language set: English.',
    chooseLangPrompt: '<b>LINKLENS</b>\nselect interface language',

    homeTitle: '<b>LINKLENS</b>',
    homeSubtitle: 'URL and data-breach analysis engine. Send a link or forward any message — the scan starts automatically and the report updates in place.',
    homeChecksHeader: 'capabilities',
    homeChecksList: [
      'threat intel — VirusTotal, Safe Browsing, URLScan, AbuseIPDB, IPQualityScore',
      'breach history — Have I Been Pwned + open regional feeds',
      'anti-phishing — SHA-256 blacklist matching',
      'infrastructure — DNS, RDAP domain age, TLS transparency logs',
      'content — redirect chains, OWASP headers, skimmer and ClickFix patterns',
    ],
    homeTip: 'forwarded posts, captions and inline button links are parsed automatically.',

    aboutTitle: '<b>ABOUT LINKLENS</b>',
    aboutBody: [
      'link and breach analysis engine, running natively on <b>Telegram Serverless</b>.',
      '',
      '<b>analysis layers</b>',
      '· redirect unshortening, OWASP header audit, skimmer and ClickFix detection',
      '· multi-engine threat intel (VirusTotal v3, Safe Browsing v4, URLScan.io, AbuseIPDB, IPQualityScore)',
      '· infrastructure telemetry (Cloudflare DoH, IANA RDAP age, crt.sh TLS logs)',
      '· open datasets: Have I Been Pwned, MotmaenBash (CC-BY-4.0), Nooshdaroo Kaveh, Leakfa-Alert (MIT)',
      '',
      '<b>privacy</b>',
      '· submitted links are processed only to generate the report',
      '· no analytics, no trackers, no third-party profiling',
      '· scan history can be deleted at any time',
      '',
      '──────────────',
      '© 2026 <a href="https://momalekiii.github.io">momalekiii.github.io</a>',
    ],
    btnVisitWebsite: 'Official website',

    btnHistory: 'History',
    btnStats: 'Stats',
    btnLanguage: 'Language',
    btnApiKeys: 'Service status',
    btnAbout: 'About',
    btnHome: 'Menu',
    btnBack: 'Back',
    btnOpenSafeUrl: 'Open link',
    btnCopyDefanged: 'Copy neutralized URL',
    btnOpenLeakfaReport: 'Breach report',
    btnTabOverview: 'Overview',
    btnTabIran: 'Breaches',
    btnTabEngines: 'Threat APIs',
    btnTabInfra: 'DNS / SSL',
    btnTabHeaders: 'Headers / DOM',
    btnCopySummary: 'Copy summary',
    btnForceRescan: 'Re-scan',
    btnClearHistory: 'Clear history',
    btnShareInline: 'Scan in another chat',

    streamHeader: '<b>LINKLENS</b> · scanning',
    stage0: 'initializing isolated probe',
    stage1: 'resolving redirects · hashing · parsing markup',
    stage2: 'querying threat intel and breach feeds',
    stage3: 'inspecting DNS · RDAP · TLS logs',
    stage4: 'computing risk score',
    lblScanFailed: 'the scan could not finish — one of the sources did not respond. Please try again in a moment.',
    scanStopped: 'scan stopped. send or forward a link to run again.',
    multiLinkProgress: 'scanning link {idx} of {total}',
    multiLinkSummaryHeader: '<b>{count} links detected</b> — select one:',

    verdict_SAFE: 'CLEAR',
    verdict_LOW_RISK: 'CLEAR · HYGIENE NOTE',
    verdict_SUSPICIOUS: 'CAUTION',
    verdict_MALICIOUS: 'DANGER',
    tagClear: 'CLEAR',
    tagHygiene: 'HYGIENE NOTE',
    tagCaution: 'CAUTION',
    tagDanger: 'DANGER',
    wordClean: 'clean',
    wordThreat: 'threat',
    wordVerified: 'verified',
    wordLicensed: 'licensed',
    sevCritical: 'CRITICAL',
    sevHigh: 'HIGH',
    sevMedium: 'MEDIUM',
    sevLow: 'LOW',
    sevInfo: 'NOTE',
    tlsNone: 'none · plain HTTP',
    secShort: 's',

    bannerShaparakVerified: '<b>VERIFIED GATEWAY</b> — {psp}, official HTTPS payment portal.',
    bannerFacilitator: '<b>LICENSED PAYMENT FACILITATOR</b> — {psp}',
    bannerFakeIranGateway: '<b>CRITICAL — COUNTERFEIT PORTAL</b> impersonating <b>{brand}</b>. Do not enter credentials or card data.',
    bannerMotmaenBashHit: '<b>CONFIRMED THREAT ({cat})</b> — SHA-256 blacklist match for <code>{target}</code>.',
    bannerLeakfaBreach: '<b>BREACH ADVISORY ({site})</b> — legitimate site, historical records exposed. Rotate old passwords and enable 2FA.',

    lblRiskScore: 'RISK',
    lblGrade: 'GRADE',
    lblInputUrl: 'TARGET',
    lblFinalUrl: 'FINAL',
    lblDomainAge: 'AGE',
    lblServerIp: 'HOST',
    lblSslStatus: 'TLS',
    lblHeadersGrade: 'HEADERS',
    lblEngines: 'LAYERS',
    lblFlagged: 'flagged',
    lblScanTime: 'LATENCY',
    lblCached: 'cached',
    lblFindings: 'findings',
    lblNoFindings: 'none — every active layer returned clean',
    lblRedirectChain: 'redirect chain',
    lblSpoofWarning: '<b>SPOOF DETECTED</b> — text claims <code>{shown}</code>, link points to <code>{actual}</code>.',
    lblNoUrlFound: 'no link found in that message.\n\nsend a URL directly, or forward any Telegram message containing a link, caption link or inline button link.',
    lblBlockedPrivate: '<b>BLOCKED — internal target</b>\nprivate, loopback and internal addresses are not scannable.',
    lblHistoryTitle: '<b>history</b>',
    lblHistoryEmpty: 'no scans recorded yet.',
    lblHistoryCleared: 'history cleared.',
    lblStatsTitle: '<b>stats</b>',
    lblTotalScans: 'SCANS',
    lblThreatsBlocked: 'THREATS',
    lblGlobalScans: 'NETWORK TOTAL',
    lblCurrentLang: 'LANGUAGE',
    lblKeysTitle: '<b>service status</b>',
    lblKeysIntro: 'live state of every analysis layer:',
    lblStatusActive: 'active',
    lblStatusStandby: 'standby',
    lblAdminClaimed: 'administrator access confirmed.',
    lblNotAdmin: 'restricted to the operator.',
    lblKeySaved: 'key <b>{key}</b> saved. applies to the next scan.',
    lblFeedsSynced: '<b>feeds synced</b>\nanti-phishing: <b>{urls}</b> URLs · <b>{apks}</b> banking trojans\nregional breaches: <b>{leakfa}</b> domains\nmalware signatures: <b>{kaveh}</b> hashes\nhave i been pwned: <b>{hibp}</b> breaches',
    daysOld: '{days}d old',
    unknown: 'unknown',
  },

  fa: {
    noExternalChecks: 'بررسی خارجی کامل نشده است. پیدا نشدن هشدار در بررسی محلی، به معنی ایمن بودن لینک نیست.',
    limitedVerdict: 'بررسی محدود — ایمنی تأیید نشده',
    limitedNotice: 'فقط بررسی\u200cهای انجام\u200cشده نمایش داده می\u200cشوند. منابع در دسترس\u200cنبوده به معنی پاک بودن لینک نیستند. این نتیجه تضمین ایمنی نیست.',

    code: 'fa',
    flag: '',
    name: 'فارسی',
    dir: 'rtl',

    langSavedToast: 'زبان روی فارسی تنظیم شد.',
    chooseLangPrompt: '<b>LINKLENS</b>\nزبان دلخواهتان را انتخاب کنید',

    homeTitle: '<b>LINKLENS</b>',
    homeSubtitle: 'لینک‌ها را قبل از باز کردن بررسی کنید. کافی است لینک را بفرستید یا هر پیامی را برای ربات فوروارد کنید؛ بررسی خودکار شروع می‌شود و نتیجه همان‌جا در یک پیام به‌روز می‌شود.',
    homeChecksHeader: 'چه چیزهایی بررسی می‌شود',
    homeChecksList: [
      'موتورهای امنیتی — VirusTotal، Safe Browsing، URLScan، AbuseIPDB، IPQualityScore',
      'سابقه نشت اطلاعات — Have I Been Pwned و منابع منطقه‌ای',
      'فهرست‌های ضد فیشینگ — تطبیق اثر انگشت SHA-256 با منابع ایرانی و جهانی',
      'زیرساخت دامنه — رکوردهای DNS، قدمت ثبت دامنه و گواهی SSL',
      'محتوای صفحه — زنجیره تغییر مسیر، هدرهای امنیتی و نشانه‌های فیشینگ',
    ],
    homeTip: 'پیام‌های فورواردی، متن زیر عکس‌ها و لینک‌های پنهان در دکمه‌ها هم خودکار پیدا می‌شوند.',

    aboutTitle: '<b>درباره LINKLENS</b>',
    aboutBody: [
      'سامانه بررسی لینک و نشت اطلاعات که مستقیم روی زیرساخت <b>Telegram Serverless</b> اجرا می‌شود.',
      '',
      '<b>چه کاری انجام می‌دهد</b>',
      '· لینک‌های کوتاه‌شده را باز می‌کند، هدرهای امنیتی را می‌سنجد و نشانه‌های فیشینگ را در کد صفحه پیدا می‌کند',
      '· هم‌زمان از موتورهای جهانی می‌پرسد: VirusTotal، Safe Browsing، URLScan.io، AbuseIPDB و IPQualityScore',
      '· وضعیت دامنه را بررسی می‌کند: DNS، قدمت ثبت و گواهی‌های SSL',
      '· از داده‌های باز استفاده می‌کند: Have I Been Pwned، مطمئن‌باش (CC-BY-4.0)، کاوه نوشدارو و لیک‌فا (MIT)',
      '',
      '<b>حریم خصوصی</b>',
      '· لینک‌ها فقط برای ساختن همین گزارش بررسی می‌شوند',
      '· هیچ ابزار ردیابی یا پروفایل‌سازی وجود ندارد',
      '· هر زمان بخواهید می‌توانید سابقه اسکن‌ها را پاک کنید',
      '',
      '──────────────',
      '© ۲۰۲۶ <a href="https://momalekiii.github.io">momalekiii.github.io</a>',
    ],
    btnVisitWebsite: 'وب‌سایت رسمی',

    btnOpenMiniApp: 'اسکنر وب',
    btnOpenScanInApp: 'نمایش در اسکنر وب',
    btnHistory: 'سابقه بررسی‌ها',
    btnStats: 'آمار من',
    btnLanguage: 'زبان',
    btnApiKeys: 'وضعیت سرویس‌ها',
    btnAbout: 'درباره ما',
    btnHome: 'صفحه اصلی',
    btnBack: 'بازگشت',
    btnOpenSafeUrl: 'باز کردن لینک',
    btnCopyDefanged: 'کپی لینک بی‌خطرشده',
    btnOpenLeakfaReport: 'گزارش نشت اطلاعات',
    btnTabOverview: 'خلاصه',
    btnTabIran: 'نشت اطلاعات',
    btnTabEngines: 'موتورهای امنیتی',
    btnTabInfra: 'دامنه و SSL',
    btnTabHeaders: 'هدرها و محتوا',
    btnCopySummary: 'کپی خلاصه',
    btnForceRescan: 'بررسی دوباره',
    btnClearHistory: 'پاک کردن سابقه',
    btnShareInline: 'بررسی در چت دیگر',

    streamHeader: '<b>LINKLENS</b> · در حال بررسی',
    stage0: 'آماده‌سازی بررسی',
    stage1: 'باز کردن لینک کوتاه و خواندن محتوای صفحه...',
    stage2: 'پرسیدن از موتورهای امنیتی و منابع نشت اطلاعات...',
    stage3: 'بررسی رکوردهای DNS، قدمت دامنه و گواهی SSL...',
    stage4: 'جمع‌بندی نتیجه و محاسبه امتیاز خطر',
    lblScanFailed: 'بررسی این لینک کامل نشد. یکی از منابع پاسخ نداد — لطفاً چند لحظه بعد دوباره بفرستید.',
    scanStopped: 'بررسی متوقف شد. هر وقت خواستید لینک تازه‌ای بفرستید.',
    multiLinkProgress: 'بررسی لینک {idx} از {total}',
    multiLinkSummaryHeader: '<b>{count} لینک در این پیام پیدا شد</b> — یکی را انتخاب کنید:',

    verdict_SAFE: 'بررسی شد — ایمن است',
    verdict_LOW_RISK: 'ایمن است، فقط یک نکته',
    verdict_SUSPICIOUS: 'مشکوک است، احتیاط کنید',
    verdict_MALICIOUS: 'خطرناک است، بازش نکنید',
    tagClear: 'پاک',
    tagHygiene: 'با یادآوری',
    tagCaution: 'احتیاط',
    tagDanger: 'خطر',
    wordClean: 'پاک',
    wordThreat: 'خطر شناسایی شد',
    wordVerified: 'تأییدشده',
    wordLicensed: 'دارای مجوز',
    sevCritical: 'بحرانی',
    sevHigh: 'مهم',
    sevMedium: 'متوسط',
    sevLow: 'کم',
    sevInfo: 'توجه',
    tlsNone: 'ندارد · بدون HTTPS',
    secShort: 'ثانیه',

    bannerShaparakVerified: '<b>درگاه پرداخت تأییدشده</b> — این آدرس درگاه رسمی {psp} است.',
    bannerFacilitator: '<b>پرداخت‌یار دارای مجوز</b> — {psp}',
    bannerFakeIranGateway: '<b>هشدار جدی</b> — این صفحه خودش را جای <b>{brand}</b> جا زده است. هیچ اطلاعات کارت یا رمزی وارد نکنید.',
    bannerMotmaenBashHit: '<b>تهدید تأییدشده ({cat})</b> — این آدرس در فهرست سیاه برای <code>{target}</code> ثبت شده است.',
    bannerLeakfaBreach: '<b>اطلاع‌رسانی نشت داده ({site})</b> — سایت معتبر است، اما اطلاعات کاربرانش پیش‌تر افشا شده. رمزهای قدیمی را عوض کنید و ورود دومرحله‌ای را روشن کنید.',

    lblRiskScore: 'امتیاز خطر',
    lblGrade: 'وضعیت',
    lblInputUrl: 'لینک ارسالی',
    lblFinalUrl: 'مقصد نهایی',
    lblDomainAge: 'قدمت دامنه',
    lblServerIp: 'سرور',
    lblSslStatus: 'اتصال امن',
    lblHeadersGrade: 'هدرهای امنیتی',
    lblEngines: 'لایه‌های بررسی',
    lblScanTime: 'زمان بررسی',
    lblCached: 'نتیجه ذخیره‌شده',
    lblFlagged: 'هشدار',
    lblFindings: 'نتیجه بررسی',
    lblNoFindings: 'هیچ مشکلی پیدا نشد؛ همه لایه‌ها پاک بودند.',
    lblRedirectChain: 'مسیر تغییر مسیر',
    lblSpoofWarning: '<b>لینک جعلی!</b> متن نشان می‌دهد <code>{shown}</code>، اما لینک واقعی به <code>{actual}</code> می‌رود.',
    lblNoUrlFound: 'در آن پیام لینکی پیدا نشد.\n\nلینک را مستقیم بفرستید، یا پیامی که لینک دارد (حتی در متن زیر عکس یا دکمه‌ها) را فوروارد کنید.',
    lblBlockedPrivate: '<b>این آدرس بررسی نمی‌شود</b>\nآدرس‌های داخلی و خصوصی به دلایل امنیتی بررسی نمی‌شوند.',
    lblHistoryTitle: '<b>سابقه بررسی‌ها</b>',
    lblHistoryEmpty: 'هنوز لینکی بررسی نکرده‌اید.',
    lblHistoryCleared: 'سابقه پاک شد.',
    lblStatsTitle: '<b>آمار من</b>',
    lblTotalScans: 'تعداد بررسی‌ها',
    lblThreatsBlocked: 'خطرهای شناسایی‌شده',
    lblGlobalScans: 'کل بررسی‌های ربات',
    lblCurrentLang: 'زبان',
    lblKeysTitle: '<b>وضعیت سرویس‌ها</b>',
    lblKeysIntro: 'وضعیت هر لایه بررسی در همین لحظه:',
    lblStatusActive: 'فعال',
    lblStatusStandby: 'غیرفعال',
    lblAdminClaimed: 'دسترسی مدیر تأیید شد.',
    lblNotAdmin: 'این بخش فقط برای مدیر سامانه است.',
    lblKeySaved: 'کلید <b>{key}</b> ذخیره شد و از بررسی بعدی استفاده می‌شود.',
    lblFeedsSynced: '<b>منابع به‌روز شدند</b>\nفهرست ضد فیشینگ: <b>{urls}</b> آدرس و <b>{apks}</b> بدافزار بانکی\nنشت اطلاعات منطقه‌ای: <b>{leakfa}</b> دامنه\nامضای بدافزار: <b>{kaveh}</b> مورد\nHave I Been Pwned: <b>{hibp}</b> نشت',
    daysOld: '{days} روز',
    unknown: 'نامشخص',
  },

  ru: {
    noExternalChecks: 'Внешняя проверка не завершена. Отсутствие локальных предупреждений не подтверждает безопасность.',
    limitedVerdict: 'Ограниченная проверка — безопасность не подтверждена',
    limitedNotice: 'Показаны только завершённые проверки. Недоступные источники не означают отсутствие угроз. Безопасность не гарантируется.',

    code: 'ru',
    flag: '',
    name: 'Русский',
    dir: 'ltr',

    langSavedToast: 'Язык: русский.',
    chooseLangPrompt: '<b>LINKLENS</b>\nвыберите язык интерфейса',

    homeTitle: '<b>LINKLENS</b>',
    homeSubtitle: 'Движок анализа ссылок и утечек данных. Отправьте ссылку или перешлите любое сообщение — проверка начнётся автоматически, отчёт обновится на месте.',
    homeChecksHeader: 'возможности',
    homeChecksList: [
      'threat intel — VirusTotal, Safe Browsing, URLScan, AbuseIPDB, IPQualityScore',
      'история утечек — Have I Been Pwned и открытые региональные фиды',
      'антифишинг — сверка SHA-256 с чёрным списком',
      'инфраструктура — DNS, возраст домена (RDAP), логи прозрачности TLS',
      'контент — цепочки редиректов, заголовки OWASP, скиммеры и ClickFix',
    ],
    homeTip: 'пересланные посты, подписи и ссылки в inline-кнопках извлекаются автоматически.',

    aboutTitle: '<b>О LINKLENS</b>',
    aboutBody: [
      'движок анализа ссылок и утечек данных, работающий нативно на <b>Telegram Serverless</b>.',
      '',
      '<b>слои анализа</b>',
      '· раскрытие редиректов, аудит заголовков OWASP, детект скиммеров и ClickFix',
      '· мультидвижковый threat intel (VirusTotal v3, Safe Browsing v4, URLScan.io, AbuseIPDB, IPQualityScore)',
      '· телеметрия инфраструктуры (Cloudflare DoH, возраст домена RDAP, логи TLS crt.sh)',
      '· открытые данные: Have I Been Pwned, MotmaenBash (CC-BY-4.0), Nooshdaroo Kaveh, Leakfa-Alert (MIT)',
      '',
      '<b>приватность</b>',
      '· ссылки обрабатываются только для формирования отчёта',
      '· без аналитики, трекеров и профилирования',
      '· историю проверок можно удалить в любой момент',
      '',
      '──────────────',
      '© 2026 <a href="https://momalekiii.github.io">momalekiii.github.io</a>',
    ],
    btnVisitWebsite: 'Официальный сайт',

    btnHistory: 'История',
    btnStats: 'Статистика',
    btnLanguage: 'Язык',
    btnApiKeys: 'Статус сервисов',
    btnAbout: 'О проекте',
    btnHome: 'Меню',
    btnBack: 'Назад',
    btnOpenSafeUrl: 'Открыть ссылку',
    btnCopyDefanged: 'Копировать безопасный URL',
    btnOpenLeakfaReport: 'Отчёт об утечке',
    btnTabOverview: 'Обзор',
    btnTabIran: 'Утечки',
    btnTabEngines: 'Threat APIs',
    btnTabInfra: 'DNS / SSL',
    btnTabHeaders: 'Заголовки / DOM',
    btnCopySummary: 'Копировать сводку',
    btnForceRescan: 'Проверить снова',
    btnClearHistory: 'Очистить историю',
    btnShareInline: 'Проверить в другом чате',

    streamHeader: '<b>LINKLENS</b> · сканирование',
    stage0: 'запуск изолированного зонда',
    stage1: 'раскрытие редиректов · хеширование · разбор разметки',
    stage2: 'запрос threat intel и фидов утечек',
    stage3: 'проверка DNS · RDAP · логов TLS',
    stage4: 'расчёт оценки риска',
    lblScanFailed: 'не удалось завершить проверку — один из источников не ответил. Попробуйте ещё раз через минуту.',
    scanStopped: 'сканирование остановлено. отправьте ссылку для повтора.',
    multiLinkProgress: 'проверка ссылки {idx} из {total}',
    multiLinkSummaryHeader: '<b>найдено ссылок: {count}</b> — выберите одну:',

    verdict_SAFE: 'ЧИСТО',
    verdict_LOW_RISK: 'ЧИСТО · ЗАМЕЧАНИЕ',
    verdict_SUSPICIOUS: 'ОСТОРОЖНО',
    verdict_MALICIOUS: 'ОПАСНО',
    tagClear: 'ЧИСТО',
    tagHygiene: 'ЗАМЕЧАНИЕ',
    tagCaution: 'ОСТОРОЖНО',
    tagDanger: 'ОПАСНО',
    wordClean: 'чисто',
    wordThreat: 'угроза',
    wordVerified: 'подтверждено',
    wordLicensed: 'лицензия',
    sevCritical: 'КРИТИЧНО',
    sevHigh: 'ВАЖНО',
    sevMedium: 'СРЕДНЕ',
    sevLow: 'НИЗКО',
    sevInfo: 'ИНФО',
    tlsNone: 'нет · HTTP без TLS',
    secShort: 'с',

    bannerShaparakVerified: '<b>ПОДТВЕРЖДЁННЫЙ ШЛЮЗ</b> — {psp}, официальный HTTPS-портал оплаты.',
    bannerFacilitator: '<b>ЛИЦЕНЗИРОВАННЫЙ ПЛАТЁЖНЫЙ АГЕНТ</b> — {psp}',
    bannerFakeIranGateway: '<b>КРИТИЧНО — ПОДДЕЛЬНЫЙ ПОРТАЛ</b> под именем <b>{brand}</b>. Не вводите данные карты или логин.',
    bannerMotmaenBashHit: '<b>ПОДТВЕРЖДЁННАЯ УГРОЗА ({cat})</b> — совпадение SHA-256 с чёрным списком для <code>{target}</code>.',
    bannerLeakfaBreach: '<b>УВЕДОМЛЕНИЕ ОБ УТЕЧКЕ ({site})</b> — сайт легитимный, но записи пользователей были раскрыты. Смените старые пароли и включите 2FA.',

    lblRiskScore: 'РИСК',
    lblGrade: 'КЛАСС',
    lblInputUrl: 'ЦЕЛЬ',
    lblFinalUrl: 'ФИНАЛ',
    lblDomainAge: 'ВОЗРАСТ',
    lblServerIp: 'ХОСТ',
    lblSslStatus: 'TLS',
    lblHeadersGrade: 'ЗАГОЛОВКИ',
    lblEngines: 'СЛОИ',
    lblFlagged: 'с флагом',
    lblScanTime: 'ВРЕМЯ',
    lblCached: 'кеш',
    lblFindings: 'находки',
    lblNoFindings: 'нет — все активные слои чистые',
    lblRedirectChain: 'цепочка редиректов',
    lblSpoofWarning: '<b>ОБНАРУЖЕНА ПОДМЕНА</b> — текст указывает на <code>{shown}</code>, ссылка ведёт на <code>{actual}</code>.',
    lblNoUrlFound: 'в сообщении не найдено ссылок.\n\nотправьте URL напрямую или перешлите сообщение со ссылкой, подписью или inline-кнопкой.',
    lblBlockedPrivate: '<b>ЗАБЛОКИРОВАНО — внутренний адрес</b>\nчастные, локальные и внутренние адреса не сканируются.',
    lblHistoryTitle: '<b>история</b>',
    lblHistoryEmpty: 'проверок пока нет.',
    lblHistoryCleared: 'история очищена.',
    lblStatsTitle: '<b>статистика</b>',
    lblTotalScans: 'ПРОВЕРКИ',
    lblThreatsBlocked: 'УГРОЗЫ',
    lblGlobalScans: 'ВСЕГО В СЕТИ',
    lblCurrentLang: 'ЯЗЫК',
    lblKeysTitle: '<b>статус сервисов</b>',
    lblKeysIntro: 'текущее состояние каждого слоя анализа:',
    lblStatusActive: 'активно',
    lblStatusStandby: 'ожидание',
    lblAdminClaimed: 'доступ администратора подтверждён.',
    lblNotAdmin: 'доступно только оператору.',
    lblKeySaved: 'ключ <b>{key}</b> сохранён. применится при следующей проверке.',
    lblFeedsSynced: '<b>фиды обновлены</b>\nантифишинг: <b>{urls}</b> URL · <b>{apks}</b> банковских троянов\nрегиональные утечки: <b>{leakfa}</b> доменов\nсигнатуры: <b>{kaveh}</b> хешей\nhave i been pwned: <b>{hibp}</b> утечек',
    daysOld: '{days} дн.',
    unknown: 'неизвестно',
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
