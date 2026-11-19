import net from 'node:net';
import { domainToASCII, domainToUnicode } from 'node:url';
import { parse as parseTldts } from 'tldts';
import type { CheckFinding } from '../types.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'cutt.ly', 'rb.gy', 'shorturl.at',
  'tiny.cc', 'lnkd.in', 'rebrand.ly', 's.id', 'v.gd', 'clk.sh', 't.ly', 'short.io', 'x.co',
]);

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'icu', 'club',
  'work', 'click', 'link', 'loan', 'download', 'stream', 'bid', 'win', 'xin', 'cfd', 'sbs', 'rest', 'cam',
]);

const MULTI_TENANT_PAAS_SUFFIXES: { suffix: string; provider: string }[] = [
  { suffix: 'sites.google.com', provider: 'Google Sites' },
  { suffix: 'appspot.com', provider: 'Google App Engine' },
  { suffix: 'firebaseapp.com', provider: 'Firebase Hosting' },
  { suffix: 'web.app', provider: 'Firebase Hosting' },
  { suffix: 'github.io', provider: 'GitHub Pages' },
  { suffix: 'pages.dev', provider: 'Cloudflare Pages' },
  { suffix: 'workers.dev', provider: 'Cloudflare Workers' },
  { suffix: 'vercel.app', provider: 'Vercel' },
  { suffix: 'netlify.app', provider: 'Netlify' },
  { suffix: 'herokuapp.com', provider: 'Heroku' },
  { suffix: 'blogspot.com', provider: 'Blogger' },
  { suffix: 'weebly.com', provider: 'Weebly' },
  { suffix: '000webhostapp.com', provider: '000webhost' },
  { suffix: 's3.amazonaws.com', provider: 'AWS S3' },
  { suffix: 'blob.core.windows.net', provider: 'Azure Blob Storage' },
  { suffix: 'trycloudflare.com', provider: 'Cloudflare Quick Tunnel' },
  { suffix: 'ngrok-free.app', provider: 'ngrok Tunnel' },
  { suffix: 'ngrok.io', provider: 'ngrok Tunnel' },
  { suffix: 'up.railway.app', provider: 'Railway Hosted App' },
  { suffix: 'onrender.com', provider: 'Render' },
  { suffix: 'fly.dev', provider: 'Fly.io' },
  { suffix: 'hf.space', provider: 'Hugging Face Spaces' },
  { suffix: 'gitlab.io', provider: 'GitLab Pages' },
  { suffix: 'webflow.io', provider: 'Webflow Staging' },
  { suffix: 'notion.site', provider: 'Notion Public Sites' },
  { suffix: 'wixsite.com', provider: 'Wix Free Sites' },
  { suffix: 'wordpress.com', provider: 'WordPress.com' },
  { suffix: 'replit.dev', provider: 'Replit' },
  { suffix: 'glitch.me', provider: 'Glitch' },
];

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.scr',
  '.pif', '.com', '.hta', '.cpl', '.lnk', '.iso', '.img', '.apk', '.dmg', '.pkg',
]);

const SUSPICIOUS_PARAM_KEYS = [
  'redirect', 'redirect_uri', 'redirect_url', 'next', 'url', 'target', 'dest', 'destination',
  'redir', 'continue', 'return', 'returnurl', 'return_url', 'goto', 'callback', 'login', 'email', 'u', 'cmd', 'exec',
];

const PHISHING_LEXICAL_TOKENS = [
  'login', 'signin', 'verify', 'verification', 'account', 'update', 'secure',
  'security', 'banking', 'wallet', 'confirm', 'suspend', 'locked', 'unlock',
  'webscr', 'billing', 'invoice', 'recover', 'auth', 'sso', 'phish', 'phishing',
];

export interface UrlIntelResult {
  findings: CheckFinding[];
  isShortener: boolean;
  isMultiTenantPaas: boolean;
  paasProvider?: string;
  registrableDomain: string;
  publicSuffix: string;
  unicodeDomain: string;
  asciiDomain: string;
  suspiciousPathTokens: string[];
}

export function extractPslBreakdown(hostname: string): {
  eTldPlusOne: string;
  publicSuffix: string;
  subdomain: string;
  isIp: boolean;
} {
  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (net.isIP(clean) !== 0) {
    return { eTldPlusOne: clean, publicSuffix: '', subdomain: '', isIp: true };
  }
  const parsed = parseTldts(clean, { allowPrivateDomains: false });
  if (parsed.domain && parsed.publicSuffix) {
    return {
      eTldPlusOne: parsed.domain,
      publicSuffix: parsed.publicSuffix,
      subdomain: parsed.subdomain || '',
      isIp: Boolean(parsed.isIp),
    };
  }
  const parts = clean.split('.').filter(Boolean);
  return {
    eTldPlusOne: parts.length >= 2 ? parts.slice(-2).join('.') : clean,
    publicSuffix: parts.length >= 2 ? parts[parts.length - 1] : '',
    subdomain: parts.length > 2 ? parts.slice(0, -2).join('.') : '',
    isIp: false,
  };
}

export function extractRegistrableDomain(hostname: string): string {
  return extractPslBreakdown(hostname).eTldPlusOne;
}

export function detectPaasHosting(asciiDomain: string): { isPaas: boolean; provider?: string } {
  const host = asciiDomain.toLowerCase();
  for (const entry of MULTI_TENANT_PAAS_SUFFIXES) {
    if (host === entry.suffix || host.endsWith(`.${entry.suffix}`)) {
      return { isPaas: true, provider: entry.provider };
    }
  }
  return { isPaas: false };
}

function tryDecodeBase64Payload(val: string): string | null {
  if (val.length < 12 || !/^[A-Za-z0-9+/_-]+=*$/.test(val)) return null;
  try {
    const normalized = val.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = Buffer.from(normalized, 'base64').toString('utf8');
    if (/https?:\/\/|@|<script|SELECT\s+|javascript:/i.test(decoded)) {
      return decoded.slice(0, 120);
    }
  } catch {
    return null;
  }
  return null;
}

export function analyzeUrlIntelligence(submittedUrl: string, normalizedUrl: string): UrlIntelResult {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const parsed = new URL(normalizedUrl);
  const hostname = parsed.hostname.toLowerCase();
  const asciiDomain = domainToASCII(hostname) || hostname;
  const unicodeDomain = domainToUnicode(asciiDomain) || hostname;
  const psl = extractPslBreakdown(asciiDomain);
  const registrableDomain = psl.eTldPlusOne;
  const publicSuffix = psl.publicSuffix;
  const tld = asciiDomain.split('.').pop() || '';
  const isIpLiteral = net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;
  const paas = detectPaasHosting(asciiDomain);
  const ownership = lookupDomainOwnership(asciiDomain);

  // 1. Transport Protocol & Unusual Port Check
  const isHttps = parsed.protocol === 'https:';
  const port = parsed.port ? Number(parsed.port) : isHttps ? 443 : 80;
  const unusualPort = (isHttps && port !== 443) || (!isHttps && port !== 80);

  findings.push({
    id: 'url-protocol-port',
    section: 'url_intelligence',
    test: { en: 'Transport Protocol & Port Inspection', ar: 'فحص بروتوكول النقل والمنفذ' },
    result: {
      en: `${parsed.protocol.replace(':', '').toUpperCase()} on port ${port}${unusualPort ? ' (unusual port)' : ''}`,
      ar: `${parsed.protocol.replace(':', '').toUpperCase()} على المنفذ ${port}${unusualPort ? ' (منفذ غير قياسي)' : ''}`,
    },
    status: !isHttps || unusualPort ? 'warning' : 'pass',
    severity: !isHttps || unusualPort ? 'medium' : 'informational',
    weight: !isHttps ? 12 : unusualPort ? 8 : 0,
    evidence: `Protocol: ${parsed.protocol} | Port: ${port} | HTTPS alone is transport encryption, not proof of site legitimacy.`,
    explanation: {
      en: !isHttps
        ? 'Unencrypted HTTP allows network observers to read or modify credentials and content in transit.'
        : unusualPort
          ? `Service listens on non-standard port ${port}, often used by temporary phishing kits or C2 panels.`
          : 'URL uses HTTPS on standard port 443. Phishing sites frequently use valid HTTPS certificates.',
      ar: !isHttps
        ? 'الاتصال غير مشفر عبر HTTP مما يعرض البيانات المرسلة للاعتراض أو التعديل.'
        : unusualPort
          ? `يستخدم الرابط منفذاً غير قياسي (${port}) وهو شائع في خوادم الاستغلال المؤقتة.`
          : 'يستخدم الرابط بروتوكول HTTPS على المنفذ القياسي 443؛ علماً بأن التشفير لا يثبت سلامة الموقع.',
    },
    recommendedAction: {
      en: !isHttps ? 'Never enter passwords or payment details over plain HTTP.' : 'Verify domain identity and content checks regardless of HTTPS.',
      ar: !isHttps ? 'لا تدخل أي كلمات مرور أو بيانات دفع عبر اتصال HTTP غير مشفر.' : 'تحقق من هوية النطاق ومحتوى الصفحة بغض النظر عن وجود HTTPS.',
    },
    forensic: {
      whereDetected: { en: `URL scheme "${parsed.protocol}" and port ${port}`, ar: `مخطط الرابط "${parsed.protocol}" والمنفذ ${port}` },
      whyRisky: {
        en: !isHttps ? 'Cleartext transport leaks passwords.' : unusualPort ? 'Non-standard ports bypass casual user inspection.' : 'HTTPS encrypts transport only.',
        ar: !isHttps ? 'الاتصال غير المشفر يكشف كلمات المرور.' : 'المنافذ غير القياسية تُستخدم غالباً في خدمات غير قياسية.',
      },
      howExploited: {
        en: 'Intercepted HTTP sessions or ephemeral custom-port C2/phishing listeners.',
        ar: 'اعتراض الجلسات غير المشفرة أو استضافة أدوات خبيثة على منافذ غير قياسية.',
      },
      userImpact: { en: 'Credential interception or rogue listener access.', ar: 'اعتراض بيانات الدخول أو الوصول لخدمة غير موثوقة.' },
      notProvenAlone: {
        en: 'Using HTTPS does NOT prove safety; similarly, plain HTTP alone does not prove active phishing.',
        ar: 'وجود HTTPS لا يعني الأمان، ووجود HTTP وحده لا يثبت التصيد.',
      },
    },
    source: 'SM URL Parser',
    timestamp: now,
    confidence: 100,
  });

  // 2. IP-Based URL Detection
  if (isIpLiteral) {
    findings.push({
      id: 'url-ip-literal',
      section: 'url_intelligence',
      test: { en: 'IP-Based Hostname Check', ar: 'فحص استخدام عنوان IP مباشر' },
      result: { en: `Raw IP address used (${hostname})`, ar: `استخدام عنوان IP مباشر (${hostname})` },
      status: 'failed',
      severity: 'high',
      weight: 22,
      evidence: `Host is literal IP: ${hostname}`,
      explanation: {
        en: 'Legitimate consumer services do not direct users to raw IP addresses; attackers use IP URLs to bypass domain reputation and age checks.',
        ar: 'نادراً ما تطلب المواقع الموثوقة زيارة عنوان IP مباشر؛ وغالباً ما يُستخدم لتجاوز فحوصات سمعة النطاقات.',
      },
      recommendedAction: {
        en: 'Do not authenticate or download files from raw IP-based web URLs.',
        ar: 'تجنب تسجيل الدخول أو تنزيل الملفات من روابط تعتمد على عناوين IP مباشرة.',
      },
      forensic: {
        whereDetected: { en: `Hostname literal IP: ${hostname}`, ar: `اسم المضيف عنوان IP مباشر: ${hostname}` },
        whyRisky: { en: 'Direct IP links evade domain age, RDAP, and registrar accountability.', ar: 'تتجاوز الروابط المباشرة بعناوين IP فحوصات عمر النطاق ومسجل النطاقات.' },
        howExploited: { en: 'Hosted temporarily on compromised VPS servers to distribute malware or phishing forms.', ar: 'استضافة مؤقتة على خوادم مخترقة لتوزيع برمجيات خبيثة أو صفحات تصيد.' },
        userImpact: { en: 'Connection to unverified infrastructure without domain identity.', ar: 'اتصال بخادم غير معروف الهوية.' },
        notProvenAlone: { en: 'Some routers/enterprise endpoints use public IPs legitimately, but consumer login links never should.', ar: 'قد تستخدم بعض الأجهزة الإدارية عناوين IP لكنها غير مخصصة لروابط تسجيل دخول المستهلكين.' },
      },
      source: 'SM URL Parser',
      timestamp: now,
      confidence: 100,
    });
  }

  // 3. Subdomain Depth & Multi-Tenant PaaS Hosting Context
  const labels = asciiDomain.split('.');
  const subdomainDepth = Math.max(0, labels.length - 2);
  const excessiveSubdomains = !isIpLiteral && !ownership.matched && !paas.isPaas && subdomainDepth >= 3;
  findings.push({
    id: 'url-subdomain-paas',
    section: 'url_intelligence',
    test: { en: 'Subdomain Structure & Hosting Platform Context', ar: 'بنية النطاقات الفرعية وسياق الاستضافة المشتركة' },
    result: paas.isPaas
      ? {
          en: `Hosted on shared multi-tenant PaaS (${paas.provider}) · Contextual note (judged by content & URL)`,
          ar: `مستضاف على منصة سحابية مشتركة (${paas.provider}) · ملاحظة سياقية (يُحكم بالمحتوى والرابط)`,
        }
      : ownership.matched && ownership.isSubdomain
        ? {
            en: `Official Subdomain (${asciiDomain}) under ${registrableDomain} (${ownership.entity?.parentCompany})`,
            ar: `نطاق فرعي رسمي (${asciiDomain}) تابع للنطاق ${registrableDomain}`,
          }
        : {
            en: `${subdomainDepth} subdomain level(s) (${registrableDomain})`,
            ar: `${subdomainDepth} مستوى نطاق فرعي (${registrableDomain})`,
          },
    status: excessiveSubdomains ? 'warning' : 'pass',
    severity: excessiveSubdomains ? 'medium' : 'informational',
    weight: excessiveSubdomains ? 10 : 0,
    evidence: `Host: ${asciiDomain} | Registrable: ${registrableDomain} | Shared PaaS: ${paas.isPaas ? paas.provider : 'No'} | OfficialRegistry: ${ownership.matched ? ownership.entity?.parentCompany : 'No'}`,
    explanation: {
      en: paas.isPaas
        ? `This URL is hosted on ${paas.provider} (${registrableDomain}). Anyone can deploy arbitrary pages on shared PaaS subdomains; therefore parent domain age and valid TLS belong to ${paas.provider}, NOT the hosted page owner.`
        : ownership.matched && ownership.isSubdomain
          ? `${asciiDomain} is an authentic subdomain directly beneath the official registrable domain ${registrableDomain}.`
          : excessiveSubdomains
            ? 'Excessive subdomain chaining can push the actual registrable domain off-screen on mobile browsers.'
            : 'Subdomain structure is within normal bounds.',
      ar: paas.isPaas
        ? `هذا الرابط مستضاف على منصة ${paas.provider} المشتركة؛ لذا فإن عمر النطاق وشهادة التشفير تخص المزود ولا تثبت موثوقية المحتوى المنشور.`
        : ownership.matched && ownership.isSubdomain
          ? `النطاق الفرعي ${asciiDomain} يتبع مباشرة النطاق الرسمي المسجل ${registrableDomain}.`
          : excessiveSubdomains
            ? 'كثرة النطاقات الفرعية قد تخفي النطاق الحقيقي على شاشات الهواتف.'
            : 'بنية النطاقات الفرعية طبيعية.',
    },
    recommendedAction: {
      en: paas.isPaas ? 'Judge the page strictly by its content, forms, and behavior—not the PaaS domain age.' : 'No action required.',
      ar: paas.isPaas ? 'قيّم الصفحة بناءً على محتواها وسلوكها الفعلي لا بناءً على سمعة مزود الاستضافة.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `Hostname hierarchy "${asciiDomain}"`, ar: `تسلسل النطاقات "${asciiDomain}"` },
      whyRisky: {
        en: 'Multi-tenant PaaS domains and temporary tunnels inherit the parent vendor domain age and HTTPS certificate.',
        ar: 'تستفيد الصفحات على المنصات السحابية المشتركة من قِدم النطاق الأم وشهادة التشفير التلقائية.',
      },
      howExploited: {
        en: 'Phishers deploy credential kits on free PaaS subdomains to appear trusted.',
        ar: 'ينشر المهاجمون صفحات تصيد على نطاقات فرعية مجانية لإظهار النطاق كخدمة موثوقة.',
      },
      userImpact: {
        en: 'Users assume vendor reputation covers third-party deployed apps.',
        ar: 'يظن المستخدم أن سمعة مزود الخدمة السحابية تحمي الصفحة المنشورة.',
      },
      notProvenAlone: {
        en: 'PaaS hosting (Firebase, Vercel, GitHub Pages) hosts millions of legitimate apps; it requires content correlation before declaring risk.',
        ar: 'الاستضافة على Firebase أو Vercel أو GitHub Pages لا تثبت وحدها أي خطر ما لم تقترن بمؤشرات تصيد في المحتوى.',
      },
    },
    source: 'SM URL & PaaS Classifier',
    timestamp: now,
    confidence: 95,
  });

  // 4. URL Length, Double Encoding & Base64 Payload Inspection
  const doubleEncoded = /%25[0-9a-fA-F]{2}/.test(normalizedUrl);
  const percentMatches = normalizedUrl.match(/%[0-9a-fA-F]{2}/g) || [];
  const excessiveLength = normalizedUrl.length > 220;
  const base64Findings: string[] = [];
  const nestedUrls: string[] = [];

  for (const [k, v] of parsed.searchParams.entries()) {
    const kl = k.toLowerCase();
    if (SUSPICIOUS_PARAM_KEYS.includes(kl) || /https?:\/\//i.test(v)) {
      if (/https?:\/\/|^\/\/[a-z0-9]/i.test(v)) {
        try {
          const targetUrlObj = new URL(v.startsWith('//') ? `https:${v}` : v);
          const rel = classifyDomainRelationship(asciiDomain, targetUrlObj.hostname);
          if (!rel.isBenignOrAuthorized) {
            nestedUrls.push(`${k}=${v.slice(0, 70)}`);
          }
        } catch {
          nestedUrls.push(`${k}=${v.slice(0, 70)}`);
        }
      }
    }
    const decodedB64 = tryDecodeBase64Payload(v);
    if (decodedB64) {
      base64Findings.push(`${k} -> "${decodedB64}"`);
    }
  }

  const hasEncodingAnomaly =
    doubleEncoded || percentMatches.length >= 16 || base64Findings.length > 0 || nestedUrls.length > 0;
  findings.push({
    id: 'url-encoding-obfuscation',
    section: 'url_intelligence',
    test: { en: 'URL Encoding, Nested URLs & Payload Obfuscation', ar: 'فحص الترميز المزدوج والروابط المتداخلة والحمولات المشفرة' },
    result: hasEncodingAnomaly
      ? {
          en: `Anomalies: ${[doubleEncoded ? 'double-encoding' : '', nestedUrls.length ? `${nestedUrls.length} nested URL(s)` : '', base64Findings.length ? `${base64Findings.length} Base64 payload(s)` : '', excessiveLength ? `${normalizedUrl.length} chars` : ''].filter(Boolean).join(', ')}`,
          ar: `رصد مؤشرات: ${[doubleEncoded ? 'ترميز مزدوج' : '', nestedUrls.length ? `${nestedUrls.length} رابط متداخل` : '', base64Findings.length ? `${base64Findings.length} حمولة Base64` : '', excessiveLength ? `${normalizedUrl.length} حرف` : ''].filter(Boolean).join('، ')}`,
        }
      : { en: `Clean parameters (${normalizedUrl.length} chars, 0 obfuscated payloads)`, ar: `معاملات نظيفة (${normalizedUrl.length} حرف)` },
    status: doubleEncoded || base64Findings.length > 0 ? 'failed' : hasEncodingAnomaly ? 'warning' : 'pass',
    severity: doubleEncoded || base64Findings.length > 0 ? 'high' : hasEncodingAnomaly ? 'medium' : 'informational',
    weight: (doubleEncoded ? 15 : 0) + (base64Findings.length > 0 ? 14 : 0) + (nestedUrls.length > 0 ? 8 : 0),
    evidence: `DoubleEncoded: ${doubleEncoded} | Nested: [${nestedUrls.join('; ') || 'none'}] | Base64: [${base64Findings.join('; ') || 'none'}] | Length: ${normalizedUrl.length}`,
    explanation: {
      en: hasEncodingAnomaly
        ? 'Double encoding, Base64-encoded parameters, or external nested URLs can be used to mask open redirects or phishing targets.'
        : 'Query parameters and URL encoding fall within standard web patterns.',
      ar: hasEncodingAnomaly
        ? 'يُستخدم الترميز المزدوج وحمولات Base64 والروابط المتداخلة لإخفاء وجهات التوجيه الخارجية.'
        : 'معاملات الرابط وترميزها ضمن النمط القياسي.',
    },
    recommendedAction: {
      en: hasEncodingAnomaly ? 'Inspect decoded destination parameters before trusting this link.' : 'No action required.',
      ar: hasEncodingAnomaly ? 'تحقق من الوجهات المفككة داخل معاملات الرابط قبل الوثوق به.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `URL path & query string (${normalizedUrl.length} chars)`, ar: `مسار الرابط ومعاملاته (${normalizedUrl.length} حرف)` },
      whyRisky: { en: 'Encoded parameters obscure final destinations or prefill victim email addresses on credential kits.', ar: 'تخفي المعاملات المشفرة الوجهة النهائية أو تمرر بريد الضحية تلقائياً لنموذج التصيد.' },
      howExploited: { en: 'Base64-encoded URLs or "%252f" bypasses evade static URL keyword filters.', ar: 'تجاوز مرشحات الأمان باستخدام الترميز المزدوج أو Base64.' },
      userImpact: { en: 'Hidden tracking, auto-redirect to attacker domain, or pre-filled phishing login.', ar: 'نقل مخفي إلى موقع خبيث أو ملء مسبق لبيانات الضحية.' },
      notProvenAlone: { en: 'Long OAuth/tracking URLs often embed legitimate return URLs; review alongside actual redirect hops.', ar: 'تستخدم روابط OAuth والحملات التسويقية معاملات طويلة بشكل مشروع أحياناً.' },
    },
    source: 'SM URL Obfuscation Analyzer',
    timestamp: now,
    confidence: 92,
  });

  // 5. Shorteners, Suspicious TLDs, Lexical Tokens & Misleading Extensions (word-boundary safe)
  const lowerPathAndHost = `${asciiDomain}${parsed.pathname}`.toLowerCase();
  const suspiciousPathTokens = PHISHING_LEXICAL_TOKENS.filter((t) =>
    new RegExp(`(?:^|[^a-z0-9])${t}(?:$|[^a-z0-9])`).test(lowerPathAndHost)
  );
  const extMatch = parsed.pathname.toLowerCase().match(/\.[a-z0-9]{1,6}$/)?.[0] || '';
  const hasExecutableExt = EXECUTABLE_EXTENSIONS.has(extMatch);
  const misleadingDoubleExt = /\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(html?|htm|exe|scr|js|zip)$/i.test(parsed.pathname);
  const suspiciousTld = !isIpLiteral && !ownership.matched && SUSPICIOUS_TLDS.has(tld);
  const isShortener = URL_SHORTENERS.has(asciiDomain) || URL_SHORTENERS.has(registrableDomain);

  findings.push({
    id: 'url-shortener-check',
    section: 'url_intelligence',
    test: { en: 'URL Shortener Detection', ar: 'فحص خدمات تقصير الروابط' },
    result: isShortener
      ? { en: `Shortened URL (${registrableDomain}) — final hop resolved separately`, ar: `رابط مختصر (${registrableDomain}) — يتم تتبع الوجهة النهائية` }
      : { en: 'Direct URL (not a known shortener)', ar: 'رابط مباشر (ليس خدمة اختصار)' },
    status: isShortener ? 'warning' : 'pass',
    severity: isShortener ? 'low' : 'informational',
    weight: isShortener ? 4 : 0,
    evidence: `Registrable domain: ${registrableDomain}`,
    explanation: {
      en: isShortener
        ? 'Shortened links mask the final destination until followed. Shortening alone is not proof of malice, so redirect tracing determines the true target.'
        : 'The submitted link is not routed through a recognized URL-shortening service.',
      ar: isShortener
        ? 'تخفي الروابط المختصرة الوجهة النهائية حتى يتم تتبعها؛ ولذلك يتم فحص الوجهة النهائية بشكل مستقل.'
        : 'الرابط لا يمر عبر خدمة اختصار روابط معروفة.',
    },
    recommendedAction: {
      en: isShortener ? 'Review the Final Resolved Destination before opening.' : 'No action required.',
      ar: isShortener ? 'راجع الوجهة النهائية المعلنة في التقرير قبل زيارة الرابط.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `Submitted domain "${registrableDomain}"`, ar: `النطاق المُدخل "${registrableDomain}"` },
      whyRisky: { en: 'Hides the true destination domain until an HTTP redirect executes.', ar: 'يُخفي اسم الموقع الحقيقي حتى لحظة الضغط وإعادة التوجيه.' },
      howExploited: { en: 'Phishers use shorteners to conceal newly registered or abusive landing domains.', ar: 'يخفي المهاجم روابط النطاقات الحديثة أو المشبوهة خلف رابط مختصر.' },
      userImpact: { en: 'Blind navigation to an unknown host.', ar: 'انتقال أعمى إلى موقع غير معروف مسبقاً.' },
      notProvenAlone: { en: 'URL shorteners are widely used legitimately on social media; always judge by the final destination checks.', ar: 'تُستخدم خدمات التقصير بكثرة بشكل مشروع؛ والحكم يعتمد على الوجهة النهائية.' },
    },
    source: 'SM URL Parser',
    timestamp: now,
    confidence: 95,
  });

  // On verified official corporate domains, standard login/account paths like accounts.google.com or github.com/login are normal
  const effectiveSuspiciousTokens = ownership.matched ? [] : suspiciousPathTokens;
  const lexicalAlert =
    hasExecutableExt || misleadingDoubleExt || suspiciousTld || effectiveSuspiciousTokens.length >= 1;
  findings.push({
    id: 'url-lexical-extensions',
    section: 'url_intelligence',
    test: { en: 'Lexical Tokens, TLD & Misleading Extensions', ar: 'الكلمات المفتاحية وامتداد النطاق والملفات المضللة' },
    result: misleadingDoubleExt
      ? { en: `Misleading double extension detected (${parsed.pathname.slice(-30)})`, ar: 'تم رصد امتداد ملف مزدوج مضلل' }
      : hasExecutableExt
        ? { en: `Executable/script extension in URL (${extMatch})`, ar: `امتداد تنفيذي خطير في الرابط (${extMatch})` }
        : lexicalAlert
          ? {
              en: `${effectiveSuspiciousTokens.length} sensitive token(s)${suspiciousTld ? `, high-abuse TLD (.${tld})` : ''}`,
              ar: `${effectiveSuspiciousTokens.length} كلمة حساسة${suspiciousTld ? `، نطاق عالي المخاطر (.${tld})` : ''}`,
            }
          : ownership.matched && suspiciousPathTokens.length > 0
            ? {
                en: `Standard service endpoint on verified official domain (${suspiciousPathTokens.join(', ')})`,
                ar: `مسار خدمة قياسي على نطاق رسمي موثق (${suspiciousPathTokens.join('، ')})`,
              }
            : { en: 'No suspicious lexical tokens or risky extensions', ar: 'لا توجد كلمات حساسة أو امتدادات خطرة' },
    status: misleadingDoubleExt || hasExecutableExt ? 'failed' : lexicalAlert ? 'warning' : 'pass',
    severity: misleadingDoubleExt || hasExecutableExt ? 'high' : suspiciousTld || effectiveSuspiciousTokens.length >= 2 ? 'medium' : lexicalAlert ? 'low' : 'informational',
    weight: misleadingDoubleExt
      ? 24
      : hasExecutableExt
        ? 20
        : (suspiciousTld ? 8 : 0) + Math.min(12, effectiveSuspiciousTokens.length * 5),
    evidence: `Tokens: [${suspiciousPathTokens.join(', ') || 'none'}] | OfficialContext: ${ownership.matched} | TLD: .${tld} | Ext: ${extMatch || 'none'}`,
    explanation: {
      en: misleadingDoubleExt || hasExecutableExt
        ? 'URL path mimics a document or points directly to an executable/script payload, posing immediate malware risk.'
        : lexicalAlert
          ? 'URL path/host uses credential or phishing-associated keywords or a high-abuse TLD on an unverified domain.'
          : 'No deceptive file extensions or unverified phishing keyword clusters found in the URL string.',
      ar: misleadingDoubleExt || hasExecutableExt
        ? 'ينتهي مسار الرابط بامتداد مزدوج مضلل أو ملف تنفيذي مباشر يمثل خطراً أمنياً.'
        : lexicalAlert
          ? 'يحتوي مسار الرابط على كلمات مرتبطة بتسجيل الدخول أو نطاق عالي الاستغلال على نطاق غير موثق.'
          : 'لم يتم رصد امتدادات ملفات مضللة أو تجمعات كلمات تصيد مشبوهة في بنية الرابط.',
    },
    recommendedAction: {
      en: lexicalAlert ? 'Cross-check these URL signals with content and domain verification findings.' : 'No action required.',
      ar: lexicalAlert ? 'اربط هذه المؤشرات بنتائج فحص المحتوى والنطاق قبل اتخاذ قرار.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `URL host/path "${asciiDomain}${parsed.pathname}"`, ar: `مسار ونطاق الرابط "${asciiDomain}${parsed.pathname}"` },
      whyRisky: { en: 'High-abuse TLDs and login/verify keywords are heavily concentrated in phishing URLs.', ar: 'تتركز الكلمات المتعلقة بالتحقق وتسجيل الدخول وامتدادات الملفات الخطرة في روابط التصيد.' },
      howExploited: { en: 'Tricks users into believing an HTML phishing page or executable is a harmless PDF/invoice or official login portal.', ar: 'إيهام الضحية بأن الملف مستند آمن أو صفحة تحقق رسمية.' },
      userImpact: { en: 'Malware execution or credential compromise.', ar: 'تشغيل برمجية خبيثة أو سرقة الحساب.' },
      notProvenAlone: { en: 'Legitimate sites have "/login" paths too; keywords never elevate risk on verified official domains and require corroborating evidence elsewhere.', ar: 'وجود كلمة "login" أو امتداد TLD معين لا يثبت التصيد وحده دون ارتباطه بمحتوى أو بنية غير موثوقة.' },
    },
    source: 'SM Lexical Engine',
    timestamp: now,
    confidence: 90,
  });

  return {
    findings,
    isShortener,
    isMultiTenantPaas: paas.isPaas,
    paasProvider: paas.provider,
    registrableDomain,
    publicSuffix,
    unicodeDomain,
    asciiDomain,
    suspiciousPathTokens,
  };
}
