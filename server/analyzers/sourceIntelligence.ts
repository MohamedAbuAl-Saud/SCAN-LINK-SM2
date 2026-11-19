import * as cheerio from 'cheerio';
import type {
  CheckFinding,
  DiscoveredSubdomainInfo,
  FormSecurityDetail,
  SourceIntelligenceData,
  SupplyChainResourceSummary,
  SuspiciousCodeSignal,
} from '../types.ts';
import { detectCompoundBrandLookalike } from './brandIntelligence.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

export interface ExternalSourceAssetsInput {
  fetchedScripts?: { url: string; code: string }[];
  fetchedCss?: { url: string; css: string }[];
}

function classifySubdomainRole(host: string): DiscoveredSubdomainInfo['role'] {
  const lower = host.toLowerCase();
  if (/(?:^|\.)(?:auth|login|signin|sso|oauth|accounts?|id|verify|secure)\b/.test(lower)) return 'auth';
  if (/(?:^|\.)(?:api|graphql|gateway|ws|rpc|rest|backend)\b/.test(lower)) return 'api';
  if (/(?:^|\.)(?:cdn|static|assets|media|img|images|fonts|js|css|files|dl)\b/.test(lower)) return 'cdn_static';
  if (/(?:^|\.)(?:mail|smtp|imap|mx|webmail|newsletter)\b/.test(lower)) return 'mail';
  if (/(?:^|\.)(?:admin|panel|dashboard|cpanel|manage|internal|console)\b/.test(lower)) return 'admin';
  return 'general';
}

const KNOWN_CDN_DOMAINS = new Set([
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'ajax.googleapis.com',
  'code.jquery.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'cdn.tailwindcss.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
]);

const KNOWN_TRACKERS = [
  { name: 'Google Analytics / GTM', pattern: /googletagmanager\.com|google-analytics\.com|ga\.js|gtag/i },
  { name: 'Meta Pixel', pattern: /connect\.facebook\.net|fbevents\.js/i },
  { name: 'Hotjar', pattern: /hotjar\.com/i },
  { name: 'Mixpanel', pattern: /mixpanel\.com/i },
  { name: 'Sentry', pattern: /sentry\.io|browser\.sentry-cdn\.com/i },
  { name: 'Cloudflare Insights', pattern: /static\.cloudflareinsights\.com/i },
];

const VULNERABLE_LIB_PATTERNS = [
  { library: 'jQuery', pattern: /jquery[.-](\d+\.\d+\.\d+)/i, maxSafe: '3.5.0', advisory: 'jQuery <3.5.0 is vulnerable to XSS in HTML parsing.' },
  { library: 'Bootstrap JS', pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.3.1', advisory: 'Bootstrap <4.3.1 has XSS vulnerabilities in tooltip/popover data attributes.' },
  { library: 'AngularJS', pattern: /angular[.-](\d+\.\d+\.\d+)/i, maxSafe: '1.8.0', advisory: 'AngularJS 1.x has multiple prototype pollution and template injection vectors.' },
  { library: 'Lodash', pattern: /lodash[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.17.21', advisory: 'Lodash <4.17.21 is vulnerable to prototype pollution and regular expression denial of service.' },
];

export function analyzeSourceIntelligence(
  finalUrl: string,
  headers: Record<string, string>,
  htmlBuffer?: Buffer,
  externalAssets?: ExternalSourceAssetsInput
): {
  sourceIntel: SourceIntelligenceData;
  formDetails: FormSecurityDetail[];
  supplyChain: SupplyChainResourceSummary;
  findings: CheckFinding[];
} {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];

  const parsedUrl = new URL(finalUrl);
  const finalHost = parsedUrl.hostname.toLowerCase();
  const finalRegDomain = extractRegistrableDomain(finalHost);

  const securityHeaders = {
    csp: headers['content-security-policy'],
    hsts: headers['strict-transport-security'],
    xFrameOptions: headers['x-frame-options'],
    xContentTypeOptions: headers['x-content-type-options'],
    referrerPolicy: headers['referrer-policy'],
    permissionsPolicy: headers['permissions-policy'],
  };

  if (!htmlBuffer) {
    const emptySource: SourceIntelligenceData = {
      ogTags: {},
      jsonLdCount: 0,
      jsonLdTypes: [],
      baseTagHijack: false,
      securityHeaders,
      externalJsFiles: [],
      externalCssFiles: [],
      inlineJsCount: 0,
      inlineCssCount: 0,
      iframeSources: [],
      embeddedResources: [],
      hiddenInputs: [],
      suspiciousAttributes: [],
      suspiciousCodeSignals: [],
      lureExcerpts: [],
      externalCssUrls: [],
      cssExternalDomains: [],
      storageAndCookieAccess: [],
      formExfiltrationHooks: [],
      isMinifiedBundlePresent: false,
      titleContentMismatch: false,
    };
    const emptySupplyChain: SupplyChainResourceSummary = {
      totalExternalDomains: 0,
      scripts: [],
      stylesheets: [],
      iframes: [],
      fonts: [],
      imagesCount: 0,
      externalImagesCount: 0,
      apiEndpoints: [],
      trackingServices: [],
      cdnDomains: [],
      externalForms: [],
      outdatedLibraries: [],
    };
    return { sourceIntel: emptySource, formDetails: [], supplyChain: emptySupplyChain, findings };
  }

  const html = htmlBuffer.toString('utf8');
  const $ = cheerio.load(html);

  // 1. Meta Tags & Canonical
  const canonicalUrl = $('link[rel="canonical"]').attr('href')?.trim();
  const ogTags: Record<string, string> = {};
  $('meta[property^="og:"], meta[name^="og:"]').each((_, el) => {
    const prop = ($(el).attr('property') || $(el).attr('name') || '').trim();
    const content = ($(el).attr('content') || '').trim();
    if (prop) ogTags[prop] = content;
  });

  const jsonLdTypes: string[] = [];
  let jsonLdCount = 0;
  $('script[type="application/ld+json"]').each((_, el) => {
    jsonLdCount++;
    try {
      const parsed = JSON.parse($(el).html() || '{}');
      if (parsed['@type']) {
        const t = Array.isArray(parsed['@type']) ? parsed['@type'].join(', ') : String(parsed['@type']);
        jsonLdTypes.push(t);
      }
    } catch {
      // ignore
    }
  });

  // 2. Base Tag Hijacking (ignore benign same-company/authorized domains)
  const baseTagHref = $('base').attr('href')?.trim();
  let baseTagHijack = false;
  if (baseTagHref) {
    try {
      const resolvedBase = new URL(baseTagHref, finalUrl);
      const baseReg = extractRegistrableDomain(resolvedBase.hostname);
      const rel = classifyDomainRelationship(finalHost, resolvedBase.hostname);
      if (baseReg !== finalRegDomain && !rel.isBenignOrAuthorized) {
        baseTagHijack = true;
      }
    } catch {
      baseTagHijack = true;
    }
  }

  const metaRefresh = $('meta[http-equiv="refresh" i]').attr('content')?.trim();

  // 3. External & Inline Resources
  const externalJsFiles: string[] = [];
  const externalCssFiles: string[] = [];
  let inlineJsCount = 0;
  let inlineCssCount = 0;
  const iframeSources: string[] = [];
  const embeddedResources: { tag: string; src: string }[] = [];
  const externalDomainsSet = new Set<string>();

  const scriptList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const stylesheetList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const iframeList: { url: string; host: string; isThirdParty: boolean }[] = [];
  const fontList: string[] = [];
  const apiEndpointsSet = new Set<string>();
  const subdomainMap = new Map<string, Set<string>>();

  const recordSubdomainCandidate = (rawUrlOrHost: string | undefined, sourceTag: string) => {
    if (!rawUrlOrHost) return;
    try {
      const resolved = /^https?:\/\//i.test(rawUrlOrHost)
        ? new URL(rawUrlOrHost)
        : new URL(rawUrlOrHost, finalUrl);
      const h = resolved.hostname.toLowerCase().replace(/\.$/, '');
      if (!h || h === finalHost) return;
      if (extractRegistrableDomain(h) === finalRegDomain) {
        if (!subdomainMap.has(h)) subdomainMap.set(h, new Set());
        if (subdomainMap.size <= 35) subdomainMap.get(h)!.add(sourceTag);
      }
    } catch {
      // ignore invalid URL
    }
  };

  if (canonicalUrl) recordSubdomainCandidate(canonicalUrl, 'canonical');
  if (ogTags['og:url']) recordSubdomainCandidate(ogTags['og:url'], 'og:url');
  if (baseTagHref) recordSubdomainCandidate(baseTagHref, 'base');

  const brandLookalikeLinks: NonNullable<SourceIntelligenceData['brandLookalikeLinks']> = [];
  const seenLookalikeHosts = new Set<string>();
  const checkLookalikeTarget = (rawUrl: string) => {
    if (!rawUrl || !/^https?:\/\//i.test(rawUrl)) return;
    try {
      const u = new URL(rawUrl);
      const host = u.hostname.toLowerCase();
      const reg = extractRegistrableDomain(host);
      if (reg === finalRegDomain || seenLookalikeHosts.has(host)) return;
      if (lookupDomainOwnership(host).matched) return;
      const compound = detectCompoundBrandLookalike(host, reg);
      if (compound) {
        seenLookalikeHosts.add(host);
        brandLookalikeLinks.push({
          url: u.toString().slice(0, 160),
          host,
          targetBrand: compound.brand,
          officialDomain: compound.officialDomain,
          evidence: compound.evidence,
        });
      }
    } catch {
      // ignore invalid URL
    }
  };

  $('a[href]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href && !href.startsWith('#') && !/^javascript:/i.test(href)) {
      recordSubdomainCandidate(href, 'anchor');
      checkLookalikeTarget(href);
    }
  });
  $('form[action]').each((_, el) => {
    const act = ($(el).attr('action') || '').trim();
    if (act) {
      recordSubdomainCandidate(act, 'form');
      checkLookalikeTarget(act);
    }
  });
  $('img[src], source[src], video[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) recordSubdomainCandidate(src, 'media');
  });

  $('script[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) {
      externalJsFiles.push(src.slice(0, 160));
      recordSubdomainCandidate(src, 'script');
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host) || KNOWN_CDN_DOMAINS.has(reg);
        if (isTP) externalDomainsSet.add(host);
        scriptList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  $('script:not([src])').each((_, el) => {
    inlineJsCount++;
    const code = $(el).html() || '';
    // Extract static API endpoints & subdomains from JS code strings
    const urlMatches = code.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,20}(?:\/[^\s"'<>]+)?/gi) || [];
    for (const m of urlMatches) {
      if (apiEndpointsSet.size < 20) apiEndpointsSet.add(m.slice(0, 120));
      recordSubdomainCandidate(m, 'inline_js');
    }
  });

  $('link[rel="stylesheet"]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href) {
      externalCssFiles.push(href.slice(0, 160));
      recordSubdomainCandidate(href, 'stylesheet');
      try {
        const u = new URL(href, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host);
        if (isTP) externalDomainsSet.add(host);
        stylesheetList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  const externalCssUrls: string[] = [];
  const cssExternalDomainsSet = new Set<string>();
  const extractCssUrls = (cssText: string) => {
    const cssRegex = /(?:@import\s+(?:url\()?['"]?([^'")\s]+)|url\(\s*['"]?(https?:\/\/[^'")\s]+)['"]?\s*\))/gi;
    let m: RegExpExecArray | null;
    while ((m = cssRegex.exec(cssText)) !== null) {
      const rawUrl = (m[1] || m[2] || '').trim();
      if (!rawUrl || /^data:/i.test(rawUrl)) continue;
      if (externalCssUrls.length < 30) externalCssUrls.push(rawUrl.slice(0, 160));
      recordSubdomainCandidate(rawUrl, 'css');
      try {
        const u = new URL(rawUrl, finalUrl);
        const h = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(h);
        if (reg !== finalRegDomain) {
          cssExternalDomainsSet.add(h);
          externalDomainsSet.add(h);
        }
      } catch {
        // ignore invalid css url
      }
    }
  };

  $('style').each((_, el) => {
    inlineCssCount++;
    extractCssUrls($(el).html() || '');
  });
  $('[style]').each((_, el) => {
    const st = $(el).attr('style') || '';
    if (/url\(/i.test(st)) extractCssUrls(st);
  });
  for (const extCss of externalAssets?.fetchedCss || []) {
    extractCssUrls(extCss.css.slice(0, 80000));
  }

  let hiddenOverlayIframes = 0;
  $('iframe[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    const st = ($(el).attr('style') || '').toLowerCase();
    if (/opacity\s*:\s*0\b|left\s*:\s*-\d{3,}|top\s*:\s*-\d{3,}|visibility\s*:\s*hidden/.test(st)) {
      hiddenOverlayIframes++;
    }
    if (src) {
      iframeSources.push(src.slice(0, 160));
      recordSubdomainCandidate(src, 'iframe');
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const isTP = extractRegistrableDomain(host) !== finalRegDomain;
        iframeList.push({ url: u.toString(), host, isThirdParty: isTP });
      } catch {
        // ignore
      }
    }
  });

  $('[data-font], link[rel*="font"], @import').each((_, el) => {
    const href = $(el).attr('href') || $(el).attr('src') || '';
    if (/fonts\./i.test(href) || /\.woff2?/i.test(href)) {
      fontList.push(href.slice(0, 100));
    }
  });

  $('object, embed, svg').each((_, el) => {
    const src = $(el).attr('data') || $(el).attr('src') || '';
    embeddedResources.push({ tag: el.tagName.toLowerCase(), src: src.slice(0, 120) });
  });

  let imagesCount = 0;
  let externalImagesCount = 0;
  $('img[src]').each((_, el) => {
    imagesCount++;
    const src = ($(el).attr('src') || '').trim();
    if (/^https?:\/\//i.test(src)) {
      try {
        if (extractRegistrableDomain(new URL(src).hostname) !== finalRegDomain) {
          externalImagesCount++;
        }
      } catch {
        // ignore
      }
    }
  });

  // 4. Hidden Inputs & Suspicious Attributes
  const hiddenInputs: { name?: string; type: string; valuePreview?: string }[] = [];
  $('input[type="hidden"]').each((_, el) => {
    const name = $(el).attr('name') || $(el).attr('id');
    const val = $(el).attr('value') || '';
    hiddenInputs.push({ name, type: 'hidden', valuePreview: val.slice(0, 40) });
  });

  const suspiciousAttributes: { attribute: string; tag: string; snippet: string }[] = [];
  $('*').each((_, el) => {
    const node = el as any;
    const tag = (node.tagName || 'element').toLowerCase();
    for (const attr of node.attribs ? Object.keys(node.attribs) : []) {
      const val = node.attribs[attr] || '';
      if (
        /^on[a-z]+/i.test(attr) ||
        /javascript:|data:text\/html/i.test(val) ||
        (attr === 'formaction' && /^https?:\/\//i.test(val))
      ) {
        suspiciousAttributes.push({ attribute: attr, tag, snippet: `${attr}="${val.slice(0, 60)}"` });
      }
    }
  });

  // 5. Context-Aware Static JS Code Signals (inline + safely retrieved external scripts)
  const suspiciousCodeSignals: SuspiciousCodeSignal[] = [];
  const fullHtmlText = html.slice(0, 120000);
  const inlineOnlyJs = $('script:not([src])')
    .map((_, el) => $(el).html() || '')
    .get()
    .join('\n');
  const externalScriptsCode = (externalAssets?.fetchedScripts || [])
    .map((s) => `/* ext:${s.url} */\n${s.code}`)
    .join('\n');
  const externalJsInspectedCount = (externalAssets?.fetchedScripts || []).length;
  const inlineJsConcat = `${inlineOnlyJs}\n${externalScriptsCode}`.slice(0, 150000);

  const storageAndCookieAccess: string[] = [];
  if (/document\.cookie\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('document.cookie');
  if (/\blocalStorage\.(?:getItem|setItem|removeItem|clear)\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('localStorage');
  if (/\bsessionStorage\.(?:getItem|setItem|removeItem|clear)\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('sessionStorage');

  const formExfiltrationHooks: string[] = [];
  const hasSubmitListener = /addEventListener\s*\(\s*['"]submit['"]|onsubmit\s*=/i.test(inlineJsConcat);
  const hasNetworkExfil = /\bfetch\s*\(|new\s+XMLHttpRequest\b|navigator\.sendBeacon\s*\(/i.test(inlineJsConcat);
  if (hasSubmitListener && hasNetworkExfil) {
    formExfiltrationHooks.push('Form submit listener combined with asynchronous network transmission (fetch/XHR/sendBeacon)');
  }
  if (/addEventListener\s*\(\s*['"](?:keydown|keyup|input|paste)['"][\s\S]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)/i.test(inlineJsConcat)) {
    formExfiltrationHooks.push('Keystroke/input listener paired with remote HTTP transmission');
  }
  if (storageAndCookieAccess.includes('document.cookie') && hasNetworkExfil) {
    formExfiltrationHooks.push('Cookie access (document.cookie) co-occurs with asynchronous network transmission');
  }

  // Static Post-Load DOM Mutation & Client-Rendered Content Divergence Detection (without executing JS!)
  const jsDomMutationPayloads: string[] = [];
  if (
    /(?:\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write)\s*(?:=|\()[\s\S]{0,300}(?:<form|<input[^>]+password|<iframe)/i.test(
      inlineJsConcat
    )
  ) {
    jsDomMutationPayloads.push('JS dynamically injects <form>, <input type="password">, or <iframe> into DOM after page load');
  }
  if (
    /(?:\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write)\s*(?:=|\()\s*[^;\n]{0,120}\batob\s*\(/i.test(
      inlineJsConcat
    )
  ) {
    jsDomMutationPayloads.push('JS decodes Base64 payload directly into live DOM markup via innerHTML / document.write');
  }
  if (
    /(?:document\.createElement\s*\(\s*['"](?:form|iframe)['"]\s*\)|createElement\s*\(\s*['"]input['"]\s*\)[\s\S]{0,220}password)/i.test(
      inlineJsConcat
    )
  ) {
    jsDomMutationPayloads.push('JS programmatically constructs credential form or iframe elements post-load');
  }
  if (
    /setTimeout\s*\([\s\S]{0,220}(?:location(?:\.href)?\s*=|location\.replace|innerHTML\s*=)/i.test(inlineJsConcat)
  ) {
    jsDomMutationPayloads.push('Delayed timer (setTimeout) alters page DOM or triggers post-load redirect');
  }

  // Minified vs Malicious Obfuscation Classification:
  // Long compressed lines (webpack/vite bundles) WITHOUT _0x arrays or encoded eval() are standard minified code!
  const lines = inlineJsConcat.split('\n');
  const hasLongMinifiedLine = lines.some((l) => l.length > 450 && /\bfunction\b|\bconst\b|\breturn\b|=>/.test(l));
  const hasMaliciousObfuscationMarker =
    /_0x[0-9a-f]{4,}/i.test(inlineJsConcat) ||
    /eval\s*\(\s*(?:atob|unescape|decodeURIComponent|function\s*\(\s*p\s*,\s*a\s*,\s*c)/i.test(inlineJsConcat) ||
    /String\.fromCharCode\s*\([^)]{25,}\)/i.test(inlineJsConcat);
  const isMinifiedBundlePresent = Boolean(
    hasLongMinifiedLine || externalJsFiles.some((s) => /\.min\.js|bundle|chunk|vendor/i.test(s))
  );
  const obfuscationVsMinifiedNote = isMinifiedBundlePresent && !hasMaliciousObfuscationMarker
    ? {
        en: 'Detected minified/compressed JavaScript bundle without malicious obfuscation markers (_0x hex arrays or encoded eval payloads). Minified production bundles are normal and NOT treated as malicious.',
        ar: 'تم رصد أكواد JavaScript مضغوطة (Minified) دون علامات تمويه خبيث؛ ضغط الأكواد الإنتاجية أمر طبيعي ولا يُصنف كبرمجية ضارة.',
      }
    : undefined;

  if (/\beval\s*\(\s*(?:atob|unescape|decodeURIComponent)/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-eval',
      indicator: 'Encoded eval() execution',
      category: 'dynamic_eval',
      codeExcerpt: 'eval(atob/unescape/...) detected in script blocks',
      contextAssessment: {
        en: 'eval() directly executes decoded payloads at runtime, a pattern commonly used to mask malicious injections.',
        ar: 'يُستخدم eval() لتنفيذ حمولات مفكوكة الشفرة ديناميكياً، وهو نمط شائع لإخفاء الأكواد الخبيثة.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  } else if (/\beval\s*\(/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-eval',
      indicator: 'eval() usage',
      category: 'dynamic_eval',
      codeExcerpt: 'eval(...) detected in inline script',
      contextAssessment: {
        en: 'Standard eval() call present; evaluate alongside form behavior and domain identity before inferring risk.',
        ar: 'استدعاء eval() موجود في السكربت؛ يتم تقييمه ضمن السياق العام والنماذج ولا يكفي بمفرده للحكم بالخطر.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  if (/atob\s*\(|btoa\s*\(/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-base64',
      indicator: 'Base64 string decoding (atob)',
      category: 'obfuscation',
      codeExcerpt: 'atob() / btoa() encoding functions present',
      contextAssessment: {
        en: 'Base64 functions decode strings at runtime. Common in web apps for client-side state, but also used by phishing kits to conceal exfiltration URLs.',
        ar: 'تفك شفرة Base64 النصوص أثناء التشغيل؛ شائعة في التطبيقات الحديثة ولكنها تُستخدم أيضاً لإخفاء روابط الإرسال في التصيد.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  if (/document\.write\s*\(/i.test(inlineJsConcat)) {
    suspiciousCodeSignals.push({
      id: 'js-docwrite',
      indicator: 'document.write() injection',
      category: 'dom_injection',
      codeExcerpt: 'document.write(...) used in script',
      contextAssessment: {
        en: 'document.write() overwrites DOM content during page load. Legacy scripts use this, while obfuscated variants inject rogue UI.',
        ar: 'يستطيع document.write كتابة محتوى في الصفحة مباشرة أثناء التحميل.',
      },
      benignContextPossible: true,
      riskLevel: 'low',
    });
  }

  // Advanced Static JS Behavioral Forensics:
  const obfuscationMarkerMatches = inlineJsConcat.match(/_0x[0-9a-f]{4,}/gi) || [];
  if (hasMaliciousObfuscationMarker && !suspiciousCodeSignals.some((s) => s.id === 'js-obfuscation')) {
    suspiciousCodeSignals.push({
      id: 'js-obfuscation',
      indicator: 'Obfuscated identifier array / decoder packer',
      category: 'obfuscation',
      codeExcerpt: `Malicious obfuscation marker(s) detected (${obfuscationMarkerMatches.length || 1})`,
      contextAssessment: {
        en: 'Script contains _0x hex lookup arrays or CharCode packers strongly associated with phishing kits and payload concealment.',
        ar: 'يحتوي الكود على مصفوفات تعتيم برمجي أو فك تشفير نصوص تُستخدم غالباً لإخفاء أدوات التصيد.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const dynamicFormActionRewrite =
    /(?:\b\w*form\w*|\bdocument\.forms\[[^\]]+\]|querySelector\s*\([^)]*form[^)]*\))\.action\s*=|\.[a-z0-9_$]*action\s*=\s*['"`]https?:\/\/|\.action\s*=\s*['"`](?:https?:)?\/\/|setAttribute\s*\(\s*['"]action['"]/i.test(
      inlineJsConcat
    );
  if (dynamicFormActionRewrite) {
    formExfiltrationHooks.push('Script dynamically rewrites <form action> submission target');
    suspiciousCodeSignals.push({
      id: 'js-form-action-rewrite',
      indicator: 'Dynamic form.action target rewriting',
      category: 'exfiltration',
      codeExcerpt: 'Inline JS dynamically alters form.action or setAttribute("action", ...)',
      contextAssessment: {
        en: 'JavaScript modifies the form destination endpoint at runtime, a technique used by credential skimmers to redirect form submissions.',
        ar: 'يُعيد الجافاسكربت توجيه وجهة إرسال النموذج ديناميكياً أثناء التشغيل، وهو أسلوب شائع في سرقة بيانات الدخول.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const passwordFieldDomHooks =
    /input\s*\[\s*type\s*=\s*['"]?password['"]?\s*\]|getElementById\s*\(\s*['"][^'"]*pass[^'"]*['"]\s*\)/i.test(
      inlineJsConcat
    ) && hasNetworkExfil;
  if (passwordFieldDomHooks) {
    formExfiltrationHooks.push('Password field DOM access paired with background network exfiltration (fetch/XHR/sendBeacon)');
    suspiciousCodeSignals.push({
      id: 'js-password-exfil-hook',
      indicator: 'DOM password reader + background transmission',
      category: 'exfiltration',
      codeExcerpt: 'Password element selector paired with fetch / XHR / sendBeacon',
      contextAssessment: {
        en: 'Inline script reads password field values directly from the DOM alongside asynchronous HTTP transmission calls.',
        ar: 'يقرأ السكربت قيمة حقل كلمة المرور مع وجود استدعاءات إرسال شبكة في الخلفية.',
      },
      benignContextPossible: true,
      riskLevel: 'high',
    });
  }

  const walletDrainerPattern =
    /navigator\.clipboard\.writeText[\s\S]{0,220}(?:0x[a-fA-F0-9]{16,40}|bc1[a-z0-9]{10,})|(?:0x[a-fA-F0-9]{40}|eth_sendTransaction)[\s\S]{0,220}navigator\.clipboard\.writeText/i.test(
      inlineJsConcat
    );
  if (walletDrainerPattern) {
    suspiciousCodeSignals.push({
      id: 'js-wallet-clipboard-hijack',
      indicator: 'Clipboard address / crypto drainer pattern',
      category: 'clipboard',
      codeExcerpt: 'Wallet/address constant paired with navigator.clipboard.writeText',
      contextAssessment: {
        en: 'Pattern swaps copied addresses or triggers wallet transaction scripting automatically.',
        ar: 'نمط يشتبه في استبدال عنوان المحفظة في الحافظة تلقائياً أو تمرير معاملات احتيالية.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const hasPasswordOnPage = $('input[type="password"]').length > 0;
  const antiDebugTraps =
    hasPasswordOnPage &&
    (/\bdebugger\s*;/i.test(inlineJsConcat) ||
      (/oncontextmenu\s*=\s*.*return\s+false/i.test(inlineJsConcat) && /F12|ctrlKey\s*&&\s*shiftKey/i.test(inlineJsConcat)));
  if (antiDebugTraps) {
    suspiciousCodeSignals.push({
      id: 'js-anti-debug',
      indicator: 'Anti-inspection / debugger trap on credential page',
      category: 'dom_injection',
      codeExcerpt: 'DevTools inspection block or debugger trap alongside password field',
      contextAssessment: {
        en: 'Phishing kits block right-click and DevTools debugging to hinder analyst inspection of credential forms.',
        ar: 'تُعطّل صفحة تحتوي حقول كلمات مرور أدوات الفحص واختصارات المطور لإعاقة تحليل السورس.',
      },
      benignContextPossible: false,
      riskLevel: 'medium',
    });
  }

  // Title vs Actual Content Contradiction Detection
  const titleText = $('title').first().text().trim().toLowerCase();
  const cloneDoc = cheerio.load(fullHtmlText);
  cloneDoc('script, style, noscript').remove();
  const bodyPlain = cloneDoc('body').text().replace(/\s+/g, ' ').trim().toLowerCase();
  let titleContentMismatch = false;
  let titleMismatchDetail: { en: string; ar: string } | undefined;
  const authoritativeBrandsInTitle = ['google', 'microsoft', 'paypal', 'apple', 'facebook', 'instagram', 'amazon', 'netflix', 'github'].filter((b) =>
    titleText.includes(b) && !finalRegDomain.includes(b)
  );
  if (authoritativeBrandsInTitle.length > 0 && !bodyPlain.includes(authoritativeBrandsInTitle[0]) && bodyPlain.length > 40) {
    titleContentMismatch = true;
    titleMismatchDetail = {
      en: `Page <title> references "${authoritativeBrandsInTitle[0]}" while visible body text diverges from that identity.`,
      ar: `عنوان الصفحة (<title>) يذكر "${authoritativeBrandsInTitle[0]}" بينما يختلف المحتوى المرئي الفعلي عن هذه الهوية.`,
    };
  } else if (titleText.length > 5 && /(login|sign in|security|verification)/i.test(titleText) && /(airdrop|claim prize|you won|virus infected|out[- ]of[- ]date)/i.test(bodyPlain)) {
    titleContentMismatch = true;
    titleMismatchDetail = {
      en: 'Page <title> presents a security/login header while visible body content promotes deceptive alerts or prize scams.',
      ar: 'يظهر <title> كصفحة دخول أو أمان بينما يعرض المحتوى الفعلي تنبيهات مزيفة أو عروضاً احتيالية.',
    };
  }

  // 6. Detailed Per-Form Analysis (FormSecurityDetail[])
  const formDetails: FormSecurityDetail[] = [];
  $('form').each((idx, el) => {
    const action = ($(el).attr('action') || '').trim();
    const method = ($(el).attr('method') || 'GET').toUpperCase();
    const idOrName = $(el).attr('id') || $(el).attr('name');
    let resolvedHost = finalHost;
    let isCrossOrigin = false;
    let originMismatch = false;

    if (action) {
      try {
        const u = new URL(action, finalUrl);
        resolvedHost = u.hostname.toLowerCase();
        const rel = classifyDomainRelationship(finalHost, resolvedHost);
        isCrossOrigin = extractRegistrableDomain(resolvedHost) !== finalRegDomain && !rel.isBenignOrAuthorized;
        originMismatch = isCrossOrigin;
      } catch {
        // relative action
      }
    }

    const inputTypesSet = new Set<string>();
    let pwdCount = 0;
    let emailCount = 0;
    let otpCount = 0;
    let pinCount = 0;
    let cardCount = 0;
    let hiddenCount = 0;
    let invisibleCount = 0;
    const unusualAttrs: string[] = [];
    const jsHandlers: string[] = [];

    $(el)
      .find('input, select, textarea')
      .each((_, inputEl) => {
        const t = ($(inputEl).attr('type') || 'text').toLowerCase();
        inputTypesSet.add(t);
        const nameId = ($(inputEl).attr('name') || $(inputEl).attr('id') || '').toLowerCase();
        const style = ($(inputEl).attr('style') || '').toLowerCase();

        if (t === 'hidden') {
          hiddenCount++;
        } else if (t === 'password') {
          pwdCount++;
        } else if (t === 'email' || /(?:^|[^a-z])(email|user|login)(?:$|[^a-z])/.test(nameId)) {
          emailCount++;
        } else if (/(?:^|[^a-z])(otp|2fa|pin[-_ ]?code)(?:$|[^a-z])/.test(nameId)) {
          otpCount++;
        } else if (/(?:^|[^a-z])(card[-_ ]?num|cvv|cvc|ccnum)(?:$|[^a-z])/.test(nameId)) {
          cardCount++;
        }

        if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b/.test(style)) {
          invisibleCount++;
        }

        for (const attr of inputEl.attribs ? Object.keys(inputEl.attribs) : []) {
          if (/^on[a-z]+/i.test(attr)) jsHandlers.push(attr);
        }
      });

    let formRisk: FormSecurityDetail['riskLevel'] = 'informational';
    const reasonEn: string[] = [];
    const reasonAr: string[] = [];

    if (isCrossOrigin && pwdCount > 0) {
      formRisk = 'critical';
      reasonEn.push('Password form submits to an external cross-origin domain.');
      reasonAr.push('نموذج كلمة المرور يرسل البيانات إلى نطاق خارجي مختلف.');
    } else if (pwdCount > 0 && !action) {
      formRisk = formExfiltrationHooks.length > 0 && /Keystroke/i.test(formExfiltrationHooks.join(' ')) ? 'high' : 'informational';
      reasonEn.push('Password form handles submission via client script / SPA state (no HTML action attribute). Verify exact domain identity.');
      reasonAr.push('يتعامل نموذج كلمة المرور مع الإرسال عبر السكربت المحلي (SPA) بدون وسم action؛ تحقق من هوية النطاق.');
    } else if (pwdCount > 0) {
      formRisk = 'informational';
      reasonEn.push('Standard same-origin password authentication form.');
      reasonAr.push('نموذج تسجيل دخول قياسي يرسل البيانات لنفس النطاق.');
    }

    formDetails.push({
      pageUrl: finalUrl,
      formIndex: idx + 1,
      idOrName,
      action: action || '[empty / current page]',
      resolvedActionHost: resolvedHost,
      method,
      usesHttps: finalUrl.startsWith('https://'),
      isCrossOrigin,
      originMismatch,
      inputTypes: Array.from(inputTypesSet),
      passwordCount: pwdCount,
      emailCount,
      otpCount,
      pinCount,
      cardCount,
      hiddenCount,
      invisibleCount,
      unusualAttributes: unusualAttrs,
      jsHandlers,
      riskLevel: formRisk,
      reason: {
        en: reasonEn.join(' ') || 'Standard form structure.',
        ar: reasonAr.join(' ') || 'بنية نموذج قياسية.',
      },
    });
  });

  // 7. Supply Chain Analysis & Outdated Libraries
  const trackingServices: { name: string; host: string }[] = [];
  for (const trk of KNOWN_TRACKERS) {
    for (const sc of scriptList) {
      if (trk.pattern.test(sc.url)) {
        if (!trackingServices.some((t) => t.name === trk.name)) {
          trackingServices.push({ name: trk.name, host: sc.host });
        }
      }
    }
  }

  const cdnDomains = Array.from(externalDomainsSet).filter((d) => KNOWN_CDN_DOMAINS.has(d));
  const outdatedLibraries: { library: string; detectedVersion: string; sourceUrl: string; advisory: string }[] = [];

  for (const sc of scriptList) {
    for (const libDef of VULNERABLE_LIB_PATTERNS) {
      const match = sc.url.match(libDef.pattern);
      if (match?.[1]) {
        outdatedLibraries.push({
          library: libDef.library,
          detectedVersion: match[1],
          sourceUrl: sc.url,
          advisory: libDef.advisory,
        });
      }
    }
  }

  const supplyChain: SupplyChainResourceSummary = {
    totalExternalDomains: externalDomainsSet.size,
    scripts: scriptList,
    stylesheets: stylesheetList,
    iframes: iframeList,
    fonts: fontList,
    imagesCount,
    externalImagesCount,
    apiEndpoints: Array.from(apiEndpointsSet),
    trackingServices,
    cdnDomains,
    externalForms: formDetails.filter((f) => f.isCrossOrigin).map((f) => f.action),
    outdatedLibraries,
  };

  const discoveredSubdomains: DiscoveredSubdomainInfo[] = Array.from(subdomainMap.entries()).map(([host, srcSet]) => {
    const role = classifySubdomainRole(host);
    const hasRiskyContext = (hasPasswordOnPage || formDetails.some((f) => f.isCrossOrigin)) && (role === 'auth' || role === 'admin');
    return {
      host,
      sources: Array.from(srcSet),
      role,
      suspiciousRole: hasRiskyContext,
    };
  });

  const bodyWordCount = bodyPlain ? bodyPlain.split(' ').length : 0;
  const hasSpaMountRoot = Boolean(
    $('#root, #app, #__next, #__nuxt, app-root').length > 0 || $('noscript').text().toLowerCase().includes('javascript')
  );
  const dynamicContentAfterJsLikely = Boolean(
    jsDomMutationPayloads.length > 0 || (hasSpaMountRoot && bodyWordCount < 35 && (inlineJsCount > 0 || externalJsFiles.length > 0))
  );

  const staticVsRenderedNote = dynamicContentAfterJsLikely
    ? jsDomMutationPayloads.length > 0
      ? {
          en: `Level A Static Analysis detected client-side JS scripts designed to inject/replace DOM content or redirect after initial load (${jsDomMutationPayloads[0]}). Level B isolated browser execution is not active locally; findings are based on inspected static source payloads.`,
          ar: `رصد التحليل الساكن (المستوى A) سكربتات JavaScript تُغيّر محتوى DOM أو تُعيد التوجيه بعد التحميل الأولي (${jsDomMutationPayloads[0]}). بيئة المتصفح المعزولة (المستوى B) غير متاحة محلياً؛ لذا تستند النتائج لقراءة السورس الفعلي.`,
        }
      : {
          en: 'Page serves a thin client-rendered JavaScript shell (SPA mount root with minimal static HTML text). Full post-render DOM requires an isolated headless browser (Level B, currently inactive); Level A inspected static HTML and accessible scripts only.',
          ar: 'تعتمد الصفحة على تطبيق JavaScript يُنشئ المحتوى بعد التحميل (SPA). قراءة شجرة DOM النهائية بعد التشغيل تتطلب متصفحاً معزولاً (المستوى B غير مفعّل محلياً)، وقد جرى فحص HTML والسكربتات المتاحة ساكنياً عبر المستوى A.',
        }
    : undefined;

  if (jsDomMutationPayloads.length > 0 && !suspiciousCodeSignals.some((s) => s.id === 'js-dom-mutation')) {
    const injectsSensitiveDom = jsDomMutationPayloads.some((m) => /<form|password|<iframe|atob/i.test(m));
    suspiciousCodeSignals.push({
      id: 'js-dom-mutation',
      indicator: 'Post-load JS DOM mutation / hidden markup injection',
      category: 'dom_injection',
      codeExcerpt: jsDomMutationPayloads[0],
      contextAssessment: {
        en: injectsSensitiveDom
          ? 'Inline/fetched JS constructs forms, password inputs, or decoded HTML fragments dynamically after page load—a classic cloaking technique to bypass static scanners.'
          : 'Script modifies DOM nodes or redirects asynchronously after a timer.',
        ar: injectsSensitiveDom
          ? 'يحقن الجافاسكربت نماذج إدخال أو حقول كلمة مرور أو شيفرة HTML مفكوكة بعد تحميل الصفحة؛ وهو أسلوب إخفاء لتفادي فحص HTML الساكن.'
          : 'يُعدّل السكربت عناصر الصفحة أو يوجهها بعد مؤقت زمني.',
      },
      benignContextPossible: !injectsSensitiveDom,
      riskLevel: injectsSensitiveDom ? 'high' : 'low',
    });
  }

  const sourceIntel: SourceIntelligenceData = {
    canonicalUrl,
    ogTags,
    jsonLdCount,
    jsonLdTypes,
    baseTagHref,
    baseTagHijack,
    metaRefresh,
    securityHeaders,
    externalJsFiles,
    externalCssFiles,
    inlineJsCount,
    inlineCssCount,
    iframeSources,
    embeddedResources,
    hiddenInputs,
    suspiciousAttributes,
    suspiciousCodeSignals,
    lureExcerpts: [],
    externalCssUrls,
    cssExternalDomains: Array.from(cssExternalDomainsSet),
    storageAndCookieAccess,
    formExfiltrationHooks,
    isMinifiedBundlePresent,
    obfuscationVsMinifiedNote,
    titleContentMismatch,
    titleMismatchDetail,
    discoveredSubdomains,
    brandLookalikeLinks,
    jsDomMutationPayloads,
    dynamicContentAfterJsLikely,
    staticVsRenderedNote,
    externalJsInspectedCount,
    jsBehaviorSummary: {
      dynamicFormActionRewrite,
      passwordFieldDomHooks,
      walletDrainerPattern,
      antiDebugTraps,
      hiddenOverlayIframes,
      obfuscationMarkerCount: obfuscationMarkerMatches.length,
    },
  };

  // Findings generation for Source Intelligence, JS Behavior, HTML Semantics & Discovered Subdomains
  if (baseTagHijack) {
    findings.push({
      id: 'source-base-tag-hijack',
      section: 'source_intelligence',
      test: { en: 'Base HTML Tag Hijack Check', ar: 'فحص التلاعب بوسم القاعدة HTML <base>' },
      result: { en: `Deceptive <base href="${baseTagHref}"> points to external host`, ar: `وسم <base href="${baseTagHref}"> يشير لنطاق خارجي` },
      status: 'failed',
      severity: 'high',
      weight: 24,
      evidence: `Base href: ${baseTagHref}`,
      explanation: {
        en: 'A malicious <base> tag redirects all relative links and resource paths to an attacker-controlled domain.',
        ar: 'يعيد وسم <base> الخبيث توجيه كافة الروابط النسبية وملفات الموقع نحو خادم يسيطر عليه المهاجم.',
      },
      recommendedAction: {
        en: 'Do not interact with this page; base-tag hijacking is a classic phishing cloaking technique.',
        ar: 'لا تتفاعل مع هذه الصفحة؛ التلاعب بوسم القاعدة هو أسلوب تصيد كلاسيكي.',
      },
      source: 'SM Source Intelligence',
      timestamp: now,
      confidence: 98,
    });
  }

  // Source Finding A: JavaScript Static Behavioral Forensics
  const highJsSignals = suspiciousCodeSignals.filter((s) => s.riskLevel === 'high' || s.riskLevel === 'critical');
  const medJsSignals = suspiciousCodeSignals.filter((s) => s.riskLevel === 'medium');
  const hasSeriousJsBehavior =
    highJsSignals.length >= 1 ||
    (hasMaliciousObfuscationMarker && formExfiltrationHooks.length > 0) ||
    dynamicFormActionRewrite ||
    walletDrainerPattern;
  const hostOwnershipSrc = classifyDomainRelationship(finalHost, finalHost);
  const suppressSpaHookOnOfficial = hostOwnershipSrc.isSameOrganization && highJsSignals.every((s) => s.benignContextPossible);

  const jsBehaviorFailed = hasSeriousJsBehavior && !suppressSpaHookOnOfficial;
  const jsBehaviorWarn = !jsBehaviorFailed && medJsSignals.length > 0 && !suppressSpaHookOnOfficial;

  findings.push({
    id: 'source-js-behavior',
    section: 'javascript_analysis',
    test: { en: 'Deep Source & JavaScript Behavioral Inspection', ar: 'التحليل العميق لسورس الموقع وسلوكيات JavaScript' },
    result: jsBehaviorFailed
      ? {
          en: `${highJsSignals.length} high-risk JS pattern(s): ${highJsSignals.map((s) => s.indicator).slice(0, 2).join('; ')}`,
          ar: `رصد ${highJsSignals.length} سلوكاً خطيراً في أكواد JavaScript: ${highJsSignals.map((s) => s.indicator).slice(0, 2).join('؛ ')}`,
        }
      : jsBehaviorWarn
        ? {
            en: `${medJsSignals.length} defensive/anti-analysis JS indicator(s) recorded`,
            ar: `رصد ${medJsSignals.length} مؤشر تعطيل فحص في كود JavaScript`,
          }
        : isMinifiedBundlePresent && !hasMaliciousObfuscationMarker
          ? {
              en: `Inspected ${inlineJsCount} inline & ${externalJsFiles.length} external JS files (standard minified production bundles verified clean)`,
              ar: `فحص ${inlineJsCount} سكربت داخلي و ${externalJsFiles.length} خارجي (حزم مضغوطة قياسية سليمة دون تمويه خبيث)`,
            }
          : {
              en: `Inspected ${inlineJsCount} inline & ${externalJsFiles.length} external JS files — no exfiltration or malicious obfuscation detected`,
              ar: `فحص ${inlineJsCount} سكربت داخلي و ${externalJsFiles.length} خارجي — خالية من التمويه الخبيث وخطافات التسريب`,
            },
    status: jsBehaviorFailed ? 'failed' : jsBehaviorWarn ? 'warning' : 'pass',
    severity: jsBehaviorFailed ? 'high' : jsBehaviorWarn ? 'medium' : 'informational',
    weight: jsBehaviorFailed ? (highJsSignals.length >= 2 || dynamicFormActionRewrite || walletDrainerPattern ? 26 : 20) : jsBehaviorWarn ? 10 : 0,
    evidence: `InlineJS: ${inlineJsCount} | ExtJS: ${externalJsFiles.length} | MinifiedOnly: ${isMinifiedBundlePresent && !hasMaliciousObfuscationMarker} | HighSignals: [${highJsSignals.map((s) => s.indicator).join(', ') || 'none'}] | ExfilHooks: [${formExfiltrationHooks.join('; ') || 'none'}] | StorageAccess: [${storageAndCookieAccess.join(', ') || 'none'}]`,
    explanation: {
      en: jsBehaviorFailed
        ? 'Static inspection of retrieved JavaScript code identified high-risk runtime patterns such as encoded eval() unpacking, obfuscated _0x arrays, dynamic form.action rewriting, or background credential/clipboard exfiltration.'
        : 'Deep static reading of page scripts confirmed clean code patterns without encoded payload unpacking or hidden credential exfiltration hooks.',
      ar: jsBehaviorFailed
        ? 'كشف الفحص الفعلي لسورس JavaScript عن أنماط برمجية عالية الخطورة مثل فك تشفير وتشغيل eval أو مصفوفات _0x المشوشة أو تغيير وجهة إرسال النماذج أو تسريب البيانات في الخلفية.'
        : 'أكدت قراءة سورس JavaScript الفعلي سلامة الأكواد وخلوها من التعتيم الخبيث أو خطافات سرقة البيانات.',
    },
    recommendedAction: {
      en: jsBehaviorFailed ? 'Do not enter credentials or allow clipboard/wallet access on this page.' : 'No action required.',
      ar: jsBehaviorFailed ? 'لا تُدخل أي بيانات أو تمنح صلاحيات للحافظة أو المحفظة في هذه الصفحة.' : 'لا يلزم إجراء.',
    },
    source: 'SM Deep Source & JS Forensics',
    timestamp: now,
    confidence: jsBehaviorFailed ? 94 : 90,
  });

  // Source Finding B: HTML Semantics, Title-vs-Body & Clickjacking Structure
  let metaRefreshExternal = false;
  if (metaRefresh) {
    const urlPart = metaRefresh.match(/url\s*=\s*['"]?([^'";\s]+)/i)?.[1];
    if (urlPart) {
      try {
        const u = new URL(urlPart, finalUrl);
        if (extractRegistrableDomain(u.hostname) !== finalRegDomain && !classifyDomainRelationship(finalHost, u.hostname).isBenignOrAuthorized) {
          metaRefreshExternal = true;
        }
      } catch {
        // ignore
      }
    }
  }
  const crossOriginFormActionAttr = suspiciousAttributes.some((a) => a.attribute === 'formaction');
  const hasHtmlStructureFail = titleContentMismatch || metaRefreshExternal || crossOriginFormActionAttr;
  const hasHtmlStructureWarn = !hasHtmlStructureFail && hiddenOverlayIframes > 0;

  findings.push({
    id: 'source-html-structure',
    section: 'source_intelligence',
    test: { en: 'HTML DOM Structure, Meta & Title Integrity', ar: 'فحص بنية HTML وسلامة العنوان والوسوم المخفية' },
    result: titleContentMismatch && titleMismatchDetail
      ? titleMismatchDetail
      : metaRefreshExternal
        ? { en: `External <meta http-equiv="refresh"> redirects off-domain (${metaRefresh?.slice(0, 60)})`, ar: `وسم <meta refresh> يحوّل إلى نطاق خارجي غير مرتبط` }
        : crossOriginFormActionAttr
          ? { en: 'Button formaction attribute overrides submission to external domain', ar: 'سمة formaction تعيد توجيه إرسال النموذج إلى نطاق خارجي' }
          : hiddenOverlayIframes > 0
            ? { en: `${hiddenOverlayIframes} invisible/off-screen iframe overlay detected in HTML`, ar: `رصد ${hiddenOverlayIframes} إطار iframe مخفي قد يُستخدم لخطف النقرات` }
            : {
                en: `HTML structure verified clean (${hiddenInputs.length} hidden inputs, 0 external meta redirects, consistent <title>)`,
                ar: `بنية HTML متسقة وسليمة (${hiddenInputs.length} مدخلات مخفية، 0 تحويلات meta خارجية، عنوان متطابق)`,
              },
    status: hasHtmlStructureFail ? 'failed' : hasHtmlStructureWarn ? 'warning' : 'pass',
    severity: hasHtmlStructureFail ? 'high' : hasHtmlStructureWarn ? 'medium' : 'informational',
    weight: hasHtmlStructureFail ? 20 : hasHtmlStructureWarn ? 10 : 0,
    evidence: `TitleMismatch: ${titleContentMismatch} | MetaRefreshExternal: ${metaRefreshExternal} | CrossOriginFormaction: ${crossOriginFormActionAttr} | HiddenOverlayIframes: ${hiddenOverlayIframes} | JSON-LD: ${jsonLdCount}`,
    explanation: {
      en: hasHtmlStructureFail
        ? 'Retrieved HTML markup contains deceptive metadata (<title> brand mismatch against body copy, off-domain meta refresh redirect, or cross-origin formaction override).'
        : 'Retrieved HTML markup semantics (<title>, meta tags, form targets, iframes) align consistently with the page domain.',
      ar: hasHtmlStructureFail
        ? 'يكشف فحص كود HTML الفعلي عن تلاعب واضح في البنية أو انتحال في وسم <title> مقابل المحتوى أو إعادة توجيه مخفية.'
        : 'وسوم HTML وبنية الصفحة تتطابق بسلاسة مع النطاق والغرض المعروض.',
    },
    recommendedAction: {
      en: hasHtmlStructureFail ? 'Verify the true domain and avoid submitting data on pages with conflicting metadata.' : 'No action required.',
      ar: hasHtmlStructureFail ? 'تحقق من النطاق الحقيقي وتجنب إدخال البيانات في صفحات متضاربة البنية.' : 'لا يلزم إجراء.',
    },
    source: 'SM HTML Source Inspector',
    timestamp: now,
    confidence: 92,
  });

  // Source Finding C: In-Page Discovered Subdomains & Third-Party Topology
  const suspiciousSubdomains = discoveredSubdomains.filter((s) => s.suspiciousRole);
  findings.push({
    id: 'source-discovered-subdomains',
    section: 'source_intelligence',
    test: { en: 'Discovered Site Subdomains & Reference Topology', ar: 'اكتشاف النطاقات الفرعية وروابط البنية داخل الموقع' },
    result:
      discoveredSubdomains.length > 0
        ? {
            en: `${discoveredSubdomains.length} sibling subdomain(s) discovered under ${finalRegDomain}: ${discoveredSubdomains.slice(0, 4).map((s) => s.host).join(', ')}`,
            ar: `تم اكتشاف ${discoveredSubdomains.length} نطاق فرعي ضمن ${finalRegDomain}: ${discoveredSubdomains.slice(0, 4).map((s) => s.host).join('، ')}`,
          }
        : {
            en: `No additional subdomains under ${finalRegDomain} referenced in page HTML (${externalDomainsSet.size} external resource host(s))`,
            ar: `لم ترد نطاقات فرعية إضافية تحت ${finalRegDomain} في كود الصفحة (${externalDomainsSet.size} مضيف موارد خارجي)`,
          },
    status: suspiciousSubdomains.length > 0 ? 'warning' : 'pass',
    severity: 'informational',
    weight: 0,
    evidence: `Subdomains[${discoveredSubdomains.length}]: [${discoveredSubdomains.map((s) => `${s.host}(${s.role})`).join(', ') || 'none'}] | ExtResourceDomains: [${Array.from(externalDomainsSet).slice(0, 8).join(', ') || 'none'}]`,
    explanation: {
      en: 'Enumerates subdomains and external asset origins referenced directly inside HTML anchors, scripts, forms, stylesheets, and inline JavaScript.',
      ar: 'يستخرج النطاقات الفرعية ومصادر الموارد المذكورة داخل كود HTML والنماذج والسكربتات لتحليل البنية الفعلية للموقع.',
    },
    recommendedAction: {
      en: 'Inspect unfamiliar authentication or admin subdomains discovered inside third-party pages.',
      ar: 'راجع أي نطاقات فرعية غريبة مرتبطة بتسجيل الدخول أو الإرسال.',
    },
    source: 'SM Subdomain & Source Mapper',
    timestamp: now,
    confidence: 90,
  });

  if (brandLookalikeLinks.length > 0) {
    findings.push({
      id: 'source-brand-lookalike-links',
      section: 'source_intelligence',
      test: { en: 'Outbound Brand-Lookalike Link Analysis', ar: 'فحص الروابط الصادرة المشابهة للعلامات التجارية' },
      result: {
        en: `${brandLookalikeLinks.length} outbound link(s)/form(s) point to brand-lookalike host (${brandLookalikeLinks[0].host})`,
        ar: `رصد ${brandLookalikeLinks.length} رابط أو نموذج يشير إلى نطاق مشابه لعلامة تجارية (${brandLookalikeLinks[0].host})`,
      },
      status: 'warning',
      severity: 'medium',
      weight: 14,
      evidence: brandLookalikeLinks.map((l) => `${l.host} -> ${l.targetBrand} (${l.officialDomain})`).join(' | '),
      explanation: {
        en: 'Source code inspection identified outbound hyperlinks or form endpoints pointing to domains that imitate well-known official brands.',
        ar: 'كشف تحليل السورس عن روابط أو وجهات نماذج تشير إلى نطاقات تتشابه اسمياً مع علامات تجارية رسمية معروفة.',
      },
      recommendedAction: {
        en: 'Verify any outbound authentication or payment links before following them.',
        ar: 'تحقق من أي روابط أو وجهات إرسال قبل الانتقال إليها.',
      },
      source: 'SM Source Link Analyzer',
      timestamp: now,
      confidence: 88,
    });
  }

  if (!securityHeaders.csp) {
    findings.push({
      id: 'source-csp-missing',
      section: 'source_intelligence',
      test: { en: 'Content Security Policy (CSP) Header', ar: 'ترويسة سياسة أمان المحتوى (CSP)' },
      result: { en: 'Content-Security-Policy header is missing', ar: 'ترويسة Content-Security-Policy مفقودة' },
      status: 'warning',
      severity: 'informational',
      weight: 0,
      evidence: 'Missing CSP header in HTTP response',
      explanation: {
        en: 'Absence of a Content Security Policy allows browser execution of injected scripts if an XSS vulnerability occurs.',
        ar: 'غياب سياسة CSP يتيح للمتصفح تنفيذ أي سكربت محقون في حال وجود ثغرة XSS.',
      },
      recommendedAction: {
        en: 'Implement a strict CSP policy in production.',
        ar: 'تفعيل سياسة CSP صارمة في بيئة الإنتاج.',
      },
      source: 'SM Header Inspector',
      timestamp: now,
      confidence: 100,
    });
  }

  return { sourceIntel, formDetails, supplyChain, findings };
}
