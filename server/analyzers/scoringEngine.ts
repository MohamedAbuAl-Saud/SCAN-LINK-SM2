import type {
  BilingualText,
  CheckFinding,
  CheckStatus,
  DomainIntelData,
  FinalVerdict,
  RedirectHop,
  RiskClassification,
  RiskSeverity,
  ScanReportDomainAuthenticity,
  SeparatedPillarAssessment,
  TechnicalSectionId,
  TechnicalSectionSummary,
  ThreatProviderResult,
  TlsInspectionData,
} from '../types.ts';
import type { DomainAuthenticityAssessment } from './officialDomainRegistry.ts';

export interface ScoringContext {
  domainAuthenticity?: DomainAuthenticityAssessment;
  tlsData?: TlsInspectionData;
  dnsData?: DomainIntelData;
  redirects?: RedirectHop[];
  finalUrl?: string;
}

const SECTION_TITLES: Record<TechnicalSectionId, BilingualText> = {
  url_intelligence: { en: '1. URL Intelligence', ar: '١. استخبارات بنية الرابط' },
  domain_deception: { en: '2. Domain Deception & Identity', ar: '٢. خداع النطاق والانتحال البصري' },
  redirect_analysis: { en: '3. Redirect Analysis', ar: '٣. تحليل إعادة التوجيه' },
  domain_intelligence: { en: '4. Domain & Registration Intel', ar: '٤. استخبارات النطاق والتسجيل' },
  dns_analysis: { en: '5. DNS & Network Resolution', ar: '٥. تحليل سجلات DNS والشبكة' },
  ssl_tls_analysis: { en: '6. SSL/TLS Certificate', ar: '٦. تحليل شهادة SSL/TLS' },
  website_content: { en: '7. Website Content & Structure', ar: '٧. فحص محتوى الموقع وبنيته' },
  source_intelligence: { en: '8. Website Source Intelligence', ar: '٨. استخبارات مصدر الموقع الأمني' },
  page_discovery: { en: '9. Multi-Page Discovery & Inspection', ar: '٩. استكشاف وفحص الصفحات المتعددة' },
  phishing_detection: { en: '10. Phishing & Lure Detection', ar: '١٠. كشف التصيد وأساليب الخداع' },
  brand_impersonation: { en: '11. Brand Impersonation', ar: '١١. كشف انتحال العلامات' },
  javascript_analysis: { en: '12. JavaScript Static Analysis', ar: '١٢. التحليل الساكن للجافاسكربت' },
  supply_chain_analysis: { en: '13. Supply Chain & External Resources', ar: '١٣. سلسلة التوريد والموارد الخارجية' },
  file_download_analysis: { en: '14. File & Download Analysis', ar: '١٤. تحليل الملفات والتنزيلات' },
  external_threat_intel: { en: '15. External Threat Intelligence', ar: '١٥. استخبارات التهديدات الخارجية' },
  screenshot_evidence: { en: '16. Screenshot Evidence', ar: '١٦. المعاينة البصرية للموقع' },
};

const SECTION_ORDER: TechnicalSectionId[] = [
  'url_intelligence',
  'domain_deception',
  'redirect_analysis',
  'domain_intelligence',
  'dns_analysis',
  'ssl_tls_analysis',
  'website_content',
  'source_intelligence',
  'page_discovery',
  'phishing_detection',
  'brand_impersonation',
  'javascript_analysis',
  'supply_chain_analysis',
  'file_download_analysis',
  'external_threat_intel',
  'screenshot_evidence',
];

const POSTURE_ONLY_FINDING_IDS = new Set(['source-csp-missing', 'dns-email-security', 'domain-age']);

function enrichFindingMetadata(f: CheckFinding): void {
  if (!f.lastUpdated) {
    f.lastUpdated = f.timestamp;
  }
  if (!f.reliabilityLabel) {
    f.reliabilityLabel = f.confidence >= 85 ? 'High' : f.confidence >= 60 ? 'Medium' : 'Low';
  }
  if (!f.riskImpact) {
    if (f.status === 'pass' || f.status === 'unknown' || f.weight <= 0) {
      f.riskImpact = 'none';
    } else if (f.severity === 'critical' || f.weight >= 30) {
      f.riskImpact = 'critical';
    } else if (f.severity === 'high' || f.weight >= 18) {
      f.riskImpact = 'high';
    } else if (f.severity === 'medium' || f.weight >= 8) {
      f.riskImpact = 'medium';
    } else {
      f.riskImpact = 'low';
    }
  }
}

function worstSeverity(findings: CheckFinding[]): RiskSeverity {
  const rank: Record<RiskSeverity, number> = {
    informational: 0,
    unknown: 1,
    low: 2,
    medium: 3,
    high: 4,
    critical: 5,
  };
  let max: RiskSeverity = 'informational';
  for (const f of findings) {
    if (rank[f.severity] > rank[max]) max = f.severity;
  }
  return max;
}

function sectionStatus(findings: CheckFinding[]): CheckStatus {
  if (findings.length === 0) return 'unknown';
  if (findings.some((f) => f.status === 'failed')) return 'failed';
  if (findings.some((f) => f.status === 'warning' && !POSTURE_ONLY_FINDING_IDS.has(f.id))) return 'warning';
  if (findings.every((f) => f.status === 'unknown')) return 'unknown';
  if (findings.some((f) => f.status === 'warning')) return 'warning';
  return 'pass';
}

function buildSeparatedAssessments(
  findings: CheckFinding[],
  providers: ThreatProviderResult[],
  context?: ScoringContext
): {
  domainAuthenticity: SeparatedPillarAssessment;
  threatIntelligence: SeparatedPillarAssessment;
  websiteSecurity: SeparatedPillarAssessment;
  sslTlsStatus: SeparatedPillarAssessment;
  redirectAnalysis: SeparatedPillarAssessment;
} {
  const byId = new Map(findings.map((f) => [f.id, f]));
  const auth = context?.domainAuthenticity;

  // 1. Domain Authenticity Pillar
  let domainAuthPillar: SeparatedPillarAssessment;
  if (auth) {
    const authStatus: CheckStatus =
      auth.conflictDetected
        ? 'failed'
        : auth.status === 'official_verified' || auth.status === 'official_subdomain'
          ? 'pass'
          : auth.status === 'brand_lookalike'
            ? 'warning'
            : auth.status === 'authorized_third_party' || auth.status === 'partner_or_provider'
              ? 'pass'
              : 'unknown';
    domainAuthPillar = {
      id: 'domain_authenticity',
      title: { en: 'Domain Authenticity', ar: 'أصالة النطاق وملكيته' },
      status: authStatus,
      verdict: auth.label,
      detail: {
        en: `${auth.registrableDomain} (PSL eTLD+1)${auth.parentCompany ? ` · Owner: ${auth.parentCompany}` : ''}${auth.corroborationSources.length ? ` · ${auth.corroborationSources.filter((s) => s.verified).length}/${auth.corroborationSources.length} corroborating signals` : ''}`,
        ar: `النطاق الأساسي ${auth.registrableDomain}${auth.parentCompany ? ` · الجهة المالكة: ${auth.parentCompany}` : ''}`,
      },
      caveat: auth.disclaimer,
    };
  } else {
    const dec = byId.get('deception-homograph-confusables');
    domainAuthPillar = {
      id: 'domain_authenticity',
      title: { en: 'Domain Authenticity', ar: 'أصالة النطاق وملكيته' },
      status: dec?.status || 'unknown',
      verdict: dec?.result || { en: 'Ownership unverified', ar: 'ملكية النطاق غير محققة' },
      detail: {
        en: 'Evaluated from domain structure and deception checks.',
        ar: 'تم التقييم بناءً على بنية النطاق وفحوصات التمويه.',
      },
    };
  }

  // 2. Threat Intelligence Pillar
  const activeProviders = providers.filter((p) => p.status === 'clean' || p.status === 'flagged' || p.status === 'suspicious');
  const flaggedProviders = providers.filter((p) => p.status === 'flagged');
  const suspiciousProviders = providers.filter((p) => p.status === 'suspicious');
  const tiStatus: CheckStatus =
    flaggedProviders.length > 0
      ? 'failed'
      : suspiciousProviders.length > 0
        ? 'warning'
        : activeProviders.length > 0
          ? 'pass'
          : 'unknown';

  const threatIntelligencePillar: SeparatedPillarAssessment = {
    id: 'threat_intelligence',
    title: { en: 'Threat Intelligence', ar: 'استخبارات التهديدات' },
    status: tiStatus,
    verdict:
      flaggedProviders.length > 0
        ? {
            en: `Flagged by ${flaggedProviders.map((p) => p.providerName).join(', ')}`,
            ar: `تم الإبلاغ عنه بواسطة ${flaggedProviders.map((p) => p.providerName).join('، ')}`,
          }
        : suspiciousProviders.length > 0
          ? {
              en: `Suspicious indicators in ${suspiciousProviders.map((p) => p.providerName).join(', ')}`,
              ar: `مؤشرات اشتباه لدى ${suspiciousProviders.map((p) => p.providerName).join('، ')}`,
            }
          : activeProviders.length > 0
            ? {
                en: `0 listings across ${activeProviders.length}/${providers.length} responding feed(s)`,
                ar: `0 بلاغ عبر ${activeProviders.length}/${providers.length} مزود استخبارات مستجيب`,
              }
            : {
                en: 'No external threat feeds responded',
                ar: 'لم تستجب أي مصادر استخبارات تهديدات خارجية',
              },
    detail: {
      en: `${providers.filter((p) => p.status === 'clean').length} clean, ${flaggedProviders.length} flagged, ${providers.filter((p) => p.status === 'auth_required').length} auth-gated, ${providers.filter((p) => p.status === 'unavailable' || p.status === 'error').length} unavailable.`,
      ar: `سليم: ${providers.filter((p) => p.status === 'clean').length}، بلاغات: ${flaggedProviders.length}، يتطلب مفتاحاً: ${providers.filter((p) => p.status === 'auth_required').length}، غير متاح: ${providers.filter((p) => p.status === 'unavailable' || p.status === 'error').length}.`,
    },
    caveat: {
      en: 'Zero listings in threat feeds shows no known prior report at scan time and never guarantees safety from newly launched or zero-day attacks.',
      ar: 'عدم وجود بلاغات في قواعد التهديدات يعني عدم إدراجه وقت الفحص فقط، ولا يضمن الأمان ضد التهديدات الجديدة أو المخترقة حديثاً.',
    },
  };

  // 3. Website Security Pillar (active content/script/phishing risk vs hardening headers posture)
  const webRiskIds = [
    'phishing-credential-harvesting',
    'phishing-social-engineering',
    'content-auto-download',
    'content-malicious-ads',
    'js-static-analysis',
    'source-base-tag-hijack',
  ];
  const webRiskFindings = webRiskIds.map((id) => byId.get(id)).filter((x): x is CheckFinding => Boolean(x));
  const cspMissing = byId.get('source-csp-missing')?.status === 'warning';
  const emailAuthMissing = byId.get('dns-email-security')?.status === 'warning';
  const contentUnreachable = byId.has('content-unavailable');

  const hasWebFailed = webRiskFindings.some((f) => f.status === 'failed');
  const hasWebWarn = webRiskFindings.some((f) => f.status === 'warning');
  const websiteSecurityPillar: SeparatedPillarAssessment = {
    id: 'website_security',
    title: { en: 'Website Security & Hardening', ar: 'أمان الموقع والحصانة البرمجية' },
    status: contentUnreachable ? 'unknown' : hasWebFailed ? 'failed' : hasWebWarn ? 'warning' : 'pass',
    verdict: contentUnreachable
      ? { en: 'HTML content unreachable', ar: 'تعذر جلب محتوى الصفحة للفحص' }
      : hasWebFailed
        ? { en: 'Active content or phishing threats detected', ar: 'رُصدت تهديدات نشطة أو تصيد في المحتوى' }
        : hasWebWarn
          ? { en: 'Minor script or form warnings observed', ar: 'لوحظت تنبيهات محتوى أو سكربت طفيفة' }
          : { en: 'No malicious content or credential traps observed', ar: 'لم يُرصد محتوى خبيث أو فخاخ تصيد في الصفحة' },
    detail: {
      en: `Posture notes (informational only, no risk penalty): CSP ${cspMissing ? 'missing' : 'present'}, SPF/DMARC ${emailAuthMissing ? 'incomplete' : 'present'}.`,
      ar: `ملاحظات التحصين (معلوماتية ولا ترفع الخطورة): سياسة CSP ${cspMissing ? 'غير مضمنة' : 'موجودة'}، سجلات البريد ${emailAuthMissing ? 'جزئية' : 'مكتملة'}.`,
    },
  };

  // 4. SSL/TLS Status Pillar
  const tlsAvail = byId.get('tls-availability');
  const tlsTrust = byId.get('tls-chain-trust');
  const tlsCipher = byId.get('tls-protocol-cipher');
  const tlsData = context?.tlsData;
  const tlsFailed = tlsAvail?.status === 'failed' || tlsTrust?.status === 'failed';
  const tlsWarn = tlsCipher?.status === 'warning';
  const tlsUnknown = !tlsAvail && !tlsTrust && !tlsData;

  const sslTlsPillar: SeparatedPillarAssessment = {
    id: 'ssl_tls_status',
    title: { en: 'SSL/TLS Status', ar: 'حالة تشفير SSL/TLS' },
    status: tlsUnknown ? 'unknown' : tlsFailed ? 'failed' : tlsWarn ? 'warning' : 'pass',
    verdict: tlsUnknown
      ? { en: 'TLS check not performed', ar: 'لم يُجرَ فحص شهادة TLS' }
      : tlsFailed
        ? { en: 'Missing, untrusted, expired, or mismatched TLS', ar: 'شهادة TLS مفقودة أو غير موثوقة أو منتهية' }
        : {
            en: `Valid encrypted TLS transport${tlsData?.protocol ? ` (${tlsData.protocol})` : ''}`,
            ar: `اتصال مشفر وصالح عبر TLS${tlsData?.protocol ? ` (${tlsData.protocol})` : ''}`,
          },
    detail: {
      en: tlsData?.issuer
        ? `Issuer: ${tlsData.issuer}${tlsData.daysRemaining !== undefined ? ` · ${tlsData.daysRemaining}d remaining` : ''}`
        : tlsTrust?.result.en || tlsAvail?.result.en || 'Transport encryption checked.',
      ar: tlsData?.issuer
        ? `الجهة المصدرة: ${tlsData.issuer}${tlsData.daysRemaining !== undefined ? ` · متبقي ${tlsData.daysRemaining} يوماً` : ''}`
        : tlsTrust?.result.ar || tlsAvail?.result.ar || 'تم فحص تشفير الاتصال.',
    },
    caveat: {
      en: 'HTTPS/TLS verifies transport encryption only; attackers routinely use valid certificates on phishing and deceptive domains.',
      ar: 'وجود شهادة HTTPS صالحة يثبت تشفير الاتصال فقط ولا يثبت أبداً موثوقية الموقع أو سلامته.',
    },
  };

  // 5. Redirect Analysis Pillar
  const redirFinding = byId.get('redirect-chain-analysis');
  const hops = context?.redirects;
  const unverifiedCrossHops = hops ? hops.filter((h) => h.crossDomain && !h.isSameOrganization).length : 0;
  const sameOrgHops = hops ? hops.filter((h) => h.isSameOrganization && h.step > 1).length : 0;
  const downgraded = hops ? hops.some((h) => h.downgradedToHttp) : false;

  const redirectPillar: SeparatedPillarAssessment = {
    id: 'redirect_analysis',
    title: { en: 'Redirect Analysis', ar: 'تحليل إعادة التوجيه' },
    status: redirFinding?.status || (downgraded ? 'failed' : unverifiedCrossHops > 0 ? 'warning' : hops ? 'pass' : 'unknown'),
    verdict: redirFinding?.result || (hops
      ? {
          en: `${Math.max(0, hops.length - 1)} hop(s) · ${unverifiedCrossHops} unverified cross-domain, ${sameOrgHops} same-company/official`,
          ar: `${Math.max(0, hops.length - 1)} تحويل(ات) · ${unverifiedCrossHops} خارجي غير مرتبط، ${sameOrgHops} ضمن نفس المؤسسة`,
        }
      : { en: 'No redirect telemetry', ar: 'لا توجد بيانات إعادة توجيه' }),
    detail: {
      en: downgraded
        ? 'Detected an insecure HTTPS-to-HTTP protocol downgrade in the redirect chain.'
        : sameOrgHops > 0 && unverifiedCrossHops === 0
          ? 'All redirects remain within the same organization or authorized official product domains.'
          : unverifiedCrossHops > 0
            ? 'Redirects traverse unrelated domains; inspect the final destination domain carefully.'
            : 'No deceptive or cross-organization redirect jumps observed.',
      ar: downgraded
        ? 'تم رصد تخفيض أمني من HTTPS إلى HTTP غير مشفر أثناء التوجيه.'
        : sameOrgHops > 0 && unverifiedCrossHops === 0
          ? 'جميع التحويلات تمت داخل نطاقات نفس الشركة أو خدماتها الرسمية المعتمدة.'
          : unverifiedCrossHops > 0
            ? 'تنتقل التحويلات عبر نطاقات غير مرتبطة؛ راجع النطاق النهائي بعناية.'
            : 'لم تُرصد قفزات توجيه مشبوهة خارج المؤسسة.',
    },
  };

  return {
    domainAuthenticity: domainAuthPillar,
    threatIntelligence: threatIntelligencePillar,
    websiteSecurity: websiteSecurityPillar,
    sslTlsStatus: sslTlsPillar,
    redirectAnalysis: redirectPillar,
  };
}

export function computeRiskAndSections(
  findings: CheckFinding[],
  providers: ThreatProviderResult[],
  context?: ScoringContext
): {
  riskScore: number;
  classification: RiskClassification;
  verdict: FinalVerdict;
  confidenceScore: number;
  confidenceLabel: 'High' | 'Medium' | 'Low';
  inspectionCoveragePercent: number;
  recommendation: BilingualText;
  topReasons: BilingualText[];
  correlationNotes: BilingualText[];
  conflictNotes: BilingualText[];
  scoreBreakdown: {
    id: string;
    label: BilingualText;
    category: string;
    delta: number;
  }[];
  evidenceBuckets: {
    confirmed: BilingualText[];
    suspicious: BilingualText[];
    inconclusive: BilingualText[];
    conflicting: BilingualText[];
  };
  domainAuthenticity?: ScanReportDomainAuthenticity;
  separatedAssessments: {
    domainAuthenticity: SeparatedPillarAssessment;
    threatIntelligence: SeparatedPillarAssessment;
    websiteSecurity: SeparatedPillarAssessment;
    sslTlsStatus: SeparatedPillarAssessment;
    redirectAnalysis: SeparatedPillarAssessment;
  };
  summaryStats: {
    totalChecks: number;
    passedChecks: number;
    warningChecks: number;
    failedChecks: number;
    criticalFindings: number;
    incompleteChecks: number;
    availableProviders: number;
    totalProviders: number;
  };
  sections: TechnicalSectionSummary[];
} {
  let strongRiskScore = 0;
  let weakSignalScore = 0;
  let passedChecks = 0;
  let warningChecks = 0;
  let substantiveWarningChecks = 0;
  let failedChecks = 0;
  let criticalFindings = 0;
  let incompleteChecks = 0;
  let confidenceSum = 0;

  const scoreBreakdown: { id: string; label: BilingualText; category: string; delta: number }[] = [];

  for (const f of findings) {
    enrichFindingMetadata(f);
    const reliabilityFactor = f.confidence >= 80 ? 1.0 : f.confidence >= 55 ? 0.85 : 0.7;
    const weighted = Math.max(0, f.weight) * reliabilityFactor;
    confidenceSum += f.confidence;

    if (f.status === 'pass') {
      passedChecks++;
    } else if (f.status === 'warning') {
      warningChecks++;
      if (!POSTURE_ONLY_FINDING_IDS.has(f.id) && f.weight > 0) {
        substantiveWarningChecks++;
      }
      if (f.severity === 'medium' || f.severity === 'high' || f.severity === 'critical' || f.weight >= 10) {
        strongRiskScore += weighted;
        if (Math.round(weighted) > 0) {
          scoreBreakdown.push({
            id: f.id,
            label: f.test,
            category: f.section,
            delta: Math.round(weighted),
          });
        }
      } else {
        weakSignalScore += weighted;
        if (Math.round(weighted) > 0) {
          scoreBreakdown.push({
            id: f.id,
            label: f.test,
            category: 'weak_signal',
            delta: Math.round(weighted),
          });
        }
      }
    } else if (f.status === 'failed') {
      failedChecks++;
      strongRiskScore += weighted;
      if (Math.round(weighted) > 0) {
        scoreBreakdown.push({
          id: f.id,
          label: f.test,
          category: f.section,
          delta: Math.round(weighted),
        });
      }
    } else {
      incompleteChecks++;
    }

    if (f.severity === 'critical' || (f.status === 'failed' && f.severity === 'high')) {
      criticalFindings++;
    }
  }

  // Rule 8 Enforcement: weak/low signals can NEVER stack arbitrarily to trigger Medium/High/Critical
  const weakSignalContribution = Math.min(15, weakSignalScore);
  if (weakSignalScore > 15) {
    scoreBreakdown.push({
      id: 'weak-signal-cap',
      label: { en: 'Weak Signal Stacking Cap', ar: 'سقف منع تراكم الإشارات الضعيفة' },
      category: 'calibration',
      delta: -Math.round(weakSignalScore - weakSignalContribution),
    });
  }
  let rawScore = strongRiskScore + weakSignalContribution;

  // =========================================================================
  // DEDUPLICATION AGAINST DOUBLE COUNTING ACROSS OVERLAPPING MODULES
  // =========================================================================
  const byId = new Map(findings.map((f) => [f.id, f]));
  const homographFinding = byId.get('deception-homograph-confusables');
  const subdomainDeceptionFinding = byId.get('deception-subdomain-identity-mismatch');
  const openRedirectFinding = byId.get('deception-open-redirect-relays');
  const brandFinding = byId.get('brand-impersonation');

  const hasDomainDeceptionFailed =
    homographFinding?.status === 'failed' ||
    subdomainDeceptionFinding?.status === 'failed' ||
    openRedirectFinding?.status === 'failed';
  const hasBrandImpersonation = brandFinding?.status === 'failed';
  const hasBrandSimilarityOnly =
    Boolean(homographFinding?.evidence?.includes('SimilarityOnly: true')) ||
    Boolean(brandFinding?.evidence?.includes('SimilarityOnly: true'));

  if (
    hasBrandImpersonation &&
    (homographFinding?.status === 'failed' || subdomainDeceptionFinding?.status === 'failed')
  ) {
    const deceptionDomainWeight = Math.max(
      homographFinding?.status === 'failed' ? homographFinding.weight : 0,
      subdomainDeceptionFinding?.status === 'failed' ? subdomainDeceptionFinding.weight : 0
    );
    const overlapDeduction = Math.round(Math.min(brandFinding?.weight || 0, deceptionDomainWeight) * 0.6);
    rawScore = Math.max(0, rawScore - overlapDeduction);
    if (overlapDeduction > 0) {
      scoreBreakdown.push({
        id: 'dedup-brand-deception',
        label: { en: 'Overlap Deduplication (Brand & Domain Deception)', ar: 'إزالة التكرار بين خداع النطاق وانتحال العلامة' },
        category: 'calibration',
        delta: -overlapDeduction,
      });
    }
  } else if (hasBrandSimilarityOnly && homographFinding?.status === 'warning' && brandFinding?.status === 'warning') {
    // Similarity-only detection must stay proportionally measured (Low Risk) without double-counting
    const overlapDeduction = Math.round(Math.min(brandFinding.weight || 0, homographFinding.weight || 0) * 0.75);
    rawScore = Math.max(0, rawScore - overlapDeduction);
    if (overlapDeduction > 0) {
      scoreBreakdown.push({
        id: 'dedup-similarity-only',
        label: { en: 'Overlap Deduplication (Similarity Only)', ar: 'إزالة التكرار لمؤشر التشابه غير المؤكد' },
        category: 'calibration',
        delta: -overlapDeduction,
      });
    }
  }

  // Deduplicate overlapping Content & Source Intelligence indicators so the same underlying signal
  // (e.g., JS obfuscation, title brand contradiction, or cross-origin form overrides) is never counted twice
  const jsStaticFinding = byId.get('js-static-analysis');
  const sourceJsFinding = byId.get('source-js-behavior');
  const sourceHtmlFinding = byId.get('source-html-structure');
  const credHarvFinding = byId.get('phishing-credential-harvesting');

  if (jsStaticFinding?.status === 'failed' && sourceJsFinding?.status === 'failed') {
    const overlapJs = Math.round(Math.min(jsStaticFinding.weight || 0, sourceJsFinding.weight || 0) * 0.85);
    if (overlapJs > 0) {
      rawScore = Math.max(0, rawScore - overlapJs);
      scoreBreakdown.push({
        id: 'dedup-js-overlap',
        label: { en: 'Overlap Deduplication (Static JS & Source Forensics)', ar: 'منع التكرار بين فحص JS الساكن وتحليل السورس' },
        category: 'calibration',
        delta: -overlapJs,
      });
    }
  }

  if (
    brandFinding?.status === 'failed' &&
    sourceHtmlFinding?.status === 'failed' &&
    (sourceHtmlFinding.evidence || '').includes('TitleMismatch: true')
  ) {
    const overlapBrand = Math.round(Math.min(brandFinding.weight || 0, sourceHtmlFinding.weight || 0) * 0.75);
    if (overlapBrand > 0) {
      rawScore = Math.max(0, rawScore - overlapBrand);
      scoreBreakdown.push({
        id: 'dedup-title-brand-overlap',
        label: { en: 'Overlap Deduplication (Title & Brand Mismatch)', ar: 'منع التكرار بين انتحال العلامة وتناقض العنوان' },
        category: 'calibration',
        delta: -overlapBrand,
      });
    }
  }

  if (
    credHarvFinding?.status === 'failed' &&
    sourceHtmlFinding?.status === 'failed' &&
    (sourceHtmlFinding.evidence || '').includes('CrossOriginFormaction: true')
  ) {
    const overlapForm = Math.round(Math.min(credHarvFinding.weight || 0, sourceHtmlFinding.weight || 0) * 0.65);
    if (overlapForm > 0) {
      rawScore = Math.max(0, rawScore - overlapForm);
      scoreBreakdown.push({
        id: 'dedup-form-overlap',
        label: { en: 'Overlap Deduplication (External Form Exfiltration)', ar: 'منع التكرار لمؤشر إرسال النموذج لنطاق خارجي' },
        category: 'calibration',
        delta: -overlapForm,
      });
    }
  }

  // =========================================================================
  // DETERMINISTIC MULTI-SIGNAL CORRELATION RULES
  // =========================================================================
  const correlationNotes: BilingualText[] = [];
  let minScoreFloor = 0;

  const hasExternalFlag = findings.some(
    (f) => f.section === 'external_threat_intel' && f.status === 'failed'
  );
  const hasExternalSuspicious = findings.some(
    (f) => f.section === 'external_threat_intel' && f.status === 'warning'
  );
  const credFinding = byId.get('phishing-credential-harvesting');
  const socialFinding = byId.get('phishing-social-engineering');
  const structFinding = byId.get('content-structure');
  const paasFinding = byId.get('url-subdomain-paas');
  const lexicalFinding = byId.get('url-lexical-extensions');
  const redirectFinding = byId.get('redirect-chain-analysis');
  const fileDirectFinding = byId.get('file-direct-download');
  const fileLinkedFinding = byId.get('file-linked-downloads');
  const tlsStrengthFinding = byId.get('tls-cipher-strength') || byId.get('tls-protocol-cipher');

  const isOfficialEntityVerified = Boolean(
    context?.domainAuthenticity &&
      (context.domainAuthenticity.status === 'official_verified' ||
        context.domainAuthenticity.status === 'official_subdomain') &&
      context.domainAuthenticity.corroborated &&
      !context.domainAuthenticity.conflictDetected
  );

  const hasCredentialRisk = credFinding?.status === 'failed';
  const hasUnwrappedPassword =
    Boolean(credFinding?.evidence.includes('unwrapped in <div>:')) &&
    !/unwrapped in <div>:\s*0\b/.test(credFinding?.evidence || '');
  const hasAnyPasswordInput =
    hasUnwrappedPassword ||
    (Boolean(credFinding?.evidence) && !/Password fields:\s*0\b/.test(credFinding?.evidence || ''));
  const hasCrossOriginForm =
    Boolean(credFinding?.evidence) && !/Cross-origin actions:\s*\[none\]/.test(credFinding?.evidence || '');
  const hasFakeUpdateAlert =
    /Fake software update|system security warning/i.test(socialFinding?.evidence || '');
  const hasExplicitPhishingLure = socialFinding?.status === 'failed';
  const hasPhishingPageArtifact =
    /Explicit social-engineering \/ phishing page markers/i.test(socialFinding?.evidence || '');
  const hasMissingTitleCreds =
    structFinding?.status === 'warning' && (structFinding?.evidence || '').includes('Title: NONE');
  const hasPhishingLexical =
    lexicalFinding?.status === 'warning' || lexicalFinding?.status === 'failed';
  const isPaasHosted =
    Boolean(paasFinding?.evidence) && !/Shared PaaS:\s*No/i.test(paasFinding?.evidence || '');
  const isYoungDomain = byId.get('domain-age')?.status === 'failed';
  const hasHttpsDowngrade = (redirectFinding?.evidence || '').includes('HTTPS->HTTP');
  const hasTlsInvalid =
    byId.get('tls-chain-trust')?.status === 'failed' ||
    byId.get('tls-availability')?.status === 'failed' ||
    tlsStrengthFinding?.status === 'failed';
  const hasDangerousFile =
    fileDirectFinding?.status === 'failed' || fileLinkedFinding?.status === 'failed';
  const hasContentUnreachable = byId.has('content-unavailable');

  // Rule 1: Confirmed external threat-intelligence hit
  if (hasExternalFlag) {
    rawScore += 25;
    minScoreFloor = Math.max(minScoreFloor, 84);
    correlationNotes.push({
      en: 'External Threat Feed Hit: One or more active threat-intelligence providers flagged this exact URL or unverified infrastructure, elevating risk to Critical.',
      ar: 'بلاغ استخبارات تهديدات: أبلغ مزود أو أكثر عن خطورة هذا الرابط أو النطاق أو عنوان IP، مما يرفع التصنيف إلى حرج.',
    });
  } else if (hasExternalSuspicious) {
    // Borderline threat feed mentions stay contextual without jumping into Medium risk unless corroborated
    rawScore += 6;
  }

  // Rule 1b: Standalone subdomain spoofing / authority @ masking structural deception
  if (
    subdomainDeceptionFinding?.status === 'failed' &&
    /SubdomainSpoofing:\s*true|Authority@:\s*true/.test(subdomainDeceptionFinding.evidence || '') &&
    context?.domainAuthenticity?.status !== 'official_verified'
  ) {
    minScoreFloor = Math.max(minScoreFloor, 54);
  }

  // Rule 2: Domain deception / homograph / confirmed open redirect + credential or social-engineering signals
  if (
    hasDomainDeceptionFailed &&
    (hasCredentialRisk ||
      hasExplicitPhishingLure ||
      hasBrandImpersonation ||
      isYoungDomain ||
      isPaasHosted ||
      (hasAnyPasswordInput && !isOfficialEntityVerified))
  ) {
    rawScore += 20;
    minScoreFloor = Math.max(minScoreFloor, hasCredentialRisk || hasBrandImpersonation ? 82 : 70);
    correlationNotes.push({
      en: 'Deceptive Domain Identity + Exploitation Signal: Visual spoofing, homoglyphs, subdomain masking, or open redirect co-occurs with credential or phishing lures.',
      ar: 'تطابق تمويه الهوية مع مؤشرات الاستغلال: تمويه النطاق أو الأحرف المتشابهة أو التوجيه المفتوح يترافق مع استدراج بيانات أو علامات تصيد.',
    });
  }

  // Rule 3: Unwrapped password input (outside <form>) ONLY when paired with genuine phishing lures/missing-title/PaaS (NEVER penalize clean SPAs alone!)
  if (
    hasUnwrappedPassword &&
    credFinding?.status === 'failed' &&
    (hasFakeUpdateAlert || hasExplicitPhishingLure || hasMissingTitleCreds || hasPhishingLexical || isPaasHosted)
  ) {
    rawScore += 24;
    minScoreFloor = Math.max(minScoreFloor, 74);
    correlationNotes.push({
      en: 'Correlated Phishing Pattern: Password input outside a standard <form> co-occurs with deceptive lures, missing <title>, or shared PaaS hosting.',
      ar: 'ترابط مؤشرات التصيد: وجود حقل كلمة مرور خارج نموذج <form> قياسي بالتزامن مع مؤشرات خداع أو غياب <title> أو استضافة تشاركية.',
    });
  }

  // Rule 4: Password or sensitive credential collection + fake alert / social engineering / cross-origin submission
  if (
    (hasCredentialRisk || hasCrossOriginForm) &&
    (hasFakeUpdateAlert || hasExplicitPhishingLure || hasCrossOriginForm || hasBrandImpersonation)
  ) {
    const comboCount = [
      hasFakeUpdateAlert,
      hasExplicitPhishingLure,
      hasCrossOriginForm,
      hasBrandImpersonation,
      hasMissingTitleCreds,
    ].filter(Boolean).length;

    rawScore += 18 + comboCount * 5;
    minScoreFloor = Math.max(minScoreFloor, comboCount >= 2 ? 82 : 68);
    correlationNotes.push({
      en: 'Credential Harvesting Correlation: Login or sensitive inputs appear alongside deceptive lures, fake alerts, impersonation, or unverified third-party endpoints.',
      ar: 'ارتباط حصد بيانات الاعتماد: حقول كلمات المرور مقترنة بعبارات تضليل أو تحذيرات مزيفة أو انتحال أو إرسال لطرف ثالث غير موثق.',
    });
  }

  // Rule 5: Explicit phishing artifact / lure on PaaS or phishing-lexical URL
  if (hasPhishingPageArtifact || (socialFinding?.status === 'failed' && (isPaasHosted || hasPhishingLexical))) {
    rawScore += 26;
    minScoreFloor = Math.max(minScoreFloor, 76);
    correlationNotes.push({
      en: 'Phishing Lure & Infrastructure Correlation: Explicit social-engineering content detected alongside shared PaaS hosting or phishing path indicators.',
      ar: 'ارتباط محتوى التصيد بالبنية المستضيفة: تم رصد نصوص خداع وتصيد صريحة على استضافة تشاركية أو مسار رابط مشبوه.',
    });
  }

  // Rule 6: Confirmed brand impersonation + newly registered domain or PaaS hosting
  if (hasBrandImpersonation && (isYoungDomain || isPaasHosted || hasPhishingLexical)) {
    rawScore += 16;
    minScoreFloor = Math.max(minScoreFloor, 74);
    correlationNotes.push({
      en: 'Impersonation Infrastructure Correlation: Brand impersonation detected on an unverified young domain or shared multi-tenant PaaS subdomain.',
      ar: 'انتحال هوية مع بنية استضافة غير موثقة: انتحال علامة تجارية معروفة على نطاق حديث أو استضافة تشاركية.',
    });
  }

  // Rule 7: Credential form over downgraded HTTP or invalid TLS
  if ((hasAnyPasswordInput || hasCredentialRisk) && (hasHttpsDowngrade || hasTlsInvalid)) {
    rawScore += 14;
    minScoreFloor = Math.max(minScoreFloor, 64);
    correlationNotes.push({
      en: 'Insecure Credential Transport: Login fields detected where HTTPS was downgraded or TLS validation failed.',
      ar: 'نقل غير آمن لبيانات الدخول: حقول تسجيل دخول على اتصال تم تخفيضه أو بشهادة غير صالحة.',
    });
  }

  // Rule 8: Smart File Download & Drive-By Risk Correlation
  const hasMimeMasqueradeOrDeceptiveFile = Boolean(
    fileDirectFinding?.evidence?.includes('MIME/Extension mismatch') ||
    fileDirectFinding?.evidence?.includes('double extension') ||
    fileLinkedFinding?.evidence?.includes('double extension')
  );

  const isCleanOrOfficialSite =
    isOfficialEntityVerified ||
    (!hasExplicitPhishingLure &&
      !hasFakeUpdateAlert &&
      !hasCredentialRisk &&
      !hasDomainDeceptionFailed &&
      !hasExternalFlag);

  if (hasMimeMasqueradeOrDeceptiveFile) {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 68);
    correlationNotes.push({
      en: 'Deceptive / Masqueraded File Download: Mismatched signature or dangerous double extension detected.',
      ar: 'تنزيل ملف مموه أو مضلل: تم رصد تلاعب بامتداد الملف أو تضارب في توقيع البايتات السحرية الثنائية.',
    });
  } else if (hasDangerousFile && !isCleanOrOfficialSite) {
    rawScore += 12;
    minScoreFloor = Math.max(minScoreFloor, 56);
    correlationNotes.push({
      en: 'High-Risk File Download in Suspicious Context: Executable or archive download detected alongside suspicious content or lures.',
      ar: 'تنزيل ملفات في سياق مشبوه: رصد تنزيل ملفات بالتزامن مع مؤشرات خطورة أو استدراج في محتوى الموقع.',
    });
  } else if ((fileDirectFinding || fileLinkedFinding) && isCleanOrOfficialSite) {
    // Legitimate software or document downloads on clean / official platforms (e.g. app installer, PDF)
    // NEVER elevate to Medium when user-initiated and content is clean!
    correlationNotes.push({
      en: 'User-Initiated Software / Document Download: Download links detected on clean/official domain via user action without automatic triggers or deception.',
      ar: 'تنزيل برمجيات أو وثائق عبر روابط اختيارية: رُصدت روابط تنزيل ضمن محتوى نظيف أو نطاق موثق دون تنزيل تلقائي قسري أو تضليل.',
    });
  }

  // Rule 9: Multi-tenant PaaS + password field notice (only escalate when combined with real phishing/suspicion signals)
  if (
    isPaasHosted &&
    hasAnyPasswordInput &&
    (hasCredentialRisk || hasUnwrappedPassword || hasFakeUpdateAlert || hasExplicitPhishingLure || hasBrandImpersonation || hasPhishingLexical)
  ) {
    minScoreFloor = Math.max(minScoreFloor, 60);
    correlationNotes.push({
      en: 'Shared Multi-Tenant PaaS Warning: Underlying platform domain age and wildcard TLS belong to the hosting provider, not this risky credential page.',
      ar: 'تنبيه استضافة تشاركية: عمر النطاق الأساسي وشهادة TLS التلقائية تعود لمزود الاستضافة وليس لموثوقية صفحة تسجيل الدخول المشبوهة.',
    });
  } else if (isPaasHosted && hasAnyPasswordInput) {
    correlationNotes.push({
      en: 'Contextual Note (Multi-Tenant PaaS Form): This page is hosted on shared PaaS infrastructure and includes a standard login form without phishing lures or domain deception.',
      ar: 'ملاحظة سياقية (استضافة تشاركية): هذه الصفحة مستضافة على منصة تشاركية وتحتوي على نموذج دخول قياسي دون علامات تصيد أو خداع.',
    });
  }

  // Rule 10: Drive-by auto-download or confirmed malvertising
  const autoDownloadFinding = byId.get('content-auto-download');
  const malAdsFinding = byId.get('content-malicious-ads');
  const permFinding = byId.get('content-permissions-audit');
  if (autoDownloadFinding?.status === 'failed') {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 72);
    scoreBreakdown.push({
      id: 'corr-autodownload',
      label: { en: 'Correlation: Drive-By Download', ar: 'ارتباط: تنزيل تلقائي أو تهريب ملفات' },
      category: 'correlation',
      delta: 18,
    });
    correlationNotes.push({
      en: 'Drive-By Download / HTML Smuggling Signal: Page triggers automatic file downloads or assembles payloads client-side without explicit user consent.',
      ar: 'محفز تنزيل تلقائي أو تهريب ملفات: تحتوي الصفحة على آلية لبدء تنزيل ملف تلقائياً أو بناء حمولات عبر المتصفح.',
    });
  }
  if (malAdsFinding?.status === 'failed' || (malAdsFinding?.status === 'warning' && permFinding?.status === 'failed')) {
    rawScore += 12;
    minScoreFloor = Math.max(minScoreFloor, 56);
    scoreBreakdown.push({
      id: 'corr-malads',
      label: { en: 'Correlation: Malvertising & Permissions', ar: 'ارتباط: إعلانات خبيثة وأذونات' },
      category: 'correlation',
      delta: 12,
    });
    correlationNotes.push({
      en: 'Malvertising / Intrusive Permission Correlation: Deceptive ad/popunder triggers co-occur with aggressive browser permission requests.',
      ar: 'ارتباط الإعلانات الخبيثة والأذونات: تزامن مؤشرات الإعلانات المنبثقة/خطف النقرات مع طلب أذونات متصفح حساسة.',
    });
  }

  // Rule 11: Deep Source / HTML / JavaScript Behavioral Exploitation Correlation
  const jsBehaviorFinding = byId.get('source-js-behavior');
  const htmlStructFinding = byId.get('source-html-structure');
  if (
    jsBehaviorFinding?.status === 'failed' &&
    (hasAnyPasswordInput || htmlStructFinding?.status === 'failed' || hasBrandImpersonation || hasCredentialRisk)
  ) {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 68);
    scoreBreakdown.push({
      id: 'corr-js-source-exploit',
      label: { en: 'Correlation: Active JS & HTML Exploitation', ar: 'ارتباط: استغلال نشط في كود JavaScript و HTML' },
      category: 'correlation',
      delta: 18,
    });
    correlationNotes.push({
      en: 'Source & JavaScript Threat Correlation: Malicious JS behavior (form rewriting, encoded unpacking, or exfiltration hooks) co-occurs with credential inputs or deceptive HTML structure.',
      ar: 'ارتباط سورس الموقع و JavaScript: تزامن سلوك خطير في أكواد JavaScript مع حقول إدخال أو تلاعب في بنية HTML.',
    });
  }

  // Weak-signal escalation firewall: if NO correlation rule fired, NO failed checks exist, NO external hits exist,
  // and NO medium/high/critical warning exists, cap score at 15 so weak signals never elevate to Medium/High/Critical.
  const hasRealDangerBasis =
    failedChecks > 0 ||
    strongRiskScore > 0 ||
    hasExternalFlag ||
    hasExternalSuspicious ||
    minScoreFloor > 0;
  const preFloorScore = Math.min(100, Math.round(rawScore));
  const computedScore = Math.min(100, Math.max(minScoreFloor, preFloorScore));
  if (computedScore > preFloorScore && hasRealDangerBasis) {
    scoreBreakdown.push({
      id: 'corr-floor',
      label: { en: 'Multi-Signal Correlation Floor Adjustment', ar: 'تعديل الحد الأدنى لترابط الأدلة المتعددة' },
      category: 'correlation',
      delta: computedScore - preFloorScore,
    });
  }
  const riskScore = hasRealDangerBasis ? computedScore : Math.min(15, computedScore);

  const totalChecks = findings.length;
  const authoritativeRatio = totalChecks > 0 ? (totalChecks - incompleteChecks) / totalChecks : 0;
  const avgConfidence = totalChecks > 0 ? confidenceSum / totalChecks : 0;
  const confidenceScore = Math.round(avgConfidence * (0.45 + 0.55 * authoritativeRatio));
  const confidenceLabel: 'High' | 'Medium' | 'Low' =
    confidenceScore >= 75 ? 'High' : confidenceScore >= 50 ? 'Medium' : 'Low';

  const availableProviders = providers.filter(
    (p) => p.status === 'clean' || p.status === 'flagged' || p.status === 'suspicious'
  ).length;
  const totalProviders = providers.length;
  const providerCoverageRatio = totalProviders > 0 ? availableProviders / totalProviders : 0;
  const inspectionCoveragePercent = Math.max(
    0,
    Math.min(100, Math.round((authoritativeRatio * 0.68 + providerCoverageRatio * 0.32) * 100))
  );

  // =========================================================================
  // 7-CATEGORY DETERMINISTIC RISK CLASSIFICATION (Strict MEDIUM > 50 rule)
  // =========================================================================
  let classification: RiskClassification;
  if (
    hasExternalFlag ||
    riskScore >= 82 ||
    (hasBrandImpersonation && hasCredentialRisk && hasFakeUpdateAlert)
  ) {
    classification = 'CRITICAL';
  } else if (
    riskScore >= 68 ||
    (hasCredentialRisk && (hasFakeUpdateAlert || hasExplicitPhishingLure || hasCrossOriginForm || hasBrandImpersonation))
  ) {
    classification = 'HIGH';
  } else if (riskScore > 50) {
    classification = 'MEDIUM';
  } else if (hasContentUnreachable || authoritativeRatio < 0.48) {
    classification = 'UNKNOWN';
  } else if (riskScore >= 12 || substantiveWarningChecks > 0 || failedChecks > 0) {
    classification = 'LOW';
  } else if (isOfficialEntityVerified) {
    classification = 'OFFICIAL_DOMAIN_VERIFIED';
  } else if (availableProviders === 0) {
    classification = 'UNKNOWN';
  } else {
    classification = 'NO_KNOWN_THREATS';
  }

  let verdict: FinalVerdict;
  if (classification === 'CRITICAL') {
    verdict = 'Critical Risk';
  } else if (classification === 'HIGH') {
    verdict = 'High Risk';
  } else if (classification === 'MEDIUM') {
    verdict = 'Medium Risk';
  } else if (classification === 'LOW') {
    verdict = 'Low Risk';
  } else if (classification === 'UNKNOWN') {
    verdict = 'Insufficient Evidence';
  } else if (classification === 'OFFICIAL_DOMAIN_VERIFIED') {
    verdict = 'Official Domain Verified';
  } else {
    verdict = 'No Known Threats';
  }

  // =========================================================================
  // CONFLICTING EVIDENCE DISCLOSURE (Rule 10)
  // =========================================================================
  const conflictNotes: BilingualText[] = [];
  const flaggedProvs = providers.filter((p) => p.status === 'flagged');
  const cleanProvs = providers.filter((p) => p.status === 'clean');

  if (
    context?.domainAuthenticity &&
    (context.domainAuthenticity.status === 'official_verified' ||
      context.domainAuthenticity.status === 'official_subdomain') &&
    (context.domainAuthenticity.conflictDetected || hasExternalFlag || hasExternalSuspicious || failedChecks > 0 || riskScore >= 12)
  ) {
    conflictNotes.push({
      en: `Ownership vs. Runtime Conflict: Domain "${context.domainAuthenticity.registrableDomain}" belongs to "${context.domainAuthenticity.parentCompany || 'an official entity'}", yet active inspection or threat telemetry flagged anomalies or potentially compromised content on this URL.`,
      ar: `تعارض بين ملكية النطاق وحالة الصفحة: يطابق النطاق "${context.domainAuthenticity.registrableDomain}" سجلات الجهة الرسمية، لكن الفحص الفعلي أو استخبارات التهديدات رصدت مؤشرات خطورة أو احتمال وجود صفحة مخترقة أو رابط ضار داخله.`,
    });
  }

  if (flaggedProvs.length > 0 && cleanProvs.length > 0) {
    conflictNotes.push({
      en: `Provider Disagreement: ${flaggedProvs.map((p) => p.providerName).join(', ')} flagged this target while ${cleanProvs.map((p) => p.providerName).join(', ')} returned clean. Conflicting external feeds are disclosed transparently and elevated conservatively.`,
      ar: `تضارب مصادر التهديدات: أبلغ ${flaggedProvs.map((p) => p.providerName).join('، ')} عن وجود خطر بينما أعاد ${cleanProvs.map((p) => p.providerName).join('، ')} نتيجة سليمة؛ يتم الإفصاح عن تعارض المصادر بوضوح دون إخفائه.`,
    });
  }

  const tlsValid = Boolean(context?.tlsData?.httpsAvailable && context.tlsData.authorized && !context.tlsData.expired && context.tlsData.domainMatches !== false);
  if (
    tlsValid &&
    (classification === 'CRITICAL' || classification === 'HIGH' || classification === 'MEDIUM' || hasDomainDeceptionFailed || hasCredentialRisk || hasExternalFlag)
  ) {
    conflictNotes.push({
      en: 'HTTPS Certificate vs. Threat Risk Conflict: A valid CA-signed TLS certificate is active, yet risk indicators were detected. Valid HTTPS encrypts transport only and never proves a website is safe.',
      ar: 'تعارض شهادة HTTPS مع مؤشرات الخطر: توجد شهادة تشفير صالحة لكن الفحص رصد مؤشرات خطورة؛ شهادة HTTPS تثبت التشفير فقط ولا تثبت سلامة الموقع.',
    });
  }

  if (
    context?.dnsData?.domainAgeDays !== undefined &&
    context.dnsData.domainAgeDays >= 365 &&
    !context.dnsData.isMultiTenantPaas &&
    (classification === 'HIGH' || classification === 'CRITICAL')
  ) {
    conflictNotes.push({
      en: `Domain Age Conflict: Domain is ${context.dnsData.domainAgeYears ?? Math.floor(context.dnsData.domainAgeDays / 365)}y old, yet active threats were detected—older domains can be compromised or abused.`,
      ar: `تعارض عمر النطاق مع الخطر: النطاق مسجل منذ فترة طويلة لكن تم رصد تهديدات نشطة، إذ قد تتعرض النطاقات القديمة للاختراق أو إساءة الاستخدام.`,
    });
  }

  const recommendation: BilingualText =
    classification === 'CRITICAL'
      ? {
          en: 'Do not visit, sign in, grant permissions, or download files. Critical malicious, credential-harvesting, or confirmed threat indicators were detected.',
          ar: 'لا تفتح الرابط ولا تُدخل أي بيانات أو توافق على أي أذونات أو تنزيلات. تم رصد مؤشرات تهديد حرجة أو تصيد مؤكد.',
        }
      : classification === 'HIGH'
        ? {
            en: 'Avoid submitting credentials or interacting with prompts on this page. High-risk phishing, deceptive identity, or fake update lures were detected.',
            ar: 'تجنب إدخال أي بيانات أو التفاعل مع النوافذ في هذه الصفحة. توجد مؤشرات خطورة عالية لاحتمال التصيد أو الخداع.',
          }
        : classification === 'MEDIUM'
          ? {
              en: 'Proceed only after independent domain verification. Suspicious infrastructure, form behavior, or deceptive patterns were identified.',
              ar: 'توخَّ الحذر وتحقق من الموقع عبر مصدر رسمي مستقل. تم رصد مؤشرات بنية أو نماذج مشبوهة.',
            }
          : classification === 'UNKNOWN'
            ? {
                en: 'Insufficient Evidence: Inspection could not retrieve full content or sufficient external threat-feed verification. Unverified links must never be assumed safe.',
                ar: 'الأدلة غير كافية (Insufficient Evidence): تعذر جلب كامل بيانات المحتوى أو استخبارات التهديدات. عدم اكتمال الفحص لا يعني الأمان أبداً.',
              }
            : classification === 'LOW'
              ? {
                  en: hasBrandSimilarityOnly
                    ? 'Domain name similarity to a known brand was detected without confirmed impersonation proof. Verify the official domain directly before signing in.'
                    : 'Low-severity observations or domain similarity notes were detected without confirmed malicious threats. Verify the exact registrable domain before submitting sensitive data.',
                  ar: hasBrandSimilarityOnly
                    ? 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال. تحقق من الموقع الرسمي مباشرة قبل إدخال أي بيانات.'
                    : 'تم رصد ملاحظات فنية منخفضة الخطورة دون دليل على تهديد مؤكد. تحقق من النطاق الفعلي قبل إدخال بيانات حساسة.',
                }
              : classification === 'OFFICIAL_DOMAIN_VERIFIED'
                ? {
                    en: `Official domain ownership verified (${context?.domainAuthenticity?.parentCompany || context?.domainAuthenticity?.officialProduct || 'verified registry'}) via PSL, registry, DNS, and TLS corroboration with 0 threat flags. Note: Official domain ownership does NOT guarantee absence of vulnerabilities, compromised subpages, or unsafe user-submitted links.`,
                    ar: `تم التحقق من أن هذا النطاق رسمي وموثوق عبر التطابق الحقيقي للنطاق الأساسي وبيانات التسجيل وDNS وTLS دون أي مؤشرات تهديد. تنبيه إلزامي: التحقق من ملكية النطاق الرسمي لا يضمن خلوه من الثغرات الأمنية أو الاختراق أو الروابط الضارة داخله.`,
                  }
                : {
                    en: 'No known threats were identified across active deterministic checks and responding threat feeds at scan time. Note: Zero listings never guarantee 100% safety against unknown or zero-day threats.',
                    ar: 'لم يتم رصد تهديدات معروفة عبر الفحوصات المكتملة ومزودي الاستخبارات المستجيبين وقت الفحص. تنبيه: غياب البلاغات لا يضمن الأمان المطلق ضد التهديدات غير المعروفة.',
                  };

  // Build concise, evidence-backed Top Reasons driving the final score & verdict
  const sevRank: Record<RiskSeverity, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    unknown: 1,
    informational: 0,
  };
  const prioritized = [...findings]
    .filter((f) => f.status === 'failed' || f.status === 'warning' || f.status === 'unknown')
    .sort((a, b) => {
      if (b.weight !== a.weight) return b.weight - a.weight;
      return sevRank[b.severity] - sevRank[a.severity];
    });

  const topReasons: BilingualText[] = [];
  for (const cn of correlationNotes.slice(0, 2)) {
    topReasons.push(cn);
  }
  for (const f of prioritized) {
    if (topReasons.length >= 5) break;
    if (f.status === 'unknown' && f.weight === 0 && classification !== 'UNKNOWN') continue;
    if (POSTURE_ONLY_FINDING_IDS.has(f.id) && (classification === 'OFFICIAL_DOMAIN_VERIFIED' || classification === 'NO_KNOWN_THREATS')) continue;
    topReasons.push({
      en: `${f.test.en}: ${f.result.en}`,
      ar: `${f.test.ar}: ${f.result.ar}`,
    });
  }
  if (topReasons.length === 0) {
    if (classification === 'OFFICIAL_DOMAIN_VERIFIED' && context?.domainAuthenticity) {
      topReasons.push({
        en: `${context.domainAuthenticity.label.en} · ${passedChecks} completed checks passed cleanly.`,
        ar: `${context.domainAuthenticity.label.ar} · اجتازت ${passedChecks} فحصاً مكتملاً دون مؤشرات تهديد.`,
      });
    } else {
      topReasons.push({
        en: `All ${passedChecks} completed deterministic checks passed with ${availableProviders}/${totalProviders} active threat-intel providers returning 0 hits.`,
        ar: `اجتازت الفحوصات المكتملة (${passedChecks}) التحقق دون مؤشرات خطرة مع استجابة ${availableProviders}/${totalProviders} من مزودي التهديدات.`,
      });
    }
  }

  const sections: TechnicalSectionSummary[] = SECTION_ORDER.map((sectionId) => {
    const secFindings = findings.filter((f) => f.section === sectionId);
    const st = sectionStatus(secFindings);
    const passed = secFindings.filter((f) => f.status === 'pass').length;
    const warn = secFindings.filter((f) => f.status === 'warning').length;
    const failed = secFindings.filter((f) => f.status === 'failed').length;
    const unk = secFindings.filter((f) => f.status === 'unknown').length;

    let summary: BilingualText;
    if (secFindings.length === 0) {
      summary = {
        en: 'No observations recorded for this module.',
        ar: 'لم تُسجل ملاحظات لهذا القسم.',
      };
    } else if (failed > 0) {
      summary = {
        en: `${failed} failed check(s) requiring attention.`,
        ar: `تم رصد ${failed} فحصاً فاشلاً يتطلب الانتباه.`,
      };
    } else if (warn > 0) {
      summary = {
        en: `${warn} observation / warning indicator(s) recorded.`,
        ar: `تم تسجيل ${warn} ملاحظة أو تحذير.`,
      };
    } else if (unk === secFindings.length) {
      summary = {
        en: 'Telemetry unavailable or not applicable in current runtime.',
        ar: 'البيانات غير متاحة أو تعذر إتمام الفحص في البيئة الحالية.',
      };
    } else {
      summary = {
        en: `All ${passed} completed check(s) passed without anomaly.`,
        ar: `اجتازت الفحوصات المكتملة (${passed}) التحقق دون مؤشرات شاذة.`,
      };
    }

    return {
      id: sectionId,
      title: SECTION_TITLES[sectionId],
      status: st,
      severity: worstSeverity(secFindings),
      summary,
      findingsCount: secFindings.length,
      passedCount: passed,
      warningCount: warn,
      failedCount: failed,
      unknownCount: unk,
    };
  });

  const separatedAssessments = buildSeparatedAssessments(findings, providers, context);

  // =========================================================================
  // CATEGORIZED EVIDENCE BUCKETS (Confirmed / Suspicious / Inconclusive / Conflicting)
  // =========================================================================
  const confirmedBucket: BilingualText[] = [];
  const suspiciousBucket: BilingualText[] = [];
  const inconclusiveBucket: BilingualText[] = [];

  if (isOfficialEntityVerified && context?.domainAuthenticity) {
    confirmedBucket.push({
      en: `Verified Official Ownership: ${context.domainAuthenticity.registrableDomain} (${context.domainAuthenticity.parentCompany || 'Registry Corroborated'}).`,
      ar: `ملكية نطاق رسمية مؤكدة: ${context.domainAuthenticity.registrableDomain} (${context.domainAuthenticity.parentCompany || 'موثق مرجعياً'}).`,
    });
  }

  for (const f of findings) {
    if (f.status === 'failed' && confirmedBucket.length < 8) {
      confirmedBucket.push({
        en: `${f.test.en}: ${f.result.en}`,
        ar: `${f.test.ar}: ${f.result.ar}`,
      });
    } else if (f.status === 'warning' && !POSTURE_ONLY_FINDING_IDS.has(f.id) && suspiciousBucket.length < 8) {
      suspiciousBucket.push({
        en: `${f.test.en}: ${f.result.en}`,
        ar: `${f.test.ar}: ${f.result.ar}`,
      });
    } else if (f.status === 'unknown' && inconclusiveBucket.length < 8) {
      inconclusiveBucket.push({
        en: `${f.test.en}: ${f.result.en}`,
        ar: `${f.test.ar}: ${f.result.ar}`,
      });
    }
  }

  if (confirmedBucket.length === 0 && passedChecks > 0) {
    confirmedBucket.push({
      en: `${passedChecks} deterministic check(s) completed with clean results; ${availableProviders}/${totalProviders} threat feed(s) responded.`,
      ar: `اجتاز ${passedChecks} فحصاً حتمياً التحقق بنجاح مع استجابة ${availableProviders}/${totalProviders} مزود استخبارات.`,
    });
  }

  const evidenceBuckets = {
    confirmed: confirmedBucket,
    suspicious: suspiciousBucket,
    inconclusive: inconclusiveBucket,
    conflicting: conflictNotes,
  };

  return {
    riskScore,
    classification,
    verdict,
    confidenceScore,
    confidenceLabel,
    inspectionCoveragePercent,
    recommendation,
    topReasons,
    correlationNotes,
    conflictNotes,
    scoreBreakdown,
    evidenceBuckets,
    domainAuthenticity: context?.domainAuthenticity as ScanReportDomainAuthenticity | undefined,
    separatedAssessments,
    summaryStats: {
      totalChecks,
      passedChecks,
      warningChecks,
      failedChecks,
      criticalFindings,
      incompleteChecks,
      availableProviders,
      totalProviders,
    },
    sections,
  };
}
