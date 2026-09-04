/**
 * Enhanced guide engine with:
 * - Multi-signal classification (CWE + CVSS + description + references + product)
 * - Confidence scoring with evidence chain
 * - Primary + secondary classifications
 * - CVE-specific reasoning vs generic guide distinction
 * - Explainability for every classification decision
 */

import GUIDES from '../data/guideTemplates'

const CWE_MAP = {
  'CWE-89': 'sqli', 'CWE-564': 'sqli',
  'CWE-79': 'xss', 'CWE-80': 'xss',
  'CWE-78': 'cmdinj', 'CWE-77': 'cmdinj', 'CWE-88': 'cmdinj',
  'CWE-22': 'traversal', 'CWE-23': 'traversal', 'CWE-35': 'traversal',
  'CWE-98': 'lfi',
  'CWE-502': 'deser',
  'CWE-918': 'ssrf', 'CWE-406': 'ssrf',
  'CWE-611': 'xxe', 'CWE-827': 'xxe',
  'CWE-284': 'idor', 'CWE-639': 'idor', 'CWE-285': 'idor',
  'CWE-601': 'redirect',
  'CWE-94': 'rce', 'CWE-74': 'rce', 'CWE-917': 'rce',
  'CWE-1336': 'ssti',
  'CWE-347': 'jwt', 'CWE-327': 'jwt', 'CWE-345': 'jwt',
  'CWE-352': 'csrf',
  'CWE-434': 'fileupload', 'CWE-436': 'fileupload',
}

const KEYWORD_MAP = [
  [/sql\s*inject|sqli\b|UNION\s+SELECT|blind\s*inject/i, 'sqli'],
  [/cross.site\s*script|xss\b|innerHTML|document\.cookie/i, 'xss'],
  [/command\s*inject|os\s*command|shell\s*inject/i, 'cmdinj'],
  [/path\s*travers|directory\s*travers|\.\.\/|\.\\.\\/i, 'traversal'],
  [/file\s*inclus|php:\/\/|include\s*\(.*\$/i, 'lfi'],
  [/deserializ|unserializ|pickle|marshal/i, 'deser'],
  [/server.side\s*request\s*forg|ssrf\b|169\.254\.169\.254/i, 'ssrf'],
  [/xml\s*external\s*entity|xxe\b|DOCTYPE.*ENTITY/i, 'xxe'],
  [/insecure\s*direct\s*object|idor\b|unauthorized.*object|broken\s*access/i, 'idor'],
  [/open\s*redirect|unvalidated\s*redirect/i, 'redirect'],
  [/template\s*inject|ssti\b|jinja|twig|freemarker|thymeleaf|mustache/i, 'ssti'],
  [/json\s*web\s*token|jwt\b|algorithm.*confusion|alg.*none|token.*forg/i, 'jwt'],
  [/cross.site\s*request\s*forg|csrf\b|xsrf\b/i, 'csrf'],
  [/file\s*upload|unrestricted.*upload|arbitrary.*file.*write|webshell/i, 'fileupload'],
  [/remote\s*code|code\s*exec|rce\b|arbitrary\s*code|jndi|log4j|log4shell/i, 'rce'],
]

const CWE_DESCRIPTIONS = {
  'CWE-89': 'SQL Injection',
  'CWE-79': 'Cross-site Scripting',
  'CWE-78': 'OS Command Injection',
  'CWE-22': 'Path Traversal',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-918': 'Server-Side Request Forgery',
  'CWE-611': 'XML External Entity',
  'CWE-284': 'Improper Access Control',
  'CWE-601': 'Open Redirect',
  'CWE-94': 'Code Injection',
  'CWE-1336': 'Server-Side Template Injection',
  'CWE-347': 'Improper Verification of Cryptographic Signature',
  'CWE-352': 'Cross-Site Request Forgery',
  'CWE-434': 'Unrestricted Upload of File',
  'CWE-20': 'Improper Input Validation',
  'CWE-77': 'Command Injection',
  'CWE-287': 'Improper Authentication',
  'CWE-798': 'Hard-coded Credentials',
  'CWE-862': 'Missing Authorization',
  'CWE-863': 'Incorrect Authorization',
}

function classifyByCWE(cwes) {
  const results = []
  const evidence = []
  for (const cwe of cwes) {
    if (CWE_MAP[cwe]) {
      results.push({ key: CWE_MAP[cwe], confidence: 85, source: 'cwe' })
      evidence.push(`CWE mapping: ${cwe} → ${CWE_DESCRIPTIONS[cwe] || cwe}`)
    }
  }
  return { results, evidence }
}

function classifyByKeywords(description) {
  const results = []
  const evidence = []
  const lower = (description || '').toLowerCase()
  for (const [pattern, key] of KEYWORD_MAP) {
    const match = lower.match(pattern)
    if (match) {
      results.push({ key, confidence: 60, source: 'keyword', match: match[0] })
      evidence.push(`Description keyword match: "${match[0]}"`)
    }
  }
  return { results, evidence }
}

function classifyByCVSS(cvssVector, cvss3) {
  const evidence = []
  if (!cvssVector) return { results: [], evidence }

  const av = cvssVector.match(/AV:([AECN])/)?.[1]
  const ac = cvssVector.match(/AC:([AH])/)?.[1]
  const pr = cvssVector.match(/PR:([NHL])/)?.[1]
  const ui = cvssVector.match(/UI:([NR])/)?.[1]
  const score = parseFloat(cvss3 || 0)

  if (av === 'N' && ac === 'L' && pr === 'N' && ui === 'N' && score >= 9.0) {
    evidence.push('CVSS vector suggests network-exploitable, low complexity, no auth - likely RCE or critical access control flaw.')
  }
  if (av === 'N' && score >= 7.0) {
    evidence.push('Network-accessible vulnerability with high impact.')
  }

  return { results: [], evidence }
}

function classifyByReferences(refs) {
  const evidence = []
  if (!refs?.length) return { results: [], evidence }

  const refUrls = refs.map(r => (r.url || r).toLowerCase())
  const hasVendorAdvisory = refUrls.some(u =>
    u.includes('vendor') || u.includes('advisory') || u.includes('security') ||
    u.includes('patch') || u.includes('bulletin')
  )
  const hasExploit = refUrls.some(u =>
    u.includes('exploit') || u.includes('github.com') || u.includes('packetstorm')
  )
  const hasNVD = refUrls.some(u => u.includes('nvd.nist.gov'))

  if (hasExploit) evidence.push('References include exploit code repositories.')
  if (hasVendorAdvisory) evidence.push('Vendor advisory available in references.')
  if (hasNVD) evidence.push('NVD reference confirmed.')

  return { results: [], evidence }
}

function classifyByProducts(products, desc) {
  const evidence = []
  if (!products?.length) return { results: [], evidence }

  const descLower = (desc || '').toLowerCase()
  for (const p of products.slice(0, 5)) {
    const pLower = p.toLowerCase()
    if (descLower.includes(pLower)) {
      evidence.push(`Affected product "${p}" confirmed in description.`)
    }
  }

  return { results: [], evidence }
}

export function classifyVulnerability(cveData) {
  const allResults = []
  const allEvidence = []

  const cweClass = classifyByCWE(cveData.cwes || [])
  allResults.push(...cweClass.results)
  allEvidence.push(...cweClass.evidence)

  const kwClass = classifyByKeywords(cveData.desc)
  allResults.push(...kwClass.results)
  allEvidence.push(...kwClass.evidence)

  const cvssClass = classifyByCVSS(cveData.cvss3Vector, cveData.cvss3)
  allResults.push(...cvssClass.results)
  allEvidence.push(...cvssClass.evidence)

  const refClass = classifyByReferences(cveData.refs)
  allResults.push(...refClass.results)
  allEvidence.push(...refClass.evidence)

  const prodClass = classifyByProducts(cveData.products, cveData.desc)
  allResults.push(...prodClass.results)
  allEvidence.push(...prodClass.evidence)

  const aggregated = {}
  for (const r of allResults) {
    if (!aggregated[r.key]) aggregated[r.key] = { key: r.key, sources: [], totalConfidence: 0 }
    aggregated[r.key].sources.push(r.source)
    aggregated[r.key].totalConfidence += r.confidence
  }

  const sorted = Object.values(aggregated)
    .sort((a, b) => b.totalConfidence - a.totalConfidence)

  const primary = sorted[0] || null
  const secondary = sorted.slice(1)

  let overallConfidence = 0
  if (primary) {
    const sourceCount = primary.sources.length
    overallConfidence = Math.min(99, primary.totalConfidence + (sourceCount - 1) * 10)
    if (kwClass.results.length === 0 && cweClass.results.length === 0) overallConfidence = 20
    if (cweClass.results.length > 0 && kwClass.results.length > 0) overallConfidence = Math.min(99, overallConfidence + 10)
  }

  const isGeneric = !primary || overallConfidence < 40

  return {
    primary: primary ? primary.key : 'generic',
    primaryLabel: primary ? (GUIDES[primary.key]?.name || primary.key) : 'General Vulnerability',
    secondary: secondary.map(s => ({ key: s.key, label: GUIDES[s.key]?.name || s.key })),
    confidence: overallConfidence,
    confidenceLabel: overallConfidence >= 80 ? 'High' : overallConfidence >= 50 ? 'Moderate' : overallConfidence >= 30 ? 'Low' : 'Very Low',
    evidence: allEvidence,
    isGeneric,
    allMatches: sorted,
    classifiedAt: new Date().toISOString(),
  }
}

export function selectGuideKey(cveData) {
  const classification = classifyVulnerability(cveData)
  return classification.primary
}

export function buildGuide(cveData) {
  const classification = classifyVulnerability(cveData)
  const key = classification.primary
  const template = GUIDES[key] || GUIDES.generic

  const resources = (template.resources || []).map(u => u.replace('CVE_ID', cveData.id))
  resources.push(`https://nvd.nist.gov/vuln/detail/${cveData.id}`)
  resources.push(`https://www.exploit-db.com/search?cve=${cveData.id}`)
  resources.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveData.id}`)

  const isCVEspecific = !classification.isGeneric && classification.confidence >= 50

  return {
    key,
    name: template.name,
    detect: template.detect || [],
    exploit: template.exploit || [],
    mitigate: template.mitigate || [],
    resources,
    classification,
    isCVEspecific,
    disclaimer: isCVEspecific
      ? `This guide is classified as "${classification.primaryLabel}" with ${classification.confidence}% confidence based on ${classification.evidence.length} evidence signals.`
      : `No specific vulnerability type could be confidently identified. Showing general educational information. Classification confidence: ${classification.confidence}%.`,
  }
}

export function getAllGuideTypes() {
  return Object.entries(GUIDES).map(([key, g]) => ({ key, name: g.name }))
}
