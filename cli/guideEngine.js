// Ported from src/utils/guideEngine.js — Enhanced with multi-signal classification
import GUIDES from './guideTemplates.js'

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
  [/template\s*inject|ssti\b|jinja|twig|freemarker|thymeleaf/i, 'ssti'],
  [/json\s*web\s*token|jwt\b|algorithm.*confusion|alg.*none/i, 'jwt'],
  [/cross.site\s*request\s*forg|csrf\b|xsrf\b/i, 'csrf'],
  [/file\s*upload|unrestricted.*upload|arbitrary.*file.*write/i, 'fileupload'],
  [/remote\s*code|code\s*exec|rce\b|arbitrary\s*code|jndi|log4j/i, 'rce'],
]

function classifyVulnerability(cveData) {
  const allResults = []
  const evidence = []

  const cwes = cveData.cwes || []
  for (const cwe of cwes) {
    if (CWE_MAP[cwe]) {
      allResults.push({ key: CWE_MAP[cwe], confidence: 85, source: 'cwe' })
      evidence.push(`CWE mapping: ${cwe}`)
    }
  }

  const desc = (cveData.desc || '').toLowerCase()
  for (const [pattern, key] of KEYWORD_MAP) {
    const match = desc.match(pattern)
    if (match) {
      allResults.push({ key, confidence: 60, source: 'keyword', match: match[0] })
      evidence.push(`Description keyword: "${match[0]}"`)
    }
  }

  const aggregated = {}
  for (const r of allResults) {
    if (!aggregated[r.key]) aggregated[r.key] = { key: r.key, sources: [], totalConfidence: 0 }
    aggregated[r.key].sources.push(r.source)
    aggregated[r.key].totalConfidence += r.confidence
  }

  const sorted = Object.values(aggregated).sort((a, b) => b.totalConfidence - a.totalConfidence)
  const primary = sorted[0] || null

  let confidence = 0
  if (primary) {
    confidence = Math.min(99, primary.totalConfidence + (primary.sources.length - 1) * 10)
    const hasKeyword = allResults.some(r => r.source === 'keyword')
    const hasCWE = allResults.some(r => r.source === 'cwe')
    if (!hasKeyword && !hasCWE) confidence = 20
    if (hasCWE && hasKeyword) confidence = Math.min(99, confidence + 10)
  }

  const isGeneric = !primary || confidence < 40

  return {
    primary: primary ? primary.key : 'generic',
    confidence,
    confidenceLabel: confidence >= 80 ? 'High' : confidence >= 50 ? 'Moderate' : confidence >= 30 ? 'Low' : 'Very Low',
    evidence,
    isGeneric,
  }
}

export function selectGuideKey(cveData) {
  return classifyVulnerability(cveData).primary
}

export function buildGuide(cveData) {
  const classification = classifyVulnerability(cveData)
  const key = classification.primary
  const template = GUIDES[key] || GUIDES.generic
  const resources = (template.resources || []).map(u => u.replace('CVE_ID', cveData.id))
  resources.push(`https://nvd.nist.gov/vuln/detail/${cveData.id}`)
  resources.push(`https://www.exploit-db.com/search?cve=${cveData.id}`)
  resources.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveData.id}`)

  return {
    key,
    name: template.name,
    detect: template.detect || [],
    exploit: template.exploit || [],
    mitigate: template.mitigate || [],
    resources,
    classification,
    isCVEspecific: !classification.isGeneric && classification.confidence >= 50,
  }
}

export function getAllGuideTypes() {
  return Object.entries(GUIDES).map(([key, g]) => ({ key, name: g.name }))
}
