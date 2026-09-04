/**
 * Multi-signal risk scoring engine.
 * Combines CVSS, EPSS, KEV, exploit availability, product popularity,
 * and environmental factors into an actionable risk score with explanation.
 */

const WEIGHTS = {
  cvss: 25,
  epss: 20,
  kev: 20,
  exploitAvailability: 10,
  productPopularity: 10,
  age: 5,
  references: 5,
  cweSeverity: 5,
}

const CRITICAL_CWES = new Set([
  'CWE-20', 'CWE-22', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94',
  'CWE-287', 'CWE-306', 'CWE-352', 'CWE-502', 'CWE-611', 'CWE-798',
  'CWE-862', 'CWE-863', 'CWE-918',
])

const POPULAR_PRODUCTS = new Set([
  'apache', 'nginx', 'mysql', 'postgresql', 'redis', 'docker',
  'kubernetes', 'log4j', 'log4shell', 'spring', 'tomcat', 'openssl',
  'windows', 'linux', 'android', 'chrome', 'firefox', 'node.js',
  'python', 'java', 'php', 'ruby', '.net', 'iis', 'exchange',
  'sharepoint', 'outlook', 'citrix', 'vmware', 'fortinet', 'palo alto',
  'cisco', 'jboss', 'weblogic', 'jenkins', 'gitlab', 'wordpress',
  'drupal', 'joomla', 'magento', 'zoom', 'teams', 'slack',
])

function cvssScore(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return { score: 0, label: 'No CVSS score', evidence: 'CVSS score not available from NVD.' }
  const normalized = (n / 10) * WEIGHTS.cvss
  let label = 'Low'
  if (n >= 9.0) label = 'Critical'
  else if (n >= 7.0) label = 'High'
  else if (n >= 4.0) label = 'Medium'
  return {
    score: normalized,
    label: `${label} (${n}/10)`,
    evidence: `CVSS base score: ${n} (${label} severity).`,
  }
}

function epssScore(probability) {
  if (probability == null) return { score: 0, label: 'No EPSS data', evidence: 'EPSS probability not available.' }
  const p = parseFloat(probability)
  if (isNaN(p)) return { score: 0, label: 'No EPSS data', evidence: 'EPSS probability not available.' }
  const normalized = p * WEIGHTS.epss
  let label = 'Low'
  if (p >= 0.7) label = 'Very High'
  else if (p >= 0.4) label = 'High'
  else if (p >= 0.1) label = 'Moderate'
  return {
    score: normalized,
    label: `${label} (${(p * 100).toFixed(1)}%)`,
    evidence: `EPSS probability of exploitation: ${(p * 100).toFixed(1)}%.`,
  }
}

function kevScore(inKEV, dateAdded) {
  if (!inKEV) return { score: 0, label: 'Not in KEV', evidence: 'CVE is not in the CISA Known Exploited Vulnerabilities catalog.' }
  const daysSince = dateAdded ? Math.floor((Date.now() - new Date(dateAdded).getTime()) / 86400000) : 0
  const recencyBonus = Math.max(0, 1 - daysSince / 365) * 5
  return {
    score: WEIGHTS.kev + recencyBonus,
    label: `In KEV (${daysSince}d ago)`,
    evidence: `Listed in CISA KEV catalog. ${daysSince > 0 ? `Added ${daysSince} days ago.` : 'Recently added.'}`,
  }
}

function exploitScore(hasExploit) {
  if (!hasExploit) return { score: 0, label: 'No known exploits', evidence: 'No public exploits found on Exploit-DB or GitHub.' }
  return {
    score: WEIGHTS.exploitAvailability,
    label: 'Exploits available',
    evidence: 'Public exploit code is available for this CVE.',
  }
}

function popularityScore(products) {
  if (!products?.length) return { score: 0, label: 'Unknown product', evidence: 'No affected product information available.' }
  const match = products.some(p => {
    const lower = p.toLowerCase()
    return POPULAR_PRODUCTS.has(lower) || [...POPULAR_PRODUCTS].some(pop => lower.includes(pop))
  })
  if (match) return {
    score: WEIGHTS.productPopularity,
    label: 'Popular product',
    evidence: `Affected product is widely deployed: ${products[0]}.`,
  }
  return { score: 2, label: 'Niche product', evidence: 'Affected product does not appear in common widely-deployed software list.' }
}

function ageScore(published) {
  if (!published) return { score: 2, label: 'Unknown age', evidence: 'Publication date not available.' }
  const days = Math.floor((Date.now() - new Date(published).getTime()) / 86400000)
  if (days < 30) return { score: WEIGHTS.age, label: 'Very recent', evidence: `Published ${days} days ago. Very new vulnerabilities often lack patches.` }
  if (days < 180) return { score: 4, label: 'Recent', evidence: `Published ${days} days ago.` }
  if (days < 365) return { score: 2, label: 'Moderate age', evidence: `Published ${days} days ago.` }
  return { score: 1, label: 'Old', evidence: `Published ${days} days ago. Older vulnerabilities likely have patches available.` }
}

function referenceScore(refs) {
  const count = refs?.length || 0
  if (count >= 10) return { score: WEIGHTS.references, label: 'Well documented', evidence: `${count} references available.` }
  if (count >= 5) return { score: 3, label: 'Moderately documented', evidence: `${count} references available.` }
  return { score: 1, label: 'Poorly documented', evidence: `Only ${count} reference(s). Less documentation may indicate lower community awareness.` }
}

function cweRiskScore(cwes) {
  if (!cwes?.length) return { score: 0, label: 'No CWE assigned', evidence: 'No CWE weakness classification available.' }
  const hasCritical = cwes.some(c => CRITICAL_CWES.has(c))
  if (hasCritical) return {
    score: WEIGHTS.cweSeverity,
    label: 'Critical weakness category',
    evidence: `Includes critical CWE: ${cwes.find(c => CRITICAL_CWES.has(c))}.`,
  }
  return { score: 3, label: 'Moderate weakness', evidence: `CWE categories: ${cwes.slice(0, 3).join(', ')}.` }
}

export function calculateRiskScore(cveData, enrichments = {}) {
  const signals = {
    cvss: cvssScore(cveData.cvss3 || cveData.cvss2),
    epss: epssScore(enrichments.epss?.probability),
    kev: kevScore(enrichments.kev?.inCatalog, enrichments.kev?.dateAdded),
    exploitAvailability: exploitScore(enrichments.hasExploit),
    productPopularity: popularityScore(cveData.products),
    age: ageScore(cveData.pub),
    references: referenceScore(cveData.refs),
    cweSeverity: cweRiskScore(cveData.cwes),
  }

  const totalScore = Object.values(signals).reduce((sum, s) => sum + s.score, 0)
  const maxScore = Object.values(WEIGHTS).reduce((sum, w) => sum + w, 0)
  const normalizedScore = Math.round((totalScore / maxScore) * 100)
  const clampedScore = Math.min(100, Math.max(0, normalizedScore))

  let riskLevel = 'Low'
  let riskColor = '#10b981'
  if (clampedScore >= 80) { riskLevel = 'Critical'; riskColor = '#ef4444' }
  else if (clampedScore >= 60) { riskLevel = 'High'; riskColor = '#f97316' }
  else if (clampedScore >= 40) { riskLevel = 'Medium'; riskColor = '#eab308' }
  else if (clampedScore >= 20) { riskLevel = 'Low-Medium'; riskColor = '#22d3ee' }

  const topFactors = Object.entries(signals)
    .filter(([, s]) => s.score > 0)
    .sort(([, a], [, b]) => b.score - a.score)
    .slice(0, 6)
    .map(([key, s]) => ({
      factor: key.replace(/([A-Z])/g, ' $1').replace(/^./, c => c.toUpperCase()),
      score: Math.round(s.score),
      label: s.label,
      evidence: s.evidence,
    }))

  return {
    score: clampedScore,
    level: riskLevel,
    color: riskColor,
    signals,
    topFactors,
    explanation: topFactors.map(f => `${f.factor}: ${f.evidence}`).join(' '),
    calculatedAt: new Date().toISOString(),
  }
}

export function calculateExploitability(cveData, enrichments = {}) {
  const factors = []
  let score = 0

  const cvss = parseFloat(cveData.cvss3 || cveData.cvss2 || 0)
  if (cvss >= 9.0) { factors.push({ factor: 'CVSS Critical', detail: 'Base score indicates critical severity.', weight: 25 }); score += 25 }
  else if (cvss >= 7.0) { factors.push({ factor: 'CVSS High', detail: 'Base score indicates high severity.', weight: 15 }); score += 15 }
  else if (cvss >= 4.0) { factors.push({ factor: 'CVSS Medium', detail: 'Base score indicates medium severity.', weight: 8 }); score += 8 }

  if (enrichments.kev?.inCatalog) { factors.push({ factor: 'Known Exploited', detail: 'Listed in CISA KEV - active exploitation confirmed.', weight: 30 }); score += 30 }

  if (enrichments.hasExploit) { factors.push({ factor: 'Exploit Available', detail: 'Public exploit code exists.', weight: 20 }); score += 20 }

  const epss = enrichments.epss?.probability
  if (epss != null && parseFloat(epss) >= 0.5) { factors.push({ factor: 'High EPSS', detail: `${(parseFloat(epss) * 100).toFixed(1)}% exploitation probability.`, weight: 15 }); score += 15 }

  if (cvss >= 7.0 && enrichments.kev?.inCatalog) { factors.push({ factor: 'Network Reachability', detail: 'High CVSS with known exploitation suggests network-exploitable.', weight: 10 }); score += 10 }

  const clamped = Math.min(100, score)
  let level = 'LOW'
  if (clamped >= 70) level = 'HIGH'
  else if (clamped >= 40) level = 'MODERATE'

  return { score: clamped, level, factors, assessedAt: new Date().toISOString() }
}

export function distinguishSeverityVsRisk(cveData, riskScore, exploitability) {
  const cvss = parseFloat(cveData.cvss3 || cveData.cvss2 || 0)
  let severityLabel = 'Unknown'
  if (cvss >= 9.0) severityLabel = 'Critical'
  else if (cvss >= 7.0) severityLabel = 'High'
  else if (cvss >= 4.0) severityLabel = 'Medium'
  else severityLabel = 'Low'

  const riskLabel = riskScore.level
  const exploitLabel = exploitability.level

  const divergence = Math.abs(riskScore.score - (cvss * 10))
  const hasDivergence = divergence > 25

  let interpretation = ''
  if (riskScore.score > cvss * 10) {
    interpretation = `Organizational risk (${riskScore.score}/100) exceeds technical severity (${cvss}/10) due to active exploitation signals.`
  } else if (riskScore.score < cvss * 10) {
    interpretation = `Organizational risk (${riskScore.score}/100) is lower than technical severity (${cvss}/10), possibly due to limited exploitation evidence or niche product.`
  } else {
    interpretation = `Technical severity and organizational risk are aligned at ${cvss}/10.`
  }

  return {
    technicalSeverity: severityLabel,
    cvssScore: cvss,
    organizationalRisk: riskLabel,
    riskScore: riskScore.score,
    exploitabilityAssessment: exploitLabel,
    exploitabilityScore: exploitability.score,
    hasDivergence,
    divergence: Math.round(divergence),
    interpretation,
    recommendation: riskScore.score >= 60
      ? 'PRIORITY: This vulnerability should be remediated urgently.'
      : riskScore.score >= 30
        ? 'SCHEDULE: Plan remediation within standard patch cycle.'
        : 'MONITOR: Track for changes in exploitation status.',
  }
}
