/**
 * Security analytics - quantitative metrics for vulnerability management.
 * Tracks CVEs discovered, severity distributions, remediation rates,
 * and risk trends over time.
 */

const STORAGE_KEY = 'cve_explorer_analytics'
let data = {}

function load() {
  try { data = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') } catch { data = {} }
  if (!data.searches) data.searches = []
  if (!data.classifications) data.classifications = []
  if (!data.riskScores) data.riskScores = []
  if (!data.remediations) data.remediations = []
}

function save() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(data)) } catch { /* storage unavailable */ }
}

export function recordSearch(cveId, result) {
  load()
  data.searches.push({
    cveId,
    timestamp: new Date().toISOString(),
    hadResult: !!result,
    severity: result?.cvss3 || result?.cvss2 || null,
  })
  if (data.searches.length > 1000) data.searches = data.searches.slice(-1000)
  save()
}

export function recordClassification(cveId, classification, confidence, evidence) {
  load()
  data.classifications.push({
    cveId,
    classification,
    confidence,
    evidence: evidence?.length || 0,
    timestamp: new Date().toISOString(),
  })
  if (data.classifications.length > 1000) data.classifications = data.classifications.slice(-1000)
  save()
}

export function recordRiskScore(cveId, score, level) {
  load()
  data.riskScores.push({
    cveId,
    score,
    level,
    timestamp: new Date().toISOString(),
  })
  if (data.riskScores.length > 1000) data.riskScores = data.riskScores.slice(-1000)
  save()
}

export function recordRemediationMetric(cveId, status, timeToFix = null) {
  load()
  data.remediations.push({
    cveId,
    status,
    timeToFix,
    timestamp: new Date().toISOString(),
  })
  if (data.remediations.length > 1000) data.remediations = data.remediations.slice(-1000)
  save()
}

export function getAnalytics() {
  load()
  const now = Date.now()
  const dayMs = 86400000

  const searchesLast7d = data.searches.filter(s => now - new Date(s.timestamp).getTime() < 7 * dayMs).length
  const searchesLast30d = data.searches.filter(s => now - new Date(s.timestamp).getTime() < 30 * dayMs).length

  const severityDist = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
  for (const s of data.searches) {
    if (!s.severity) { severityDist.unknown++; continue }
    const n = parseFloat(s.severity)
    if (n >= 9.0) severityDist.critical++
    else if (n >= 7.0) severityDist.high++
    else if (n >= 4.0) severityDist.medium++
    else severityDist.low++
  }

  const classificationAccuracy = {}
  for (const c of data.classifications) {
    if (!classificationAccuracy[c.classification]) classificationAccuracy[c.classification] = { total: 0, highConf: 0 }
    classificationAccuracy[c.classification].total++
    if (c.confidence >= 70) classificationAccuracy[c.classification].highConf++
  }

  const riskDistribution = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const r of data.riskScores) {
    if (r.score >= 80) riskDistribution.critical++
    else if (r.score >= 60) riskDistribution.high++
    else if (r.score >= 40) riskDistribution.medium++
    else riskDistribution.low++
  }

  const avgRiskScore = data.riskScores.length
    ? Math.round(data.riskScores.reduce((s, r) => s + r.score, 0) / data.riskScores.length)
    : 0

  const remediationStats = {
    total: data.remediations.length,
    open: data.remediations.filter(r => r.status === 'open').length,
    fixed: data.remediations.filter(r => r.status === 'verified' || r.status === 'closed').length,
    avgTimeToFix: 0,
  }

  const fixedRemediations = data.remediations.filter(r => r.timeToFix != null)
  if (fixedRemediations.length) {
    remediationStats.avgTimeToFix = Math.round(
      fixedRemediations.reduce((s, r) => s + r.timeToFix, 0) / fixedRemediations.length
    )
  }

  return {
    totalSearches: data.searches.length,
    searchesLast7d,
    searchesLast30d,
    severityDistribution: severityDist,
    classificationMetrics: classificationAccuracy,
    riskDistribution,
    avgRiskScore,
    remediationStats,
    uniqueCVEs: new Set(data.searches.map(s => s.cveId)).size,
    generatedAt: new Date().toISOString(),
  }
}

export function clearAnalytics() {
  data = { searches: [], classifications: [], riskScores: [], remediations: [] }
  save()
}
