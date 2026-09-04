/**
 * Audit trail - records all security-relevant actions for accountability.
 */

const STORAGE_KEY = 'cve_explorer_audit'
let entries = []

function load() {
  try { entries = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]') } catch { entries = [] }
}

function save() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(entries)) } catch { /* storage unavailable */ }
}

export function getAuditLog(filter = {}) {
  if (!entries.length) load()
  let result = [...entries]
  if (filter.action) result = result.filter(e => e.action === filter.action)
  if (filter.entityType) result = result.filter(e => e.entityType === filter.entityType)
  if (filter.entityId) result = result.filter(e => e.entityId === filter.entityId)
  if (filter.since) result = result.filter(e => new Date(e.timestamp) >= new Date(filter.since))
  return result.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
}

export function logAudit({ action, entityType, entityId, detail = '', user = 'current-user', metadata = {} }) {
  if (!entries.length) load()
  const entry = {
    id: `audit-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    action,
    entityType,
    entityId,
    detail,
    user,
    metadata,
    timestamp: new Date().toISOString(),
  }
  entries.push(entry)
  if (entries.length > 2000) entries = entries.slice(-2000)
  save()
  return entry
}

export function logSearch(cveId, source = 'manual') {
  return logAudit({ action: 'search', entityType: 'cve', entityId: cveId, detail: `Searched for CVE ${cveId}`, metadata: { source } })
}

export function logRemediationAction(recordId, action, detail) {
  return logAudit({ action: `remediation.${action}`, entityType: 'remediation', entityId: recordId, detail })
}

export function logAssetAction(assetId, action, detail) {
  return logAudit({ action: `asset.${action}`, entityType: 'asset', entityId: assetId, detail })
}

export function logClassification(cveId, classification, confidence) {
  return logAudit({ action: 'classify', entityType: 'cve', entityId: cveId, detail: `Classified as ${classification} (confidence: ${confidence}%)` })
}

export function logRiskAssessment(cveId, riskScore) {
  return logAudit({ action: 'risk_assessment', entityType: 'cve', entityId: cveId, detail: `Risk score: ${riskScore}/100` })
}

export function getAuditStats() {
  if (!entries.length) load()
  const byAction = {}
  const byEntityType = {}
  const byUser = {}
  const byDay = {}

  for (const e of entries) {
    byAction[e.action] = (byAction[e.action] || 0) + 1
    byEntityType[e.entityType] = (byEntityType[e.entityType] || 0) + 1
    byUser[e.user] = (byUser[e.user] || 0) + 1
    const day = e.timestamp.slice(0, 10)
    byDay[day] = (byDay[day] || 0) + 1
  }

  return { total: entries.length, byAction, byEntityType, byUser, byDay }
}
