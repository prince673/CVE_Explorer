/**
 * Remediation tracking - track who is fixing what, when, and verify completion.
 * Lifecycle: Open → Assigned → In Progress → Fixed → Verified → Closed
 */

const STORAGE_KEY = 'cve_explorer_remediation'
const STATUSES = ['open', 'assigned', 'in_progress', 'fixed', 'verified', 'closed']
const PRIORITIES = ['p1_critical', 'p2_high', 'p3_medium', 'p4_low']

let records = []
let listeners = []

function load() {
  try { records = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]') } catch { records = [] }
}

function save() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(records)) } catch { /* storage unavailable */ }
  listeners.forEach(fn => fn([...records]))
}

export function onRemediationChange(fn) {
  listeners.push(fn)
  return () => { listeners = listeners.filter(f => f !== fn) }
}

export function getRemediationRecords() {
  if (!records.length) load()
  return [...records]
}

export function getRemediationForCVE(cveId) {
  if (!records.length) load()
  return records.filter(r => r.cveId === cveId)
}

export function createRemediation(cveId, data = {}) {
  if (!records.length) load()
  const record = {
    id: `rem-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    cveId,
    status: data.status || 'open',
    priority: data.priority || 'p3_medium',
    assignedTo: data.assignedTo || '',
    assignedTeam: data.assignedTeam || '',
    dueDate: data.dueDate || null,
    fixDescription: data.fixDescription || '',
    notes: data.notes || '',
    assetId: data.assetId || null,
    verificationMethod: data.verificationMethod || '',
    verifiedBy: data.verifiedBy || '',
    history: [{
      action: 'created',
      timestamp: new Date().toISOString(),
      by: data.createdBy || 'system',
      detail: 'Remediation record created.',
    }],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  records.push(record)
  save()
  return record
}

export function updateRemediation(id, updates) {
  if (!records.length) load()
  const idx = records.findIndex(r => r.id === id)
  if (idx === -1) return null

  const old = { ...records[idx] }
  const historyEntry = {
    action: 'updated',
    timestamp: new Date().toISOString(),
    by: updates.updatedBy || 'system',
    detail: Object.keys(updates).filter(k => k !== 'updatedBy').map(k => {
      if (k === 'status') return `Status: ${old.status} → ${updates.status}`
      if (k === 'assignedTo') return `Assigned to: ${old.assignedTo || 'unassigned'} → ${updates.assignedTo}`
      return `${k} updated`
    }).join('; '),
  }

  records[idx] = {
    ...records[idx],
    ...updates,
    updatedAt: new Date().toISOString(),
    history: [...(records[idx].history || []), historyEntry],
  }
  save()
  return records[idx]
}

export function getRemediationStats() {
  if (!records.length) load()
  const byStatus = {}
  const byPriority = {}
  let overdue = 0
  let avgDaysToFix = 0
  let fixedCount = 0

  for (const r of records) {
    byStatus[r.status] = (byStatus[r.status] || 0) + 1
    byPriority[r.priority] = (byPriority[r.priority] || 0) + 1

    if (r.dueDate && r.status !== 'closed' && r.status !== 'verified') {
      if (new Date(r.dueDate) < new Date()) overdue++
    }

    if (r.status === 'verified' || r.status === 'closed') {
      const created = new Date(r.createdAt)
      const updated = new Date(r.updatedAt)
      avgDaysToFix += (updated - created) / 86400000
      fixedCount++
    }
  }

  return {
    total: records.length,
    byStatus,
    byPriority,
    overdue,
    avgDaysToFix: fixedCount > 0 ? Math.round(avgDaysToFix / fixedCount) : 0,
    openCount: (byStatus.open || 0) + (byStatus.assigned || 0) + (byStatus.in_progress || 0),
    closedCount: (byStatus.verified || 0) + (byStatus.closed || 0),
  }
}

export function getNextStatus(currentStatus) {
  const idx = STATUSES.indexOf(currentStatus)
  if (idx < 0 || idx >= STATUSES.length - 1) return null
  return STATUSES[idx + 1]
}

export { STATUSES, PRIORITIES }

export function _resetForTest() {
  records = []
}
