/**
 * Vulnerability lifecycle and timeline tracking.
 * Tracks the evolution of a CVE from discovery through remediation.
 */

const STORAGE_KEY = 'cve_explorer_lifecycles'
let lifecycles = {}

function load() {
  try { lifecycles = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') } catch { lifecycles = {} }
}

function save() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(lifecycles)) } catch { /* storage unavailable */ }
}

export const LIFECYCLE_STATES = [
  'discovered',
  'published',
  'analyzed',
  'exploit_appeared',
  'patch_available',
  'patch_deployed',
  'verified',
  'closed',
]

export function getLifecycle(cveId) {
  if (!Object.keys(lifecycles).length) load()
  return lifecycles[cveId] || createDefaultLifecycle(cveId)
}

function createDefaultLifecycle(cveId) {
  const lifecycle = {
    cveId,
    currentState: 'published',
    transitions: [],
    createdAt: new Date().toISOString(),
  }
  return lifecycle
}

export function transitionLifecycle(cveId, newState, detail = '', user = 'system') {
  if (!Object.keys(lifecycles).length) load()
  const lifecycle = getLifecycle(cveId)

  if (!LIFECYCLE_STATES.includes(newState)) return null

  lifecycle.transitions.push({
    from: lifecycle.currentState,
    to: newState,
    timestamp: new Date().toISOString(),
    by: user,
    detail,
  })
  lifecycle.currentState = newState

  lifecycles[cveId] = lifecycle
  save()
  return lifecycle
}

export function buildTimeline(cveData, enrichments = {}) {
  const events = []

  if (cveData.pub) {
    events.push({
      date: cveData.pub,
      type: 'published',
      label: 'CVE Published',
      detail: cveData.desc?.slice(0, 100) + '...',
      color: '#3b82f6',
    })
  }

  if (cveData.mod && cveData.mod !== cveData.pub) {
    events.push({
      date: cveData.mod,
      type: 'modified',
      label: 'Last Modified',
      detail: 'CVE record updated.',
      color: '#6b7280',
    })
  }

  if (enrichments.kev?.dateAdded) {
    events.push({
      date: enrichments.kev.dateAdded,
      type: 'kev',
      label: 'Added to CISA KEV',
      detail: 'Vulnerability added to Known Exploited Vulnerabilities catalog.',
      color: '#ef4444',
    })
  }

  if (enrichments.kev?.dueDate) {
    events.push({
      date: enrichments.kev.dueDate,
      type: 'kev_deadline',
      label: 'KEV Remediation Deadline',
      detail: 'Federal agencies must remediate by this date.',
      color: '#f97316',
    })
  }

  if (enrichments.hasExploit) {
    events.push({
      date: cveData.mod || cveData.pub || new Date().toISOString(),
      type: 'exploit',
      label: 'Exploit Available',
      detail: 'Public exploit code detected.',
      color: '#dc2626',
    })
  }

  if (enrichments.patchAvailable) {
    events.push({
      date: enrichments.patchDate || new Date().toISOString(),
      type: 'patch',
      label: 'Patch Available',
      detail: 'Vendor patch or fix version released.',
      color: '#22c55e',
    })
  }

  const lifecycle = getLifecycle(cveData.id)
  for (const t of lifecycle.transitions) {
    events.push({
      date: t.timestamp,
      type: 'lifecycle',
      label: `${t.from} → ${t.to}`,
      detail: t.detail,
      color: '#8b5cf6',
    })
  }

  return events.sort((a, b) => new Date(a.date) - new Date(b.date))
}

export function getLifecycleProgress(cveId) {
  const lifecycle = getLifecycle(cveId)
  const idx = LIFECYCLE_STATES.indexOf(lifecycle.currentState)
  return {
    current: lifecycle.currentState,
    progress: Math.round(((idx + 1) / LIFECYCLE_STATES.length) * 100),
    states: LIFECYCLE_STATES,
    currentIndex: idx,
  }
}

export function _resetForTest() {
  lifecycles = {}
}
