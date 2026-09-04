/**
 * Alerting system - generate and manage alerts for new CVEs,
 * KEV additions, EPSS changes, and patch releases.
 */

const STORAGE_KEY = 'cve_explorer_alerts'
let alerts = []
let listeners = []

function load() {
  try { alerts = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]') } catch { alerts = [] }
}

function save() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(alerts)) } catch { /* storage unavailable */ }
  listeners.forEach(fn => fn([...alerts]))
}

export function onAlertsChange(fn) {
  listeners.push(fn)
  return () => { listeners = listeners.filter(f => f !== fn) }
}

export function getAlerts(filter = {}) {
  if (!alerts.length) load()
  let result = [...alerts]
  if (filter.unreadOnly) result = result.filter(a => !a.read)
  if (filter.type) result = result.filter(a => a.type === filter.type)
  if (filter.severity) result = result.filter(a => a.severity === filter.severity)
  return result.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
}

export function getUnreadCount() {
  if (!alerts.length) load()
  return alerts.filter(a => !a.read).length
}

export function createAlert({ type, title, message, severity = 'info', cveId = null, source = 'system' }) {
  if (!alerts.length) load()
  const alert = {
    id: `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type,
    title,
    message,
    severity,
    cveId,
    source,
    read: false,
    acknowledged: false,
    createdAt: new Date().toISOString(),
  }
  alerts.unshift(alert)
  if (alerts.length > 500) alerts = alerts.slice(0, 500)
  save()
  return alert
}

export function markAlertRead(id) {
  if (!alerts.length) load()
  const alert = alerts.find(a => a.id === id)
  if (alert) { alert.read = true; save() }
}

export function markAllRead() {
  if (!alerts.length) load()
  alerts.forEach(a => { a.read = true })
  save()
}

export function acknowledgeAlert(id) {
  if (!alerts.length) load()
  const alert = alerts.find(a => a.id === id)
  if (alert) { alert.acknowledged = true; alert.read = true; save() }
}

export function deleteAlert(id) {
  if (!alerts.length) load()
  alerts = alerts.filter(a => a.id !== id)
  save()
}

export function clearAllAlerts() {
  alerts = []
  save()
}

export function checkForNewExploitation(cveId, oldData, newData) {
  if (!oldData?.kev?.inCatalog && newData?.kev?.inCatalog) {
    createAlert({
      type: 'kev_update',
      title: `CVE ${cveId} added to CISA KEV`,
      message: `This vulnerability has been added to the CISA Known Exploited Vulnerabilities catalog, indicating active exploitation in the wild.`,
      severity: 'critical',
      cveId,
      source: 'CISA KEV',
    })
  }
  if (!oldData?.epss && newData?.epss) {
    const prob = parseFloat(newData.epss.probability)
    if (prob >= 0.5) {
      createAlert({
        type: 'epss_increase',
        title: `CVE ${cveId} has high EPSS score`,
        message: `EPSS probability: ${(prob * 100).toFixed(1)}%. This vulnerability has a high likelihood of exploitation.`,
        severity: prob >= 0.7 ? 'critical' : 'high',
        cveId,
        source: 'EPSS',
      })
    }
  }
  if (!oldData?.hasExploit && newData?.hasExploit) {
    createAlert({
      type: 'new_exploit',
      title: `New exploit available for ${cveId}`,
      message: 'Public exploit code has been detected for this CVE.',
      severity: 'high',
      cveId,
      source: 'Exploit-DB',
    })
  }
}
