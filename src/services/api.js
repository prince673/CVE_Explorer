/**
 * Backend API client - replaces all client-side service modules.
 * All intelligence now comes from the FastAPI backend.
 */

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

async function apiFetch(path, options = {}) {
  const resp = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }))
    throw new Error(err.detail || `API error ${resp.status}`)
  }
  return resp.json()
}

export async function lookupCVE(cveId) {
  return apiFetch(`/api/cve/${encodeURIComponent(cveId)}`)
}

export async function fetchCVEEnrichments(cveId) {
  return apiFetch(`/api/cve/${encodeURIComponent(cveId)}/enrichments`)
}

export async function fetchAffectedAssets(cveId) {
  return apiFetch(`/api/cve/${encodeURIComponent(cveId)}/assets`)
}

export async function listAssets() {
  return apiFetch('/api/assets/')
}

export async function createAsset(data) {
  return apiFetch('/api/assets/', { method: 'POST', body: JSON.stringify(data) })
}

export async function deleteAsset(assetId) {
  return apiFetch(`/api/assets/${assetId}`, { method: 'DELETE' })
}

export async function getAssetSummary() {
  return apiFetch('/api/assets/summary')
}

export async function getAssetCVEs(assetId) {
  return apiFetch(`/api/assets/${assetId}/cves`)
}

export async function getRemediationForCVE(cveId) {
  return apiFetch(`/api/remediation/${encodeURIComponent(cveId)}`)
}

export async function createRemediation(data) {
  return apiFetch('/api/remediation/', { method: 'POST', body: JSON.stringify(data) })
}

export async function updateRemediation(recordId, data) {
  return apiFetch(`/api/remediation/${recordId}`, { method: 'PATCH', body: JSON.stringify(data) })
}

export async function getRemediationStats() {
  return apiFetch('/api/remediation/stats/overview')
}

export async function listAlerts(opts = {}) {
  const params = new URLSearchParams()
  if (opts.unreadOnly) params.set('unread_only', 'true')
  if (opts.type) params.set('alert_type', opts.type)
  return apiFetch(`/api/alerts/?${params}`)
}

export async function getUnreadAlertCount() {
  return apiFetch('/api/alerts/unread-count')
}

export async function markAlertRead(alertId) {
  return apiFetch(`/api/alerts/${alertId}/read`, { method: 'PATCH' })
}

export async function markAllAlertsRead() {
  return apiFetch('/api/alerts/read-all', { method: 'POST' })
}

export async function acknowledgeAlert(alertId) {
  return apiFetch(`/api/alerts/${alertId}/acknowledge`, { method: 'PATCH' })
}

export async function getDashboardAnalytics() {
  return apiFetch('/api/analytics/dashboard')
}

export async function healthCheck() {
  return apiFetch('/api/health')
}
