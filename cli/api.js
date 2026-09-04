// Ported from src/services/cveApi.js — uses native fetch (Node 18+)
const CIRCL_BASE = 'https://cve.circl.lu/api/cve'
const NVD_BASE   = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

function normalizeCircl(d) {
  const cvss3 = d.cvss3?.score ?? d['cvss-score'] ?? null
  const cwes = d.cwe ? [d.cwe] : []
  const refs = (d.references || []).map(u => ({ url: u }))
  const products = (d.vulnerable_configuration || [])
    .slice(0, 20)
    .map(c =>
      typeof c === 'string'
        ? c.replace(/^cpe:[^:]*:[^:]*:/, '').replace(/:/g, ' ')
        : c.id || ''
    )
    .filter(Boolean)
  return {
    id:       d.id,
    desc:     d.summary || 'No description available.',
    cvss3:    cvss3,
    cvss2:    d.cvss ?? null,
    pub:      d.Published,
    mod:      d.Modified,
    cwes,
    refs,
    products,
  }
}

function normalizeNVD(item) {
  let desc = ''
  ;(item.descriptions || []).forEach(x => { if (x.lang === 'en') desc = x.value })
  const m3 = item.metrics?.cvssMetricV31?.[0] || item.metrics?.cvssMetricV30?.[0] || null
  const cwes = []
  ;(item.weaknesses || []).forEach(w =>
    (w.description || []).forEach(x => cwes.push(x.value))
  )
  const refs = (item.references || []).map(r => ({ url: r.url }))
  return {
    id:       item.id,
    desc:     desc || 'No description available.',
    cvss3:    m3?.cvssData?.baseScore ?? null,
    cvss2:    item.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null,
    pub:      item.published,
    mod:      item.lastModified,
    cwes,
    refs,
    products: [],
  }
}

export async function fetchCVE(id) {
  // Try CIRCL first
  try {
    const res = await fetch(`${CIRCL_BASE}/${id}`, { signal: AbortSignal.timeout(10000) })
    if (res.ok) {
      const data = await res.json()
      if (data?.id) return normalizeCircl(data)
    }
  } catch { /* fall through to NVD */ }

  // Fallback: NVD
  try {
    const url = `${NVD_BASE}?cveId=${encodeURIComponent(id)}`
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) })
    if (res.ok) {
      const data = await res.json()
      const item = data?.vulnerabilities?.[0]?.cve
      if (item) return normalizeNVD(item)
    }
  } catch { /* fall through */ }

  throw new Error(`CVE ${id} was not found in any database. Verify the ID and try again.`)
}
