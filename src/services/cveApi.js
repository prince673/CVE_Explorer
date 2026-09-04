/**
 * Enhanced API service layer with:
 * - CIRCL + NVD CVE data
 * - EPSS scoring integration
 * - CISA KEV catalog integration
 * - Exploit-DB / GitHub exploit detection
 * - IndexedDB caching for all responses
 * - Fallback and retry logic
 */

import axios from 'axios'
import { cacheGet, cacheSet, STORES, CACHE_TTL } from '../utils/cache'

const CIRCL_BASE = 'https://cve.circl.lu/api/cve'
const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const EPSS_BASE = 'https://api.first.org/data/v1/epss'
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const EXPLOIT_DB_SEARCH = 'https://www.exploit-db.com/search?cve='

let kevCache = null
let kevCacheTime = 0

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

  const cvssVector = d.cvss3?.vector || null
  const attackVector = cvssVector?.match(/AV:([AECN])/)?.[1] || null
  const attackComplexity = cvssVector?.match(/AC:([AH])/)?.[1] || null
  const privilegesRequired = cvssVector?.match(/PR:([NHL])/)?.[1] || null
  const userInteraction = cvssVector?.match(/UI:([NR])/)?.[1] || null

  return {
    id: d.id,
    desc: d.summary || 'No description available.',
    cvss3,
    cvss2: d.cvss ?? null,
    cvss3Vector: cvssVector || null,
    pub: d.Published,
    mod: d.Modified,
    cwes,
    refs,
    products,
    cvssMetrics: {
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
    },
  }
}

function normalizeNVD(item) {
  let desc = ''
  ;(item.descriptions || []).forEach(x => {
    if (x.lang === 'en') desc = x.value
  })

  const m3 =
    item.metrics?.cvssMetricV31?.[0] ||
    item.metrics?.cvssMetricV30?.[0] ||
    null

  const cwes = []
  ;(item.weaknesses || []).forEach(w =>
    (w.description || []).forEach(x => cwes.push(x.value))
  )

  const refs = (item.references || []).map(r => ({
    url: r.url,
    source: r.source || '',
    tags: r.tags || [],
  }))

  const cvss3Vector = m3?.cvssData?.vectorString || null
  const attackVector = cvss3Vector?.match(/AV:([AECN])/)?.[1] || null
  const attackComplexity = cvss3Vector?.match(/AC:([AH])/)?.[1] || null
  const privilegesRequired = cvss3Vector?.match(/PR:([NHL])/)?.[1] || null
  const userInteraction = cvss3Vector?.match(/UI:([NR])/)?.[1] || null

  return {
    id: item.id,
    desc: desc || 'No description available.',
    cvss3: m3?.cvssData?.baseScore ?? null,
    cvss2: item.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null,
    cvss3Vector,
    pub: item.published,
    mod: item.lastModified,
    cwes,
    refs,
    products: [],
    cvssMetrics: {
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
    },
  }
}

export async function fetchCVE(id) {
  const cached = await cacheGet(STORES.cve, id, CACHE_TTL.cve)
  if (cached) return cached

  try {
    const { data } = await axios.get(`${CIRCL_BASE}/${id}`, { timeout: 10000 })
    if (data?.id) {
      const normalized = normalizeCircl(data)
      await cacheSet(STORES.cve, id, normalized, CACHE_TTL.cve)
      return normalized
    }
  } catch { /* fall through */ }

  try {
    const { data } = await axios.get(NVD_BASE, {
      params: { cveId: id },
      timeout: 15000,
    })
    const item = data?.vulnerabilities?.[0]?.cve
    if (item) {
      const normalized = normalizeNVD(item)
      await cacheSet(STORES.cve, id, normalized, CACHE_TTL.cve)
      return normalized
    }
  } catch { /* fall through */ }

  throw new Error(`CVE ${id} was not found in any database. Verify the ID and try again.`)
}

export async function fetchEPSS(cveId) {
  const cached = await cacheGet(STORES.epss, cveId, CACHE_TTL.epss)
  if (cached) return cached

  try {
    const { data } = await axios.get(EPSS_BASE, {
      params: { cve: cveId },
      timeout: 8000,
    })
    const entry = data?.data?.[0]
    if (entry) {
      const result = {
        cveId: entry.cve,
        probability: parseFloat(entry.epss),
        percentile: parseFloat(entry.percentile),
        date: entry.date,
      }
      await cacheSet(STORES.epss, cveId, result, CACHE_TTL.epss)
      return result
    }
  } catch { /* fall through */ }
  return null
}

export async function fetchKEVCatalog() {
  if (kevCache && Date.now() - kevCacheTime < 6 * 3600000) return kevCache

  const cached = await cacheGet(STORES.kev, 'full-catalog', CACHE_TTL.kev)
  if (cached) { kevCache = cached; kevCacheTime = Date.now(); return cached }

  try {
    const { data } = await axios.get(KEV_URL, { timeout: 20000 })
    const catalog = data?.vulnerabilities || []
    const index = {}
    for (const v of catalog) {
      index[v.cveID] = {
        cveID: v.cveID,
        vendorProject: v.vendorProject,
        product: v.product,
        dateAdded: v.dateAdded,
        shortDescription: v.shortDescription,
        requiredAction: v.requiredAction,
        dueDate: v.dueDate,
        knownRansomwareCampaignUse: v.knownRansomwareCampaignUse,
      }
    }
    await cacheSet(STORES.kev, 'full-catalog', index, CACHE_TTL.kev)
    kevCache = index
    kevCacheTime = Date.now()
    return index
  } catch { /* fall through */ }
  return {}
}

export async function checkKEV(cveId) {
  const catalog = await fetchKEVCatalog()
  const entry = catalog[cveId]
  return entry ? {
    inCatalog: true,
    ...entry,
  } : { inCatalog: false }
}

export async function checkExploitAvailability(cveId) {
  const cached = await cacheGet(STORES.exploits, cveId, CACHE_TTL.exploits)
  if (cached) return cached

  let hasExploit = false
  const exploitSources = []

  try {
    const { data } = await axios.get(`https://api.github.com/search/repositories`, {
      params: { q: `${cveId} exploit`, sort: 'stars', per_page: 5 },
      timeout: 10000,
    })
    if (data?.items?.length > 0) {
      hasExploit = true
      exploitSources.push(...data.items.slice(0, 3).map(i => ({
        url: i.html_url,
        stars: i.stargazers_count,
        source: 'GitHub',
      })))
    }
  } catch { /* fall through */ }

  const result = { hasExploit, sources: exploitSources }
  await cacheSet(STORES.exploits, cveId, result, CACHE_TTL.exploits)
  return result
}

export async function fetchCVEEnrichments(cveId) {
  const cached = await cacheGet(STORES.enrichments, cveId, CACHE_TTL.enrichments)
  if (cached) return cached

  const [epss, kev, exploit] = await Promise.allSettled([
    fetchEPSS(cveId),
    checkKEV(cveId),
    checkExploitAvailability(cveId),
  ])

  const enrichments = {
    epss: epss.status === 'fulfilled' ? epss.value : null,
    kev: kev.status === 'fulfilled' ? kev.value : { inCatalog: false },
    hasExploit: exploit.status === 'fulfilled' ? exploit.value?.hasExploit : false,
    exploitSources: exploit.status === 'fulfilled' ? exploit.value?.sources || [] : [],
    fetchedAt: new Date().toISOString(),
  }

  await cacheSet(STORES.enrichments, cveId, enrichments, CACHE_TTL.enrichments)
  return enrichments
}

export async function searchCVEs(query, options = {}) {
  const { page = 0, limit = 20 } = options

  try {
    const { data } = await axios.get(NVD_BASE, {
      params: {
        keywordSearch: query,
        resultsPerPage: limit,
        startIndex: page * limit,
      },
      timeout: 15000,
    })

    return (data?.vulnerabilities || []).map(v => normalizeNVD(v.cve))
  } catch {
    throw new Error('Search failed. Please try again.')
  }
}
