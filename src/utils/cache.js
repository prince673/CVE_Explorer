/**
 * IndexedDB + localStorage caching layer for CVE data, EPSS, KEV, and enrichments.
 * Provides offline capability and reduces API dependency.
 */

const DB_NAME = 'cve-explorer-db'
const DB_VERSION = 1
const STORES = {
  cve: 'cve-cache',
  epss: 'epss-cache',
  kev: 'kev-cache',
  exploits: 'exploit-cache',
  enrichments: 'enrichment-cache',
  assets: 'asset-store',
  remediation: 'remediation-store',
  alerts: 'alert-store',
  audit: 'audit-log',
  searchHistory: 'search-history',
}

let dbInstance = null

function openDB() {
  if (dbInstance) return Promise.resolve(dbInstance)
  return new Promise((resolve) => {
    if (typeof indexedDB === 'undefined') {
      resolve(null)
      return
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = (e) => {
      const db = e.target.result
      Object.values(STORES).forEach(name => {
        if (!db.objectStoreNames.contains(name)) {
          db.createObjectStore(name, { keyPath: 'key' })
        }
      })
    }
    req.onsuccess = (e) => { dbInstance = e.target.result; resolve(dbInstance) }
    req.onerror = () => resolve(null)
  })
}

async function runInStore(storeName, mode, fn) {
  const db = await openDB()
  if (!db) return null
  const tx = db.transaction(storeName, mode)
  const store = tx.objectStore(storeName)
  try {
    return await Promise.resolve(fn(store, tx))
  } catch {
    return null
  }
}

export async function cacheSet(storeName, key, value, ttlMs = 3600000) {
  const result = await runInStore(storeName, 'readwrite', (store, tx) => new Promise((resolve) => {
    try {
      const req = store.put({ key, value, ts: Date.now(), ttl: ttlMs })
      req.onsuccess = () => resolve(true)
      req.onerror = () => { tx.abort(); resolve(null) }
    } catch { resolve(null) }
  }))
  if (result === null) {
    try { localStorage.setItem(`${storeName}:${key}`, JSON.stringify({ value, ts: Date.now() })) } catch { /* storage unavailable */ }
  }
}

export async function cacheGet(storeName, key, ttlMs = 3600000) {
  const result = await runInStore(storeName, 'readonly', (store) => new Promise((resolve) => {
    try {
      const req = store.get(key)
      req.onsuccess = () => {
        const r = req.result
        if (!r) return resolve(null)
        if (Date.now() - r.ts > (r.ttl ?? ttlMs)) return resolve(null)
        resolve(r.value)
      }
      req.onerror = () => resolve(null)
    } catch { resolve(null) }
  }))
  if (result !== null) return result

  try {
    const raw = localStorage.getItem(`${storeName}:${key}`)
    if (!raw) return null
    const { value, ts } = JSON.parse(raw)
    if (Date.now() - ts > ttlMs) return null
    return value
  } catch { return null }
}

export async function cacheDelete(storeName, key) {
  await runInStore(storeName, 'readwrite', (store) => new Promise((resolve) => {
    try {
      const req = store.delete(key)
      req.onsuccess = () => resolve(true)
      req.onerror = () => resolve(null)
    } catch { resolve(null) }
  }))
  try { localStorage.removeItem(`${storeName}:${key}`) } catch { /* storage unavailable */ }
}

export async function cacheClear(storeName) {
  await runInStore(storeName, 'readwrite', (store) => new Promise((resolve) => {
    try {
      const req = store.clear()
      req.onsuccess = () => resolve(true)
      req.onerror = () => resolve(null)
    } catch { resolve(null) }
  }))
}

export async function cacheKeys(storeName) {
  const result = await runInStore(storeName, 'readonly', (store) => new Promise((resolve) => {
    try {
      const req = store.getAllKeys()
      req.onsuccess = () => resolve(req.result || [])
      req.onerror = () => resolve(null)
    } catch { resolve(null) }
  }))
  return result || []
}

export async function getAllCached(storeName) {
  const result = await runInStore(storeName, 'readonly', (store) => new Promise((resolve) => {
    try {
      const req = store.getAll()
      req.onsuccess = () => {
        const now = Date.now()
        const items = (req.result || []).filter(r => now - r.ts <= (r.ttl ?? Infinity))
        resolve(items.map(r => r.value))
      }
      req.onerror = () => resolve(null)
    } catch { resolve(null) }
  }))
  return result || []
}

export const CACHE_TTL = {
  cve: 24 * 60 * 60 * 1000,
  epss: 6 * 60 * 60 * 1000,
  kev: 12 * 60 * 60 * 1000,
  exploits: 12 * 60 * 60 * 1000,
  enrichments: 6 * 60 * 60 * 1000,
  assets: Infinity,
  remediation: Infinity,
  alerts: 30 * 24 * 60 * 60 * 1000,
  audit: Infinity,
  searchHistory: 30 * 24 * 60 * 60 * 1000,
}

export { STORES }
