/**
 * Asset management store - localStorage-backed inventory of organization's
 * software, versions, and environments. Enables CVE-to-asset correlation.
 */

let assets = []
let listeners = []

function loadAssets() {
  try {
    const raw = localStorage.getItem('cve_explorer_assets')
    assets = raw ? JSON.parse(raw) : []
  } catch { assets = [] }
}

function saveAssets() {
  try {
    localStorage.setItem('cve_explorer_assets', JSON.stringify(assets))
  } catch { /* storage unavailable */ }
  listeners.forEach(fn => fn([...assets]))
}

export function onAssetsChange(fn) {
  listeners.push(fn)
  return () => { listeners = listeners.filter(f => f !== fn) }
}

export function getAssets() {
  if (!assets.length) loadAssets()
  return [...assets]
}

export function addAsset(asset) {
  const newAsset = {
    id: `asset-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: asset.name || 'Unnamed Asset',
    type: asset.type || 'server',
    hostname: asset.hostname || '',
    ipAddress: asset.ipAddress || '',
    environment: asset.environment || 'production',
    internetFacing: asset.internetFacing || false,
    criticality: asset.criticality || 'medium',
    owner: asset.owner || '',
    software: (asset.software || []).map(s => ({
      name: s.name || '',
      version: s.version || '',
      cpe: s.cpe || '',
      endOfLife: s.endOfLife || false,
      eolDate: s.eolDate || null,
    })),
    tags: asset.tags || [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  assets.push(newAsset)
  saveAssets()
  return newAsset
}

export function updateAsset(id, updates) {
  const idx = assets.findIndex(a => a.id === id)
  if (idx === -1) return null
  assets[idx] = { ...assets[idx], ...updates, updatedAt: new Date().toISOString() }
  saveAssets()
  return assets[idx]
}

export function deleteAsset(id) {
  assets = assets.filter(a => a.id !== id)
  saveAssets()
}

export function findAffectedAssets(cveData) {
  if (!assets.length) loadAssets()
  const affected = []
  const desc = (cveData.desc || '').toLowerCase()
  const products = (cveData.products || []).map(p => p.toLowerCase())

  for (const asset of assets) {
    for (const sw of asset.software) {
      const swName = sw.name.toLowerCase()
      const isMatch = products.some(p => p.includes(swName) || swName.includes(p)) ||
        desc.includes(swName)
      if (isMatch) {
        affected.push({
          asset,
          software: sw,
          matchReason: `Software "${sw.name}" ${sw.version ? `v${sw.version}` : ''} matches affected product in CVE.`,
        })
      }
    }
  }

  return affected.sort((a, b) => {
    const critOrder = { critical: 0, high: 1, medium: 2, low: 3 }
    return (critOrder[a.asset.criticality] ?? 2) - (critOrder[b.asset.criticality] ?? 2)
  })
}

export function getAssetSummary() {
  if (!assets.length) loadAssets()
  const total = assets.length
  const internetFacing = assets.filter(a => a.internetFacing).length
  const byEnvironment = {}
  const byCriticality = {}
  const byType = {}
  let totalSoftware = 0
  let eolSoftware = 0

  for (const asset of assets) {
    byEnvironment[asset.environment] = (byEnvironment[asset.environment] || 0) + 1
    byCriticality[asset.criticality] = (byCriticality[asset.criticality] || 0) + 1
    byType[asset.type] = (byType[asset.type] || 0) + 1
    totalSoftware += asset.software.length
    eolSoftware += asset.software.filter(s => s.endOfLife).length
  }

  return { total, internetFacing, byEnvironment, byCriticality, byType, totalSoftware, eolSoftware }
}

export function importAssetsFromSBOM(sbomData) {
  const imported = []
  for (const pkg of sbomData) {
    const existing = assets.find(a =>
      a.software.some(s => s.name.toLowerCase() === pkg.name.toLowerCase() && s.version === pkg.version)
    )
    if (!existing) {
      const asset = addAsset({
        name: `SBOM: ${pkg.name}`,
        type: 'dependency',
        software: [{ name: pkg.name, version: pkg.version, cpe: pkg.cpe || '' }],
        tags: ['sbom-import'],
      })
      imported.push(asset)
    }
  }
  return imported
}
