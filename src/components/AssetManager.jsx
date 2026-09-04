import { useState, useCallback, useEffect } from 'react'
import { listAssets, createAsset, deleteAsset, getAssetSummary } from '../services/api'

const CRITICITY_COLORS = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

const ENV_COLORS = {
  production: 'bg-red-500/15 text-red-400 border-red-500/40',
  staging: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  development: 'bg-blue-500/15 text-blue-400 border-blue-500/40',
  test: 'bg-purple-500/15 text-purple-400 border-purple-500/40',
}

export default function AssetManager() {
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    name: '', type: 'server', hostname: '', environment: 'production',
    internetFacing: false, criticality: 'medium', owner: '',
    softwareName: '', softwareVersion: '',
  })
  const [assets, setAssets] = useState([])
  const [summary, setSummary] = useState(null)
  const [tick, setTick] = useState(0)
  const bump = useCallback(() => setTick(t => t + 1), [])

  useEffect(() => {
    Promise.all([listAssets(), getAssetSummary()])
      .then(([a, s]) => { setAssets(a ?? []); setSummary(s ?? null) })
      .catch(() => { setAssets([]); setSummary(null) })
  }, [tick])

  async function handleAdd() {
    await createAsset({
      name: form.name,
      type: form.type,
      hostname: form.hostname,
      environment: form.environment,
      internetFacing: form.internetFacing,
      criticality: form.criticality,
      owner: form.owner,
      software: form.softwareName ? [{ name: form.softwareName, version: form.softwareVersion }] : [],
    })
    setForm({
      name: '', type: 'server', hostname: '', environment: 'production',
      internetFacing: false, criticality: 'medium', owner: '',
      softwareName: '', softwareVersion: '',
    })
    setShowForm(false)
    bump()
  }

  async function handleDelete(id) {
    await deleteAsset(id)
    bump()
  }

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-lg">🏗️</span>
        <h3 className="font-bold text-base text-white">Asset Inventory</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="ml-auto text-xs text-accent-cyan hover:underline"
        >
          {showForm ? 'Cancel' : '+ Add Asset'}
        </button>
      </div>

      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">
          <div className="bg-dark-bg/60 rounded-lg p-2 text-center">
            <div className="text-lg font-bold text-accent-cyan">{summary.total}</div>
            <div className="text-[10px] text-gray-500">Total Assets</div>
          </div>
          <div className="bg-dark-bg/60 rounded-lg p-2 text-center">
            <div className="text-lg font-bold text-red-400">{summary.internetFacing}</div>
            <div className="text-[10px] text-gray-500">Internet Facing</div>
          </div>
          <div className="bg-dark-bg/60 rounded-lg p-2 text-center">
            <div className="text-lg font-bold text-accent-purple">{summary.totalSoftware}</div>
            <div className="text-[10px] text-gray-500">Software Items</div>
          </div>
          <div className="bg-dark-bg/60 rounded-lg p-2 text-center">
            <div className="text-lg font-bold text-orange-400">{summary.eolSoftware}</div>
            <div className="text-[10px] text-gray-500">EOL Software</div>
          </div>
        </div>
      )}

      {showForm && (
        <div className="bg-dark-bg/60 border border-dark-border rounded-lg p-4 mb-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <input placeholder="Asset name" className="input-field text-sm" value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
            <select className="input-field text-sm" value={form.type}
              onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>
              <option value="server">Server</option>
              <option value="workstation">Workstation</option>
              <option value="network">Network Device</option>
              <option value="container">Container</option>
              <option value="cloud">Cloud Service</option>
              <option value="dependency">Dependency</option>
            </select>
            <input placeholder="Hostname / IP" className="input-field text-sm" value={form.hostname}
              onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))} />
            <select className="input-field text-sm" value={form.environment}
              onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="test">Test</option>
            </select>
            <input placeholder="Software name" className="input-field text-sm" value={form.softwareName}
              onChange={e => setForm(f => ({ ...f, softwareName: e.target.value }))} />
            <input placeholder="Software version" className="input-field text-sm" value={form.softwareVersion}
              onChange={e => setForm(f => ({ ...f, softwareVersion: e.target.value }))} />
          </div>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2 text-xs text-gray-400">
              <input type="checkbox" checked={form.internetFacing}
                onChange={e => setForm(f => ({ ...f, internetFacing: e.target.checked }))}
                className="accent-accent-cyan" />
              Internet Facing
            </label>
            <select className="input-field text-sm flex-1" value={form.criticality}
              onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <input placeholder="Owner" className="input-field text-sm flex-1" value={form.owner}
              onChange={e => setForm(f => ({ ...f, owner: e.target.value }))} />
          </div>
          <button onClick={handleAdd} disabled={!form.name} className="btn-primary text-sm w-full">
            Add Asset
          </button>
        </div>
      )}

      {assets.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-4">No assets. Add assets to enable CVE-to-asset correlation.</p>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {assets.map(asset => (
            <div key={asset.id} className="bg-dark-bg/50 border border-dark-border/50 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-sm font-semibold text-gray-200">{asset.name}</span>
                <span className={`text-[10px] font-bold uppercase ${CRITICITY_COLORS[asset.criticality]}`}>
                  {asset.criticality}
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded-full border ${ENV_COLORS[asset.environment] || ''}`}>
                  {asset.environment}
                </span>
                {asset.internetFacing && (
                  <span className="text-[10px] bg-red-500/15 text-red-400 px-2 py-0.5 rounded-full border border-red-500/40">
                    🌐 Internet
                  </span>
                )}
                <button onClick={() => handleDelete(asset.id)} className="ml-auto text-[10px] text-gray-600 hover:text-red-400">
                  Delete
                </button>
              </div>
              {asset.software?.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {asset.software.map((sw, i) => (
                    <span key={i} className="text-[10px] font-mono text-gray-500 bg-dark-bg border border-dark-border/50 rounded px-1.5 py-0.5">
                      {sw.name} {sw.version && `v${sw.version}`}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
