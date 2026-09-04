import { findAffectedAssets } from '../utils/assetStore'

const CRITICITY_COLORS = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-green-400',
}

export default function AffectedAssetsPanel({ cveData }) {
  if (!cveData) return null

  const affected = findAffectedAssets(cveData)

  if (affected.length === 0) return null

  return (
    <div className="card mb-5 border-l-4 border-red-500">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-lg">🎯</span>
        <h3 className="font-bold text-base text-white">Affected Assets</h3>
        <span className="text-xs bg-red-500/15 text-red-400 px-2 py-0.5 rounded-full border border-red-500/40">
          {affected.length} affected
        </span>
      </div>

      <div className="space-y-2">
        {affected.map(({ asset, software, matchReason }, i) => (
          <div key={i} className="bg-dark-bg/50 border border-dark-border/50 rounded-lg p-3">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-sm font-semibold text-gray-200">{asset.name}</span>
              <span className={`text-[10px] font-bold uppercase ${CRITICITY_COLORS[asset.criticality]}`}>
                {asset.criticality}
              </span>
              {asset.internetFacing && (
                <span className="text-[10px] bg-red-500/15 text-red-400 px-2 py-0.5 rounded-full border border-red-500/40">
                  🌐 Internet Facing
                </span>
              )}
              <span className="text-[10px] text-gray-500">{asset.environment}</span>
            </div>
            <p className="text-xs text-gray-500">{matchReason}</p>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-[10px] font-mono text-accent-cyan">{software.name}</span>
              {software.version && <span className="text-[10px] text-gray-600">v{software.version}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
