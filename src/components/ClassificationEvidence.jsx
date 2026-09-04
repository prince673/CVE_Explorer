export default function ClassificationEvidence({ classification }) {
  if (!classification) return null

  return (
    <div className="card mb-5">
      <div className="flex items-center gap-2 mb-3">
        <span className="text-lg">🔍</span>
        <h3 className="font-bold text-base text-white">Classification Analysis</h3>
      </div>

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="text-xs font-bold text-gray-300">Primary:</span>
        <span className="text-xs bg-accent-cyan/15 text-accent-cyan px-2 py-0.5 rounded-full border border-accent-cyan/40">
          {classification.primaryLabel}
        </span>
        <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${
          classification.confidence >= 80
            ? 'text-green-400 bg-green-500/15 border-green-500/40'
            : classification.confidence >= 50
              ? 'text-yellow-400 bg-yellow-500/15 border-yellow-500/40'
              : classification.confidence >= 30
                ? 'text-orange-400 bg-orange-500/15 border-orange-500/40'
                : 'text-red-400 bg-red-500/15 border-red-500/40'
        }`}>
          {classification.confidence}% confidence
        </span>
      </div>

      {classification.secondary.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 mb-3">
          <span className="text-xs text-gray-500">Secondary:</span>
          {classification.secondary.map((s, i) => (
            <span key={i} className="text-[10px] bg-dark-bg border border-dark-border text-gray-400 px-2 py-0.5 rounded-full">
              {s.label}
            </span>
          ))}
        </div>
      )}

      <div className="border-l-4 border-accent-purple bg-accent-purple/5 rounded-r-lg px-4 py-2 mb-3 text-xs text-gray-400">
        {classification.isGeneric
          ? '⚠ No specific vulnerability type could be confidently classified. Showing general educational information.'
          : `Classified with ${classification.confidenceLabel.toLowerCase()} confidence based on ${classification.evidence.length} evidence signals.`
        }
      </div>

      {classification.evidence.length > 0 && (
        <div>
          <p className="text-xs font-bold text-gray-500 mb-2">Evidence Chain:</p>
          <div className="space-y-1">
            {classification.evidence.map((e, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span className="text-green-400 mt-0.5 shrink-0">✓</span>
                <span className="text-gray-400">{e}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
