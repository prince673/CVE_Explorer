import SeverityBadge from './SeverityBadge'

function FactorBar({ factor, maxScore = 25 }) {
  const pct = Math.min(100, (factor.score / maxScore) * 100)
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-400 w-36 shrink-0 truncate">{factor.factor}</span>
      <div className="flex-1 h-2 rounded-full bg-dark-bg overflow-hidden">
        <div className="h-full rounded-full bg-accent-cyan transition-all duration-500" style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-gray-500 w-12 text-right">{factor.score}</span>
    </div>
  )
}

export default function RiskScoreCard({ riskScore, exploitability, severityVsRisk }) {
  if (!riskScore) return null

  return (
    <div className="card mb-5 dark:bg-gradient-to-br dark:from-dark-bg3 dark:to-dark-card">
      <div className="flex flex-wrap items-start gap-6 mb-5">
        <div className="flex flex-col items-center">
          <div className="relative w-20 h-20">
            <svg className="w-20 h-20 -rotate-90" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r="34" fill="none" stroke="#1a2035" strokeWidth="6" />
              <circle
                cx="40" cy="40" r="34" fill="none"
                stroke={riskScore.color}
                strokeWidth="6"
                strokeDasharray={`${(riskScore.score / 100) * 213.6} 213.6`}
                strokeLinecap="round"
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-xl font-extrabold" style={{ color: riskScore.color }}>
                {riskScore.score}
              </span>
            </div>
          </div>
          <span className="text-xs font-bold mt-1" style={{ color: riskScore.color }}>
            {riskScore.level}
          </span>
          <span className="text-[10px] text-gray-600">RISK SCORE</span>
        </div>

        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center gap-3 mb-3">
            <SeverityBadge score={severityVsRisk?.cvssScore || 0} />
            {exploitability && (
              <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${
                exploitability.level === 'HIGH'
                  ? 'text-red-400 bg-red-500/15 border-red-500/40'
                  : exploitability.level === 'MODERATE'
                    ? 'text-yellow-400 bg-yellow-500/15 border-yellow-500/40'
                    : 'text-green-400 bg-green-500/15 border-green-500/40'
              }`}>
                Exploitability: {exploitability.level}
              </span>
            )}
          </div>
          {riskScore.topFactors.slice(0, 5).map((f, i) => (
            <FactorBar key={i} factor={f} />
          ))}
        </div>
      </div>

      {severityVsRisk && (
        <div className={`rounded-lg px-4 py-3 text-sm ${
          severityVsRisk.hasDivergence
            ? 'border-l-4 border-yellow-500 bg-yellow-500/10 text-yellow-200/80'
            : 'border-l-4 border-accent-cyan bg-accent-cyan/10 text-gray-300'
        }`}>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-bold text-white">Severity vs Risk Analysis</span>
            {severityVsRisk.hasDivergence && (
              <span className="text-xs bg-yellow-500/20 text-yellow-300 px-2 py-0.5 rounded-full">
                Divergence: {severityVsRisk.divergence}
              </span>
            )}
          </div>
          <p className="text-xs leading-relaxed">{severityVsRisk.interpretation}</p>
          <p className="text-xs font-semibold mt-1 text-white">{severityVsRisk.recommendation}</p>
        </div>
      )}
    </div>
  )
}
