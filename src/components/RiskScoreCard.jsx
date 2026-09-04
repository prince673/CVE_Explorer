const PRIORITY_STYLES = {
  P1: { bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/40', ring: '#ef4444' },
  P2: { bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/40', ring: '#f97316' },
  P3: { bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/40', ring: '#eab308' },
  P4: { bg: 'bg-green-500/15', text: 'text-green-400', border: 'border-green-500/40', ring: '#22c55e' },
}

function SignalBar({ signal }) {
  const pct = signal.max > 0 ? Math.min(100, (signal.value / signal.max) * 100) : 0
  const ratio = signal.max > 0 ? signal.value / signal.max : 0
  const barColor = ratio >= 0.7 ? '#ef4444' : ratio >= 0.4 ? '#f97316' : ratio >= 0.2 ? '#eab308' : '#22c55e'
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs text-gray-400 w-20 shrink-0 truncate">{signal.name.toUpperCase()}</span>
      <div className="flex-1 h-2 rounded-full bg-dark-bg overflow-hidden">
        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: barColor }} />
      </div>
      <span className="text-xs text-gray-500 w-12 text-right">{signal.value}/{signal.max}</span>
      <span className="text-[10px] text-gray-600 w-10 text-right shrink-0">{signal.weight}</span>
    </div>
  )
}

export default function RiskScoreCard({ risk }) {
  if (!risk) return null

  const pStyle = PRIORITY_STYLES[risk.priority] || PRIORITY_STYLES.P4
  const ringColor = pStyle.ring
  const circumference = 2 * Math.PI * 34

  return (
    <div className="card mb-5 dark:bg-gradient-to-br dark:from-dark-bg3 dark:to-dark-card">

      {/* Top: donut + priority + signals */}
      <div className="flex flex-wrap items-start gap-6 mb-5">

        {/* Risk donut */}
        <div className="flex flex-col items-center">
          <div className="relative w-24 h-24">
            <svg className="w-24 h-24 -rotate-90" viewBox="0 0 80 80">
              <circle cx="40" cy="40" r="34" fill="none" stroke="#1a2035" strokeWidth="6" />
              <circle
                cx="40" cy="40" r="34" fill="none"
                stroke={ringColor}
                strokeWidth="6"
                strokeDasharray={`${(risk.score / 100) * circumference} ${circumference}`}
                strokeLinecap="round"
                className="transition-all duration-700"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl font-extrabold" style={{ color: ringColor }}>{risk.score}</span>
              <span className="text-[10px] text-gray-500 -mt-0.5">/ 100</span>
            </div>
          </div>

          {/* Priority badge */}
          <span className={`mt-2 text-sm font-extrabold px-3 py-1 rounded-full border ${pStyle.bg} ${pStyle.text} ${pStyle.border}`}>
            {risk.priority}
          </span>
          <span className="text-[10px] text-gray-600 mt-0.5">{risk.level} RISK</span>
        </div>

        {/* Signals breakdown */}
        <div className="flex-1 min-w-0 space-y-2">
          <div className="text-xs font-bold uppercase tracking-widest text-gray-500 mb-1">
            Signal Breakdown
          </div>
          {risk.signals?.map((s, i) => (
            <SignalBar key={i} signal={s} />
          ))}
        </div>
      </div>

      {/* Reasons */}
      {risk.reasons?.length > 0 && (
        <div className="mb-4 p-4 bg-dark-bg/50 rounded-lg border border-dark-border/50">
          <div className="text-xs font-bold uppercase tracking-widest text-gray-500 mb-2">
            Why this priority?
          </div>
          <ul className="space-y-1.5">
            {risk.reasons.map((r, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-300">
                <span className="text-accent-cyan mt-0.5">•</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommendation */}
      {risk.recommendation && (
        <div className={`rounded-lg px-4 py-3 text-sm border-l-4 ${
          risk.priority === 'P1'
            ? 'border-red-500 bg-red-500/10 text-red-200/80'
            : risk.priority === 'P2'
              ? 'border-orange-500 bg-orange-500/10 text-orange-200/80'
              : 'border-accent-cyan bg-accent-cyan/10 text-gray-300'
        }`}>
          <span className="font-bold text-white">Recommendation: </span>
          {risk.recommendation}
        </div>
      )}
    </div>
  )
}
