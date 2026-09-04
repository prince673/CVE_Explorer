import { useState, useEffect } from 'react'
import { getDashboardAnalytics } from '../services/api'

export default function AnalyticsDashboard() {
  const [analytics, setAnalytics] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    getDashboardAnalytics()
      .then(data => { if (!cancelled) setAnalytics(data) })
      .catch(() => { if (!cancelled) setAnalytics(null) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  if (loading) {
    return (
      <div className="space-y-5">
        <div className="flex items-center gap-2 mb-2">
          <span className="text-lg">📊</span>
          <h2 className="font-bold text-lg text-white">Security Analytics</h2>
        </div>
        <p className="text-sm text-gray-500 text-center py-8">Loading analytics...</p>
      </div>
    )
  }

  if (!analytics) return null

  const sevEntries = Object.entries(analytics.severityDistribution || {})
  const riskEntries = Object.entries(analytics.riskDistribution || {})

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-lg">📊</span>
        <h2 className="font-bold text-lg text-white">Security Analytics</h2>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="card text-center py-4">
          <div className="text-2xl font-extrabold text-accent-cyan">{analytics.totalSearches}</div>
          <div className="text-xs text-gray-500">Total Searches</div>
        </div>
        <div className="card text-center py-4">
          <div className="text-2xl font-extrabold text-accent-purple">{analytics.uniqueCVEs}</div>
          <div className="text-xs text-gray-500">Unique CVEs</div>
        </div>
        <div className="card text-center py-4">
          <div className="text-2xl font-extrabold text-amber-400">{analytics.avgRiskScore}</div>
          <div className="text-xs text-gray-500">Avg Risk Score</div>
        </div>
        <div className="card text-center py-4">
          <div className="text-2xl font-extrabold text-green-400">{analytics.searchesLast7d}</div>
          <div className="text-xs text-gray-500">Searches (7d)</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div className="card">
          <h3 className="font-bold text-sm text-white mb-3">Severity Distribution</h3>
          <div className="space-y-2">
            {sevEntries.map(([sev, count]) => {
              const total = analytics.totalSearches || 1
              const pct = Math.round((count / total) * 100)
              const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#10b981', unknown: '#6b7280' }
              return (
                <div key={sev} className="flex items-center gap-2">
                  <span className="text-xs text-gray-400 w-16 capitalize">{sev}</span>
                  <div className="flex-1 h-2 rounded-full bg-dark-bg overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: colors[sev] }} />
                  </div>
                  <span className="text-xs text-gray-500 w-10 text-right">{count}</span>
                </div>
              )
            })}
          </div>
        </div>

        <div className="card">
          <h3 className="font-bold text-sm text-white mb-3">Risk Distribution</h3>
          <div className="space-y-2">
            {riskEntries.map(([level, count]) => {
              const total = analytics.totalSearches || 1
              const pct = Math.round((count / total) * 100)
              const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#10b981' }
              return (
                <div key={level} className="flex items-center gap-2">
                  <span className="text-xs text-gray-400 w-16 capitalize">{level}</span>
                  <div className="flex-1 h-2 rounded-full bg-dark-bg overflow-hidden">
                    <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: colors[level] }} />
                  </div>
                  <span className="text-xs text-gray-500 w-10 text-right">{count}</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
