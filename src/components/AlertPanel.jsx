import { useState, useCallback } from 'react'
import { getAlerts, markAlertRead, markAllRead, acknowledgeAlert, getUnreadCount } from '../utils/alerts'

const SEVERITY_COLORS = {
  critical: 'border-red-500/40 bg-red-500/8',
  high: 'border-orange-500/40 bg-orange-500/8',
  medium: 'border-yellow-500/40 bg-yellow-500/8',
  info: 'border-blue-500/40 bg-blue-500/8',
}

const SEVERITY_DOTS = {
  critical: 'bg-red-400',
  high: 'bg-orange-400',
  medium: 'bg-yellow-400',
  info: 'bg-blue-400',
}

export default function AlertPanel() {
  const [filter, setFilter] = useState('all')
  const [, setTick] = useState(0)

  const f = filter === 'unread' ? { unreadOnly: true } : filter !== 'all' ? { type: filter } : {}
  const alerts = getAlerts(f)
  const unread = getUnreadCount()

  const bump = useCallback(() => setTick(t => t + 1), [])

  function handleMarkRead(id) {
    markAlertRead(id)
    bump()
  }

  function handleAcknowledge(id) {
    acknowledgeAlert(id)
    bump()
  }

  function handleMarkAllRead() {
    markAllRead()
    bump()
  }

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-lg">🔔</span>
        <h3 className="font-bold text-base text-white">Alerts</h3>
        {unread > 0 && (
          <span className="bg-red-500 text-white text-[10px] font-bold px-2 py-0.5 rounded-full">
            {unread}
          </span>
        )}
        <button onClick={handleMarkAllRead} className="ml-auto text-xs text-gray-500 hover:text-gray-300">
          Mark all read
        </button>
      </div>

      <div className="flex gap-1 mb-4 overflow-x-auto pb-1">
        {[
          { key: 'all', label: 'All' },
          { key: 'unread', label: 'Unread' },
          { key: 'kev_update', label: 'KEV' },
          { key: 'epss_increase', label: 'EPSS' },
          { key: 'new_exploit', label: 'Exploits' },
        ].map(ff => (
          <button
            key={ff.key}
            onClick={() => setFilter(ff.key)}
            className={`text-xs px-3 py-1.5 rounded-full border transition-colors whitespace-nowrap ${
              filter === ff.key
                ? 'border-accent-cyan text-accent-cyan bg-accent-cyan/10'
                : 'border-dark-border text-gray-500 hover:text-gray-300'
            }`}
          >
            {ff.label}
          </button>
        ))}
      </div>

      {alerts.length === 0 ? (
        <p className="text-sm text-gray-500 text-center py-4">No alerts.</p>
      ) : (
        <div className="space-y-2 max-h-96 overflow-y-auto">
          {alerts.slice(0, 50).map(alert => (
            <div
              key={alert.id}
              className={`border rounded-lg p-3 ${SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.info} ${
                !alert.read ? 'ring-1 ring-accent-cyan/30' : ''
              }`}
            >
              <div className="flex items-start gap-2 mb-1">
                <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${SEVERITY_DOTS[alert.severity]}`} />
                <div className="flex-1 min-w-0">
                  <h4 className="text-sm font-semibold text-gray-200">{alert.title}</h4>
                  <p className="text-xs text-gray-400 mt-0.5">{alert.message}</p>
                  <div className="flex items-center gap-2 mt-2">
                    <span className="text-[10px] text-gray-600">{new Date(alert.createdAt).toLocaleString()}</span>
                    {alert.cveId && (
                      <span className="text-[10px] font-mono text-accent-cyan">{alert.cveId}</span>
                    )}
                  </div>
                </div>
                <div className="flex gap-1 shrink-0">
                  {!alert.read && (
                    <button onClick={() => handleMarkRead(alert.id)} className="text-[10px] text-gray-500 hover:text-gray-300">Read</button>
                  )}
                  {!alert.acknowledged && (
                    <button onClick={() => handleAcknowledge(alert.id)} className="text-[10px] text-accent-cyan hover:underline">Ack</button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
