import { useState, useCallback, useEffect } from 'react'
import {
  getRemediationForCVE, createRemediation, updateRemediation,
} from '../services/api'

const STATUSES = ['open', 'assigned', 'in_progress', 'fixed', 'verified', 'closed']
const PRIORITIES = ['p1_critical', 'p2_high', 'p3_medium', 'p4_low']

const STATUS_LABELS = {
  open: 'Open', assigned: 'Assigned', in_progress: 'In Progress',
  fixed: 'Fixed', verified: 'Verified', closed: 'Closed',
}

const STATUS_COLORS = {
  open: 'bg-gray-500/15 text-gray-400 border-gray-600',
  assigned: 'bg-blue-500/15 text-blue-400 border-blue-500/40',
  in_progress: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/40',
  fixed: 'bg-green-500/15 text-green-400 border-green-500/40',
  verified: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  closed: 'bg-gray-700/40 text-gray-500 border-gray-600',
}

const PRIORITY_LABELS = {
  p1_critical: 'P1 Critical', p2_high: 'P2 High', p3_medium: 'P3 Medium', p4_low: 'P4 Low',
}

export default function RemediationTracker({ cveId }) {
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ assignedTo: '', priority: 'p3_medium', notes: '' })
  const [records, setRecords] = useState([])
  const [tick, setTick] = useState(0)
  const bump = useCallback(() => setTick(t => t + 1), [])

  useEffect(() => {
    if (!cveId) return
    let cancelled = false
    getRemediationForCVE(cveId)
      .then(data => { if (!cancelled) setRecords(data ?? []) })
      .catch(() => { if (!cancelled) setRecords([]) })
    return () => { cancelled = true }
  }, [cveId, tick])

  async function handleCreate() {
    await createRemediation({
      cve_id: cveId,
      assigned_to: form.assignedTo,
      priority: form.priority,
      notes: form.notes,
    })
    setShowForm(false)
    setForm({ assignedTo: '', priority: 'p3_medium', notes: '' })
    bump()
  }

  async function handleAdvance(id) {
    const rec = records.find(r => r.id === id)
    if (!rec) return
    const nextStatus = STATUSES[STATUSES.indexOf(rec.status) + 1]
    if (nextStatus) {
      await updateRemediation(id, { status: nextStatus })
      bump()
    }
  }

  return (
    <div className="card mb-5">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-lg">🔧</span>
        <h3 className="font-bold text-base text-white">Remediation Tracking</h3>
        <button
          onClick={() => setShowForm(!showForm)}
          className="ml-auto text-xs text-accent-cyan hover:underline"
        >
          {showForm ? 'Cancel' : '+ Add Record'}
        </button>
      </div>

      {showForm && (
        <div className="bg-dark-bg/60 border border-dark-border rounded-lg p-4 mb-4 space-y-3">
          <input
            type="text"
            placeholder="Assigned to (name/team)"
            className="input-field text-sm"
            value={form.assignedTo}
            onChange={e => setForm(f => ({ ...f, assignedTo: e.target.value }))}
          />
          <select
            className="input-field text-sm"
            value={form.priority}
            onChange={e => setForm(f => ({ ...f, priority: e.target.value }))}
          >
            {PRIORITIES.map(p => (
              <option key={p} value={p}>{PRIORITY_LABELS[p]}</option>
            ))}
          </select>
          <textarea
            placeholder="Notes"
            className="input-field text-sm h-16 resize-none"
            value={form.notes}
            onChange={e => setForm(f => ({ ...f, notes: e.target.value }))}
          />
          <button onClick={handleCreate} className="btn-primary text-sm w-full">Create Record</button>
        </div>
      )}

      {records.length === 0 ? (
        <p className="text-sm text-gray-500">No remediation records for this CVE.</p>
      ) : (
        <div className="space-y-3">
          {records.map(rec => (
            <div key={rec.id} className="bg-dark-bg/50 border border-dark-border/50 rounded-lg p-3">
              <div className="flex flex-wrap items-center gap-2 mb-2">
                <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${STATUS_COLORS[rec.status]}`}>
                  {STATUS_LABELS[rec.status]}
                </span>
                <span className="text-xs text-gray-500">{PRIORITY_LABELS[rec.priority]}</span>
                {rec.assigned_to && <span className="text-xs text-gray-400">→ {rec.assigned_to}</span>}
              </div>
              {rec.notes && <p className="text-xs text-gray-500 mb-2">{rec.notes}</p>}
              {rec.history?.length > 0 && (
                <div className="text-[10px] text-gray-600 space-y-0.5">
                  {rec.history.slice(-3).map((h, i) => (
                    <div key={i}>{h.action} — {new Date(h.timestamp).toLocaleString()}</div>
                  ))}
                </div>
              )}
              {rec.status !== 'closed' && rec.status !== 'verified' && (
                <button
                  onClick={() => handleAdvance(rec.id)}
                  className="mt-2 text-xs text-accent-cyan hover:underline"
                >
                  Advance → {STATUS_LABELS[STATUSES[STATUSES.indexOf(rec.status) + 1]] || 'Done'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
