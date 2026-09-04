import { describe, it, expect, beforeEach } from 'vitest'
import {
  createRemediation, updateRemediation, getRemediationForCVE,
  getRemediationStats, getNextStatus, STATUSES, _resetForTest,
} from '../src/utils/remediation'

const store = {}
const localStorage = {
  getItem: (k) => store[k] ?? null,
  setItem: (k, v) => { store[k] = String(v) },
  removeItem: (k) => { delete store[k] },
  clear: () => { Object.keys(store).forEach(k => delete store[k]) },
}
globalThis.localStorage = localStorage

beforeEach(() => {
  localStorage.clear()
  _resetForTest()
})

describe('Remediation Tracker', () => {
  describe('createRemediation', () => {
    it('creates a remediation record', () => {
      const record = createRemediation('CVE-2021-44228', {
        assignedTo: 'Security Team',
        priority: 'p1_critical',
      })
      expect(record).toHaveProperty('id')
      expect(record.cveId).toBe('CVE-2021-44228')
      expect(record.status).toBe('open')
      expect(record.assignedTo).toBe('Security Team')
      expect(record.priority).toBe('p1_critical')
      expect(record.history.length).toBe(1)
      expect(record.history[0].action).toBe('created')
    })

    it('generates unique IDs', () => {
      const r1 = createRemediation('CVE-2021-44228')
      const r2 = createRemediation('CVE-2021-44228')
      expect(r1.id).not.toBe(r2.id)
    })
  })

  describe('updateRemediation', () => {
    it('updates status and records history', () => {
      const record = createRemediation('CVE-2021-44228')
      const updated = updateRemediation(record.id, { status: 'assigned', assignedTo: 'Alice' })
      expect(updated.status).toBe('assigned')
      expect(updated.assignedTo).toBe('Alice')
      expect(updated.history.length).toBe(2)
      expect(updated.history[1].action).toBe('updated')
    })

    it('returns null for non-existent record', () => {
      const result = updateRemediation('non-existent', { status: 'fixed' })
      expect(result).toBeNull()
    })
  })

  describe('getRemediationForCVE', () => {
    it('returns records for specific CVE', () => {
      createRemediation('CVE-2021-44228')
      createRemediation('CVE-2021-44228')
      createRemediation('CVE-2017-0144')
      const records = getRemediationForCVE('CVE-2021-44228')
      expect(records.length).toBe(2)
    })
  })

  describe('getRemediationStats', () => {
    it('computes statistics', () => {
      const r1 = createRemediation('CVE-2021-44228', { priority: 'p1_critical' })
      createRemediation('CVE-2017-0144', { priority: 'p2_high' })
      updateRemediation(r1.id, { status: 'verified' })

      const stats = getRemediationStats()
      expect(stats.total).toBe(2)
      expect(stats.closedCount).toBe(1)
      expect(stats.openCount).toBe(1)
    })
  })

  describe('getNextStatus', () => {
    it('returns next status in lifecycle', () => {
      expect(getNextStatus('open')).toBe('assigned')
      expect(getNextStatus('assigned')).toBe('in_progress')
      expect(getNextStatus('in_progress')).toBe('fixed')
      expect(getNextStatus('fixed')).toBe('verified')
      expect(getNextStatus('verified')).toBe('closed')
      expect(getNextStatus('closed')).toBeNull()
    })
  })
})
