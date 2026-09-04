import { describe, it, expect, beforeEach } from 'vitest'
import { getLifecycle, transitionLifecycle, buildTimeline, getLifecycleProgress, LIFECYCLE_STATES, _resetForTest } from '../src/utils/lifecycle'

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

describe('Lifecycle Tracker', () => {
  describe('getLifecycle', () => {
    it('creates default lifecycle for new CVE', () => {
      const lifecycle = getLifecycle('CVE-2021-44228')
      expect(lifecycle.cveId).toBe('CVE-2021-44228')
      expect(lifecycle.currentState).toBe('published')
    })
  })

  describe('transitionLifecycle', () => {
    it('transitions between states', () => {
      transitionLifecycle('CVE-2021-44228', 'analyzed', 'Security team reviewed')
      const lifecycle = getLifecycle('CVE-2021-44228')
      expect(lifecycle.currentState).toBe('analyzed')
      expect(lifecycle.transitions.length).toBe(1)
      expect(lifecycle.transitions[0].detail).toBe('Security team reviewed')
    })

    it('returns null for invalid state', () => {
      const result = transitionLifecycle('CVE-2021-44228', 'invalid_state')
      expect(result).toBeNull()
    })

    it('tracks full lifecycle', () => {
      transitionLifecycle('CVE-2021-44228', 'analyzed')
      transitionLifecycle('CVE-2021-44228', 'exploit_appeared')
      transitionLifecycle('CVE-2021-44228', 'patch_available')
      transitionLifecycle('CVE-2021-44228', 'patch_deployed')
      transitionLifecycle('CVE-2021-44228', 'verified')
      transitionLifecycle('CVE-2021-44228', 'closed')

      const lifecycle = getLifecycle('CVE-2021-44228')
      expect(lifecycle.currentState).toBe('closed')
      expect(lifecycle.transitions.length).toBe(6)
    })
  })

  describe('buildTimeline', () => {
    it('builds timeline from CVE data', () => {
      const events = buildTimeline({
        id: 'CVE-2021-44228',
        pub: '2021-12-10T00:00:00',
        mod: '2021-12-15T00:00:00',
        desc: 'Log4Shell',
      }, {
        kev: { inCatalog: true, dateAdded: '2021-12-10', dueDate: '2021-12-24' },
        hasExploit: true,
      })
      expect(events.length).toBeGreaterThanOrEqual(4)
      expect(events.some(e => e.type === 'published')).toBe(true)
      expect(events.some(e => e.type === 'kev')).toBe(true)
      expect(events.some(e => e.type === 'exploit')).toBe(true)
    })

    it('sorts events chronologically', () => {
      const events = buildTimeline({
        id: 'CVE-2021-44228',
        pub: '2021-12-10T00:00:00',
        mod: '2021-12-15T00:00:00',
      }, {})
      for (let i = 1; i < events.length; i++) {
        expect(new Date(events[i].date).getTime()).toBeGreaterThanOrEqual(
          new Date(events[i - 1].date).getTime()
        )
      }
    })
  })

  describe('getLifecycleProgress', () => {
    it('calculates progress percentage', () => {
      transitionLifecycle('CVE-2021-44228', 'exploit_appeared')
      const progress = getLifecycleProgress('CVE-2021-44228')
      expect(progress.current).toBe('exploit_appeared')
      expect(progress.progress).toBeGreaterThan(0)
      expect(progress.progress).toBeLessThanOrEqual(100)
    })
  })
})
