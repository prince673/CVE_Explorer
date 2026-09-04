import { describe, it, expect } from 'vitest'
import { calculateRiskScore, calculateExploitability, distinguishSeverityVsRisk } from '../src/utils/riskScoring'

describe('Risk Scoring Engine', () => {
  describe('calculateRiskScore', () => {
    it('returns a score between 0 and 100', () => {
      const result = calculateRiskScore({ cvss3: 9.8, cwes: ['CWE-89'], desc: 'test' })
      expect(result.score).toBeGreaterThanOrEqual(0)
      expect(result.score).toBeLessThanOrEqual(100)
    })

    it('gives higher score for critical CVSS', () => {
      const critical = calculateRiskScore({ cvss3: 9.8, cwes: [], desc: '' })
      const low = calculateRiskScore({ cvss3: 2.0, cwes: [], desc: '' })
      expect(critical.score).toBeGreaterThan(low.score)
    })

    it('gives higher score for KEV-listed CVEs', () => {
      const withKEV = calculateRiskScore(
        { cvss3: 7.5, cwes: [], desc: '' },
        { kev: { inCatalog: true, dateAdded: '2024-01-01' } }
      )
      const withoutKEV = calculateRiskScore(
        { cvss3: 7.5, cwes: [], desc: '' },
        { kev: { inCatalog: false } }
      )
      expect(withKEV.score).toBeGreaterThan(withoutKEV.score)
    })

    it('gives higher score for high EPSS', () => {
      const highEPSS = calculateRiskScore(
        { cvss3: 7.0, cwes: [], desc: '' },
        { epss: { probability: 0.8 } }
      )
      const lowEPSS = calculateRiskScore(
        { cvss3: 7.0, cwes: [], desc: '' },
        { epss: { probability: 0.05 } }
      )
      expect(highEPSS.score).toBeGreaterThan(lowEPSS.score)
    })

    it('gives higher score when exploits are available', () => {
      const withExploit = calculateRiskScore(
        { cvss3: 7.0, cwes: [], desc: '' },
        { hasExploit: true }
      )
      const withoutExploit = calculateRiskScore(
        { cvss3: 7.0, cwes: [], desc: '' },
        { hasExploit: false }
      )
      expect(withExploit.score).toBeGreaterThan(withoutExploit.score)
    })

    it('provides top factors with evidence', () => {
      const result = calculateRiskScore({ cvss3: 9.8, cwes: ['CWE-89'], desc: 'SQL injection' })
      expect(result.topFactors.length).toBeGreaterThan(0)
      expect(result.topFactors[0]).toHaveProperty('factor')
      expect(result.topFactors[0]).toHaveProperty('evidence')
    })

    it('assigns correct risk levels', () => {
      const critical = calculateRiskScore(
        { cvss3: 9.8, cwes: ['CWE-89'], desc: 'SQL injection in production' },
        { kev: { inCatalog: true }, epss: { probability: 0.9 }, hasExploit: true }
      )
      expect(['Critical', 'High']).toContain(critical.level)
    })

    it('gives higher score for popular products', () => {
      const popular = calculateRiskScore({ cvss3: 7.0, cwes: [], desc: '', products: ['Apache'] })
      const niche = calculateRiskScore({ cvss3: 7.0, cwes: [], desc: '', products: ['ObscureApp'] })
      expect(popular.score).toBeGreaterThanOrEqual(niche.score)
    })
  })

  describe('calculateExploitability', () => {
    it('returns HIGH for critical CVE with KEV and exploits', () => {
      const result = calculateExploitability(
        { cvss3: 9.8, cwes: [] },
        { kev: { inCatalog: true }, hasExploit: true, epss: { probability: 0.8 } }
      )
      expect(result.level).toBe('HIGH')
      expect(result.score).toBeGreaterThanOrEqual(70)
    })

    it('returns LOW for low CVSS without exploitation signals', () => {
      const result = calculateExploitability(
        { cvss3: 3.0, cwes: [] },
        { kev: { inCatalog: false }, hasExploit: false }
      )
      expect(result.level).toBe('LOW')
    })

    it('provides factor breakdown', () => {
      const result = calculateExploitability(
        { cvss3: 9.0, cwes: [] },
        { kev: { inCatalog: true } }
      )
      expect(result.factors.length).toBeGreaterThan(0)
      expect(result.factors[0]).toHaveProperty('factor')
      expect(result.factors[0]).toHaveProperty('detail')
    })
  })

  describe('distinguishSeverityVsRisk', () => {
    it('detects divergence when risk exceeds severity', () => {
      const risk = { score: 85, level: 'Critical' }
      const exploit = { score: 80, level: 'HIGH' }
      const svr = distinguishSeverityVsRisk(
        { cvss3: 5.0 },
        risk, exploit,
        { kev: { inCatalog: true } }
      )
      expect(svr.hasDivergence).toBe(true)
      expect(svr.interpretation).toContain('exceeds')
    })

    it('provides recommendation based on risk', () => {
      const risk = { score: 85, level: 'Critical' }
      const exploit = { score: 80, level: 'HIGH' }
      const svr = distinguishSeverityVsRisk(
        { cvss3: 9.0 },
        risk, exploit,
        {}
      )
      expect(svr.recommendation).toBeDefined()
      expect(typeof svr.recommendation).toBe('string')
    })
  })
})
