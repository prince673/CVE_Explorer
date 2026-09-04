import { describe, it, expect } from 'vitest'
import { classifyVulnerability, buildGuide, selectGuideKey } from '../src/utils/guideEngine'

describe('Classification Engine', () => {
  describe('classifyVulnerability', () => {
    it('classifies SQL injection by CWE-89', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-89'],
        desc: 'A SQL injection vulnerability allows attackers to execute arbitrary SQL queries.',
      })
      expect(result.primary).toBe('sqli')
      expect(result.confidence).toBeGreaterThanOrEqual(70)
      expect(result.evidence.length).toBeGreaterThan(0)
      expect(result.isGeneric).toBe(false)
    })

    it('classifies XSS by CWE-79', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-79'],
        desc: 'Cross-site scripting vulnerability in the web application.',
      })
      expect(result.primary).toBe('xss')
      expect(result.confidence).toBeGreaterThanOrEqual(70)
    })

    it('classifies RCE by description keywords', () => {
      const result = classifyVulnerability({
        cwes: [],
        desc: 'Remote code execution vulnerability allows attackers to run arbitrary code on the server.',
      })
      expect(result.primary).toBe('rce')
      expect(result.confidence).toBeGreaterThanOrEqual(40)
    })

    it('classifies SSRF by CWE-918', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-918'],
        desc: 'Server-side request forgery allows internal network access.',
      })
      expect(result.primary).toBe('ssrf')
    })

    it('classifies XXE by CWE-611', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-611'],
        desc: 'XML external entity injection vulnerability.',
      })
      expect(result.primary).toBe('xxe')
    })

    it('classifies path traversal by CWE-22', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-22'],
        desc: 'Path traversal allows reading arbitrary files.',
      })
      expect(result.primary).toBe('traversal')
    })

    it('classifies deserialization by CWE-502', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-502'],
        desc: 'Insecure deserialization leads to remote code execution.',
      })
      expect(result.primary).toBe('deser')
    })

    it('classifies IDOR by CWE-284', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-284'],
        desc: 'Broken access control allows unauthorized object access.',
      })
      expect(result.primary).toBe('idor')
    })

    it('classifies JWT vulnerability by CWE-347', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-347'],
        desc: 'Improper verification of JWT token signature.',
      })
      expect(result.primary).toBe('jwt')
    })

    it('classifies CSRF by CWE-352', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-352'],
        desc: 'Cross-site request forgery vulnerability.',
      })
      expect(result.primary).toBe('csrf')
    })

    it('returns generic for unknown CWE', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-999'],
        desc: 'Some unknown vulnerability type.',
      })
      expect(result.isGeneric).toBe(true)
    })

    it('provides evidence chain', () => {
      const result = classifyVulnerability({
        cwes: ['CWE-89'],
        desc: 'SQL injection in login form allows UNION SELECT queries.',
        refs: [{ url: 'https://exploit-db.com/12345' }],
        products: ['MySQL'],
      })
      expect(result.evidence.length).toBeGreaterThanOrEqual(2)
      expect(result.evidence.some(e => e.includes('CWE'))).toBe(true)
    })

    it('increases confidence with multiple evidence sources', () => {
      const singleSource = classifyVulnerability({
        cwes: ['CWE-89'],
        desc: '',
      })
      const multiSource = classifyVulnerability({
        cwes: ['CWE-89'],
        desc: 'SQL injection allows arbitrary queries.',
        refs: [{ url: 'https://exploit-db.com/123' }],
      })
      expect(multiSource.confidence).toBeGreaterThanOrEqual(singleSource.confidence)
    })
  })

  describe('selectGuideKey', () => {
    it('selects correct guide key for SQLi', () => {
      const key = selectGuideKey({ cwes: ['CWE-89'], desc: '' })
      expect(key).toBe('sqli')
    })

    it('selects correct guide key for XSS', () => {
      const key = selectGuideKey({ cwes: ['CWE-79'], desc: '' })
      expect(key).toBe('xss')
    })

    it('falls back to keyword matching', () => {
      const key = selectGuideKey({ cwes: [], desc: 'cross-site scripting vulnerability' })
      expect(key).toBe('xss')
    })

    it('returns generic for unclassifiable', () => {
      const key = selectGuideKey({ cwes: [], desc: 'some random vulnerability' })
      expect(key).toBe('generic')
    })
  })

  describe('buildGuide', () => {
    it('builds a complete guide with classification', () => {
      const guide = buildGuide({
        id: 'CVE-2021-44228',
        cwes: ['CWE-94'],
        desc: 'Remote code execution via Log4j JNDI lookup.',
        refs: [],
      })
      expect(guide).toHaveProperty('key')
      expect(guide).toHaveProperty('name')
      expect(guide).toHaveProperty('detect')
      expect(guide).toHaveProperty('exploit')
      expect(guide).toHaveProperty('mitigate')
      expect(guide).toHaveProperty('resources')
      expect(guide).toHaveProperty('classification')
      expect(guide).toHaveProperty('isCVEspecific')
      expect(guide.classification).toHaveProperty('confidence')
      expect(guide.classification).toHaveProperty('evidence')
    })

    it('includes NVD and exploit-db resources', () => {
      const guide = buildGuide({
        id: 'CVE-2021-44228',
        cwes: ['CWE-94'],
        desc: '',
        refs: [],
      })
      expect(guide.resources.some(r => r.includes('nvd.nist.gov'))).toBe(true)
      expect(guide.resources.some(r => r.includes('exploit-db.com'))).toBe(true)
      expect(guide.resources.some(r => r.includes('cve.mitre.org'))).toBe(true)
    })

    it('marks generic guide when confidence is low', () => {
      const guide = buildGuide({
        id: 'CVE-9999-0001',
        cwes: [],
        desc: 'An unspecified vulnerability.',
        refs: [],
      })
      expect(guide.isCVEspecific).toBe(false)
    })
  })
})
