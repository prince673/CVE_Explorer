import { describe, it, expect } from 'vitest'
import { parseSBOM } from '../src/utils/sbomParser'

describe('SBOM Parser', () => {
  describe('package.json parsing', () => {
    it('parses package.json dependencies', () => {
      const content = JSON.stringify({
        dependencies: { react: '^18.0.0', lodash: '~4.17.21' },
        devDependencies: { vite: '^5.0.0' },
      })
      const result = parseSBOM('package.json', content)
      expect(result.format).toBe('package-json')
      expect(result.totalPackages).toBe(3)
      expect(result.packages.some(p => p.name === 'react')).toBe(true)
      expect(result.packages.some(p => p.name === 'lodash')).toBe(true)
      expect(result.packages.some(p => p.name === 'vite')).toBe(true)
    })

    it('strips version prefixes', () => {
      const content = JSON.stringify({ dependencies: { express: '^4.18.0' } })
      const result = parseSBOM('package.json', content)
      expect(result.packages[0].version).toBe('4.18.0')
    })

    it('handles empty package.json', () => {
      const content = JSON.stringify({})
      const result = parseSBOM('package.json', content)
      expect(result.totalPackages).toBe(0)
    })
  })

  describe('requirements.txt parsing', () => {
    it('parses requirements.txt', () => {
      const content = 'flask==2.3.0\nrequests>=2.28.0\nnumpy\n'
      const result = parseSBOM('requirements.txt', content)
      expect(result.format).toBe('requirements')
      expect(result.totalPackages).toBe(3)
      expect(result.packages[0].name).toBe('flask')
      expect(result.packages[0].ecosystem).toBe('pypi')
    })

    it('skips comments and blank lines', () => {
      const content = '# This is a comment\n\nflask==2.3.0\n# Another comment\n'
      const result = parseSBOM('requirements.txt', content)
      expect(result.totalPackages).toBe(1)
    })
  })

  describe('pom.xml parsing', () => {
    it('parses Maven dependencies', () => {
      const content = `<dependencies>
        <dependency><groupId>org.springframework</groupId><artifactId>spring-core</artifactId><version>5.3.0</version></dependency>
        <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId></dependency>
      </dependencies>`
      const result = parseSBOM('pom.xml', content)
      expect(result.format).toBe('pom-xml')
      expect(result.totalPackages).toBe(2)
      expect(result.packages[0].name).toBe('org.springframework:spring-core')
    })
  })

  describe('CycloneDX parsing', () => {
    it('parses CycloneDX SBOM', () => {
      const content = JSON.stringify({
        components: [
          { name: 'lodash', version: '4.17.21', cpe: 'cpe:2.3:a:lodash:lodash:4.17.21' },
          { name: 'express', version: '4.18.0' },
        ],
      })
      const result = parseSBOM('bom.json', content)
      expect(result.format).toBe('cyclonedx')
      expect(result.totalPackages).toBe(2)
      expect(result.packages[0].cpe).toBe('cpe:2.3:a:lodash:lodash:4.17.21')
    })
  })

  describe('SPDX parsing', () => {
    it('parses SPDX SBOM', () => {
      const content = JSON.stringify({
        packages: [
          { name: 'lodash', versionInfo: '4.17.21', spdxID: 'SPDXRef-Package-lodash' },
          { name: 'NOASSERTION', versionInfo: '1.0' },
        ],
      })
      const result = parseSBOM('spdx.json', content)
      expect(result.format).toBe('spdx')
      expect(result.totalPackages).toBe(1)
      expect(result.packages[0].name).toBe('lodash')
    })
  })

  describe('format detection', () => {
    it('auto-detects package.json', () => {
      const content = JSON.stringify({ dependencies: {} })
      const result = parseSBOM('package.json', content)
      expect(result.format).toBe('package-json')
    })

    it('auto-detects requirements.txt', () => {
      const content = 'flask==2.3.0\n'
      const result = parseSBOM('requirements.txt', content)
      expect(result.format).toBe('requirements')
    })

    it('auto-detects CycloneDX from content', () => {
      const content = JSON.stringify({ components: [] })
      const result = parseSBOM('bom.json', content)
      expect(result.format).toBe('cyclonedx')
    })
  })
})
