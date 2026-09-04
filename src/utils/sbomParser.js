/**
 * SBOM (Software Bill of Materials) parser.
 * Supports package.json, requirements.txt, pom.xml, CycloneDX, SPDX,
 * and generic CPE-based input.
 */

const PACKAGE_JSON_REGEX = /package\.json/i
const REQUIREMENTS_REGEX = /requirements\.txt/i
const POM_REGEX = /pom\.xml/i
const CYCLONEDX_REGEX = /cyclonedx/i
const SPDX_REGEX = /spdx/i

function parsePackageJson(content) {
  try {
    const pkg = JSON.parse(content)
    const deps = { ...pkg.dependencies, ...pkg.devDependencies }
    return Object.entries(deps || {}).map(([name, version]) => ({
      name,
      version: version.replace(/^[~^>=<]/, ''),
      ecosystem: 'npm',
      type: 'direct',
    }))
  } catch { return [] }
}

function parseRequirementsTxt(content) {
  return content.split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith('-'))
    .map(line => {
      const match = line.match(/^([a-zA-Z0-9_.-]+)\s*([=><!~]+)\s*(.+)$/)
      if (match) return { name: match[1], version: match[3].trim(), ecosystem: 'pypi', type: 'direct' }
      return { name: line, version: '*', ecosystem: 'pypi', type: 'direct' }
    })
    .filter(Boolean)
}

function parsePomXml(content) {
  const deps = []
  const depRegex = /<dependency>\s*<groupId>(.*?)<\/groupId>\s*<artifactId>(.*?)<\/artifactId>\s*(?:<version>(.*?)<\/version>)?/g
  let match
  while ((match = depRegex.exec(content)) !== null) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3] || '*',
      ecosystem: 'maven',
      type: 'direct',
    })
  }
  return deps
}

function parseCycloneDX(content) {
  try {
    const doc = JSON.parse(content)
    const components = doc.components || []
    return components.map(c => ({
      name: c.name || '',
      version: c.version || '*',
      ecosystem: c.packageUrl ? c.packageUrl.split(':')[1] : (c.type || 'unknown'),
      cpe: c.cpe || '',
      type: 'direct',
    }))
  } catch { return [] }
}

function parseSPDX(content) {
  try {
    const doc = JSON.parse(content)
    const packages = doc.packages || []
    return packages.filter(p => p.name !== 'NOASSERTION').map(p => ({
      name: p.name || '',
      version: p.versionInfo || '*',
      ecosystem: 'spdx',
      spdxId: p.spdxID || '',
      type: 'direct',
    }))
  } catch { return [] }
}

function detectFormat(filename, content) {
  if (PACKAGE_JSON_REGEX.test(filename)) return 'package-json'
  if (REQUIREMENTS_REGEX.test(filename)) return 'requirements'
  if (POM_REGEX.test(filename)) return 'pom-xml'
  if (CYCLONEDX_REGEX.test(filename)) return 'cyclonedx'
  if (SPDX_REGEX.test(filename)) return 'spdx'
  try {
    const parsed = JSON.parse(content)
    if (parsed.components) return 'cyclonedx'
    if (parsed.packages) return 'spdx'
    if (parsed.dependencies || parsed.devDependencies) return 'package-json'
  } catch { /* fall through */ }
  if (content.includes('<dependency>') && content.includes('<groupId>')) return 'pom-xml'
  if (/^[a-zA-Z0-9_-]+\s*[=><!~]/m.test(content)) return 'requirements'
  return 'unknown'
}

export function parseSBOM(filename, content) {
  const format = detectFormat(filename, content)
  let packages = []

  switch (format) {
    case 'package-json': packages = parsePackageJson(content); break
    case 'requirements': packages = parseRequirementsTxt(content); break
    case 'pom-xml': packages = parsePomXml(content); break
    case 'cyclonedx': packages = parseCycloneDX(content); break
    case 'spdx': packages = parseSPDX(content); break
    default:
      try {
        packages = parsePackageJson(content)
      } catch { /* fall through */ }
  }

  return {
    format,
    packages,
    totalPackages: packages.length,
    parsedAt: new Date().toISOString(),
    filename,
  }
}

export function parseDependencyFile(content, filename = 'dependencies.txt') {
  return parseSBOM(filename, content)
}
