// Terminal formatter — enhanced with EPSS, KEV, risk scoring, classification
import chalk from 'chalk'
import boxen from 'boxen'

export function getSeverity(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return { label: 'UNKNOWN', color: chalk.gray, badge: chalk.bgGray.black }
  if (n >= 9.0)  return { label: 'CRITICAL', color: chalk.red,     badge: chalk.bgRed.white }
  if (n >= 7.0)  return { label: 'HIGH',     color: chalk.yellow,  badge: chalk.bgYellow.black }
  if (n >= 4.0)  return { label: 'MEDIUM',   color: chalk.cyan,    badge: chalk.bgCyan.black }
  return              { label: 'LOW',      color: chalk.green,   badge: chalk.bgGreen.black }
}

export function formatDate(str) {
  if (!str) return '—'
  try { return new Date(str).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) }
  catch { return str }
}

function cvssBar(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return chalk.gray('no score')
  const filled = Math.round((n / 10) * 20)
  const { color, badge } = getSeverity(n)
  const bar = color('█'.repeat(filled)) + chalk.gray('░'.repeat(20 - filled))
  return `${bar} ${badge(` ${n.toFixed(1)} `)} ${getSeverity(n).label}`
}

function wrap(text, width = 72) {
  const words = text.split(' ')
  const lines = []
  let current = ''
  for (const word of words) {
    if ((current + ' ' + word).trim().length > width) {
      lines.push(current.trim())
      current = word
    } else {
      current = current ? current + ' ' + word : word
    }
  }
  if (current) lines.push(current.trim())
  return lines.join('\n')
}

function sectionHeader(icon, title) {
  return '\n' + chalk.bold.cyan(`${icon}  ${title}`) + '\n' + chalk.cyan('─'.repeat(60))
}

function renderSteps(steps, color) {
  return steps.map((s, i) => {
    const num   = chalk.dim(`[${String(i + 1).padStart(2, '0')}]`)
    const title = color.bold(s.t)
    const body  = chalk.gray(wrap(s.b, 68))
    let out     = `\n  ${num} ${title}\n      ${body}`
    if (s.cmd) {
      const cmdLines = s.cmd.split('\n').map(l => chalk.yellow('      $ ') + chalk.white(l)).join('\n')
      out += '\n' + cmdLines
    }
    return out
  }).join('\n')
}

function riskBar(score) {
  const filled = Math.round((score / 100) * 20)
  let color = chalk.green
  if (score >= 80) color = chalk.red
  else if (score >= 60) color = chalk.yellow
  else if (score >= 40) color = chalk.cyan
  return color('█'.repeat(filled)) + chalk.gray('░'.repeat(20 - filled)) + ` ${score}/100`
}

export function renderCVE(cveData, guide, enrichments = {}, opts = {}) {
  const { section, noColor } = opts
  const prevLevel = chalk.level
  if (noColor) chalk.level = 0

  const { label, badge } = getSeverity(cveData.cvss3 ?? cveData.cvss2)
  const lines = []

  const headerContent = [
    chalk.bold.white(`  ${cveData.id}`) + '  ' + badge(` ${label} `),
    '',
    chalk.dim('CVSS v3:  ') + cvssBar(cveData.cvss3),
    cveData.cvss2 ? chalk.dim('CVSS v2:  ') + chalk.magenta(cveData.cvss2.toFixed(1)) : '',
    '',
    chalk.dim('Published:  ') + chalk.white(formatDate(cveData.pub)),
    chalk.dim('Modified:   ') + chalk.white(formatDate(cveData.mod)),
    cveData.cwes?.length ? chalk.dim('CWE(s):     ') + chalk.yellow(cveData.cwes.join(', ')) : '',
  ].filter(Boolean).join('\n')

  lines.push(
    boxen(headerContent, {
      padding: { top: 1, bottom: 1, left: 2, right: 2 },
      borderStyle: 'round',
      borderColor: 'cyan',
    })
  )

  // Classification
  if (guide.classification) {
    const cls = guide.classification
    lines.push(chalk.bold('\n🔍  Classification'))
    lines.push(`  Type:      ${chalk.cyan(cls.primary)} (${cls.confidenceLabel}, ${cls.confidence}%)`)
    lines.push(`  Evidence:  ${cls.evidence.length} signals`)
    if (!cls.isGeneric) {
      lines.push(chalk.green(`  ✓ CVE-specific guide selected`))
    } else {
      lines.push(chalk.yellow(`  ⚠ Low confidence — showing general guide`))
    }
  }

  // EPSS
  if (enrichments.epss) {
    lines.push(chalk.bold('\n📈  EPSS'))
    const p = enrichments.epss.probability
    const pct = (p * 100).toFixed(1)
    lines.push(`  Probability: ${chalk.yellow(pct + '%')}  Percentile: P${Math.round(enrichments.epss.percentile * 100)}`)
  }

  // KEV
  if (enrichments.kev?.inCatalog) {
    lines.push(chalk.bold('\n🚨  CISA KEV'))
    lines.push(chalk.red(`  ACTIVE EXPLOITATION — In Known Exploited Vulnerabilities catalog`))
    if (enrichments.kev.dueDate) lines.push(chalk.dim(`  Due date: ${enrichments.kev.dueDate}`))
    if (enrichments.kev.knownRansomwareCampaignUse === 'Known') {
      lines.push(chalk.red.bold(`  ⚠️  Known ransomware campaign use`))
    }
  }

  // Exploits
  if (enrichments.hasExploit) {
    lines.push(chalk.bold('\n💥  Exploits'))
    lines.push(chalk.red(`  Public exploit code is available`))
    if (enrichments.exploitSources?.length) {
      for (const s of enrichments.exploitSources.slice(0, 3)) {
        lines.push(chalk.dim(`  → ${s.url}`) + (s.stars ? chalk.gray(` (${s.stars}★)`) : ''))
      }
    }
  }

  // Risk Score
  const cvss = parseFloat(cveData.cvss3 || cveData.cvss2 || 0)
  let riskScore = 0
  if (cvss >= 9.0) riskScore += 25
  else if (cvss >= 7.0) riskScore += 15
  else if (cvss >= 4.0) riskScore += 8
  if (enrichments.kev?.inCatalog) riskScore += 20
  if (enrichments.epss?.probability >= 0.5) riskScore += 20
  if (enrichments.hasExploit) riskScore += 10
  riskScore = Math.min(100, riskScore)

  if (riskScore > 0) {
    lines.push(chalk.bold('\n⚡  Risk Score'))
    lines.push(`  ${riskBar(riskScore)}  ${riskScore >= 60 ? chalk.red('HIGH PRIORITY') : riskScore >= 30 ? chalk.yellow('MEDIUM') : chalk.green('LOW')}`)
  }

  lines.push(chalk.bold('\n📄  Description'))
  lines.push(chalk.gray(wrap(cveData.desc, 76)))

  if (cveData.products?.length) {
    lines.push(chalk.bold('\n📦  Affected Products'))
    cveData.products.slice(0, 10).forEach(p => lines.push(chalk.dim('  • ') + chalk.white(p)))
    if (cveData.products.length > 10) lines.push(chalk.dim(`  … and ${cveData.products.length - 10} more`))
  }

  lines.push(chalk.bold.magenta(`\n🗂  Guide Type: ${guide.name}`))
  if (!guide.isCVEspecific) {
    lines.push(chalk.yellow(`  ⚠ Low classification confidence — general guide`))
  }

  if (!section || section === 'detect') {
    lines.push(sectionHeader('🔍', 'Detection Steps'))
    lines.push(renderSteps(guide.detect, chalk.green))
  }

  if (!section || section === 'exploit') {
    lines.push(sectionHeader('💥', 'Exploitation Steps'))
    lines.push(chalk.bgRed.white.bold('  ⚠  AUTHORIZED TESTING ENVIRONMENTS ONLY  '))
    lines.push(renderSteps(guide.exploit, chalk.red))
  }

  if (!section || section === 'mitigate') {
    lines.push(sectionHeader('🛡 ', 'Mitigation Steps'))
    lines.push(renderSteps(guide.mitigate, chalk.blue))
  }

  if (!section || section === 'resources') {
    lines.push(sectionHeader('🔗', 'Resources'))
    guide.resources.forEach(r => lines.push(chalk.dim('  • ') + chalk.cyan.underline(r)))
  }

  lines.push('\n' + chalk.dim('─'.repeat(60)))
  lines.push(chalk.dim('⚡ cve-explorer v3.0  |  Enhanced with EPSS, KEV, risk scoring'))
  lines.push(chalk.dim('   NVD: https://nvd.nist.gov  |  CIRCL: https://cve.circl.lu'))
  lines.push('')

  chalk.level = prevLevel
  return lines.join('\n')
}

export function renderGuideTypes(types) {
  const header = chalk.bold.cyan('  Supported Vulnerability Guide Types\n') + chalk.cyan('-'.repeat(50))
  const rows = types.map((t, i) => {
    const num = String(i + 1).padStart(2, ' ') + '.'
    return chalk.dim('  ' + num + '  ') + chalk.white.bold(t.name) + chalk.dim('  [' + t.key + ']')
  })
  return header + '\n' + rows.join('\n') + '\n'
}

export function renderHelp() {
  return boxen(
    chalk.bold.cyan('cve-explorer v3.0') + chalk.dim(' — Enhanced CVE lookup with EPSS, KEV, risk scoring\n\n') +
    chalk.bold('Usage:\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.dim('                 # Full report\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.green(' --section detect') + chalk.dim('  # Only detection steps\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.green(' --section exploit') + chalk.dim(' # Only exploit steps\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.green(' --section mitigate') + chalk.dim(' # Only mitigation\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.green(' --section resources') + chalk.dim('# Only resources\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.green(' --json') + chalk.dim('            # Raw JSON output\n') +
    chalk.white('  cve-explorer ') + chalk.yellow('<CVE-ID>') + chalk.green(' --output report.txt') + chalk.dim('# Save to file\n') +
    chalk.white('  cve-explorer ') + chalk.green('--list-types') + chalk.dim('               # Show all guide types\n') +
    chalk.white('  cve-explorer ') + chalk.green('--help') + chalk.dim('                     # Show this help\n\n') +
    chalk.bold('Flags:\n') +
    chalk.green('  --section  ') + chalk.dim('<detect|exploit|mitigate|resources>\n') +
    chalk.green('  --json     ') + chalk.dim('Dump raw JSON to stdout\n') +
    chalk.green('  --output   ') + chalk.dim('<file>  Write plain-text report to file\n') +
    chalk.green('  --no-color ') + chalk.dim('Disable ANSI colors (for logging/piping)\n') +
    chalk.green('  --list-types') + chalk.dim(' List all supported vuln guide types\n\n') +
    chalk.bold('New in v3.0:\n') +
    chalk.dim('  • EPSS exploitation probability scores\n') +
    chalk.dim('  • CISA KEV active exploitation status\n') +
    chalk.dim('  • Multi-signal classification with confidence\n') +
    chalk.dim('  • Risk scoring with explainable factors\n') +
    chalk.dim('  • Exploit availability detection'),
    { padding: 1, borderStyle: 'round', borderColor: 'cyan' }
  )
}
