#!/usr/bin/env node
// cve-explorer v3.0 — Enhanced with EPSS, KEV, risk scoring, classification
import minimist from 'minimist'
import readline from 'readline'
import { writeFileSync } from 'fs'
import ora from 'ora'
import { fetchCVE } from './api.js'
import { buildGuide, getAllGuideTypes } from './guideEngine.js'
import { renderCVE, renderGuideTypes, renderHelp } from './formatter.js'
import chalk from 'chalk'

const EPSS_BASE = 'https://api.first.org/data/v1/epss'
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

const argv = minimist(process.argv.slice(2), {
  boolean: ['help', 'h', 'json', 'list-types', 'no-color'],
  string:  ['section', 'output', 'id'],
})

const VALID_SECTIONS = ['detect', 'exploit', 'mitigate', 'resources']
const CVE_PATTERN    = /^CVE-\d{4}-\d{4,}$/i

function validateId(id) {
  if (!id) return null
  const trimmed = id.trim().toUpperCase()
  return CVE_PATTERN.test(trimmed) ? trimmed : null
}

function stripAnsi(str) {
  return str.replace(/\x1B\[[0-9;]*m/g, '')
}

async function fetchEPSS(cveId) {
  try {
    const res = await fetch(`${EPSS_BASE}?cve=${cveId}`, { signal: AbortSignal.timeout(8000) })
    if (res.ok) {
      const data = await res.json()
      const entry = data?.data?.[0]
      if (entry) return { probability: parseFloat(entry.epss), percentile: parseFloat(entry.percentile), date: entry.date }
    }
  } catch {}
  return null
}

async function fetchKEV(cveId) {
  try {
    const res = await fetch(KEV_URL, { signal: AbortSignal.timeout(15000) })
    if (res.ok) {
      const data = await res.json()
      const vuln = (data?.vulnerabilities || []).find(v => v.cveID === cveId)
      if (vuln) return { inCatalog: true, ...vuln }
    }
  } catch {}
  return { inCatalog: false }
}

async function fetchExploits(cveId) {
  try {
    const res = await fetch(`https://api.github.com/search/repositories?q=${cveId}+exploit&sort=stars&per_page=3`, {
      signal: AbortSignal.timeout(10000),
    })
    if (res.ok) {
      const data = await res.json()
      if (data?.items?.length > 0) {
        return { hasExploit: true, sources: data.items.map(i => ({ url: i.html_url, stars: i.stargazers_count })) }
      }
    }
  } catch {}
  return { hasExploit: false, sources: [] }
}

async function runLookup(rawId, opts) {
  const id = validateId(rawId)
  if (!id) {
    console.error(chalk.red(`✘ Invalid CVE ID: "${rawId}" — expected format: CVE-YYYY-NNNN`))
    process.exit(1)
  }

  if (opts.section && !VALID_SECTIONS.includes(opts.section)) {
    console.error(chalk.red(`✘ Invalid --section "${opts.section}". Choose from: ${VALID_SECTIONS.join(', ')}`))
    process.exit(1)
  }

  const spinner = ora({ text: `Fetching ${id}…`, color: 'cyan' }).start()

  let cveData, guide, enrichments
  try {
    cveData = await fetchCVE(id)
    guide   = buildGuide(cveData)
    spinner.text = 'Fetching EPSS, KEV, exploit data…'

    const [epss, kev, exploit] = await Promise.allSettled([
      fetchEPSS(id),
      fetchKEV(id),
      fetchExploits(id),
    ])

    enrichments = {
      epss: epss.status === 'fulfilled' ? epss.value : null,
      kev: kev.status === 'fulfilled' ? kev.value : { inCatalog: false },
      hasExploit: exploit.status === 'fulfilled' ? exploit.value?.hasExploit : false,
      exploitSources: exploit.status === 'fulfilled' ? exploit.value?.sources || [] : [],
    }

    spinner.succeed(chalk.green(`Fetched ${id} — ${guide.name}`))
    if (guide.classification) {
      console.log(chalk.dim(`  Classification: ${guide.classification.primary} (${guide.classification.confidenceLabel}, ${guide.classification.confidence}%)`))
    }
  } catch (err) {
    spinner.fail(chalk.red(`Failed: ${err.message}`))
    process.exit(1)
  }

  if (opts.json) {
    const out = JSON.stringify({ cve: cveData, guide, enrichments }, null, 2)
    console.log(out)
    if (opts.output) {
      writeFileSync(opts.output, out, 'utf8')
      console.error(chalk.dim(`Saved JSON to ${opts.output}`))
    }
    return
  }

  const rendered = renderCVE(cveData, guide, enrichments, { section: opts.section, noColor: opts['no-color'] })
  console.log(rendered)

  if (opts.output) {
    const plain = stripAnsi(rendered)
    writeFileSync(opts.output, plain, 'utf8')
    console.log(chalk.dim(`\n✔ Report saved to ${chalk.white(opts.output)}`))
  }
}

async function interactiveMode(opts) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout })
  console.log(chalk.bold.cyan('\n  ╔══════════════════════════════════════════╗'))
  console.log(chalk.bold.cyan('  ║   CVE Explorer v3.0 — Interactive Mode   ║'))
  console.log(chalk.bold.cyan('  ╚══════════════════════════════════════════╝'))
  console.log(chalk.dim('  Enhanced with EPSS, KEV, exploit detection, risk scoring\n'))
  console.log(chalk.dim('  Type a CVE ID to look it up, or "quit" to exit.\n'))

  const ask = () => {
    rl.question(chalk.cyan('  cve> '), async (input) => {
      const trimmed = input.trim()
      if (!trimmed || trimmed.toLowerCase() === 'quit' || trimmed.toLowerCase() === 'exit') {
        console.log(chalk.dim('\n  Goodbye!\n'))
        rl.close()
        return
      }
      await runLookup(trimmed, opts)
      ask()
    })
  }
  ask()
}

async function main() {
  if (argv.help || argv.h) {
    console.log(renderHelp())
    process.exit(0)
  }

  if (argv['list-types']) {
    console.log(renderGuideTypes(getAllGuideTypes()))
    process.exit(0)
  }

  const rawId = argv._[0] || argv.id || null

  const opts = {
    section:   argv.section   || null,
    json:      argv.json      || false,
    output:    argv.output    || null,
    'no-color': argv['no-color'] || false,
  }

  if (!rawId) {
    await interactiveMode(opts)
  } else {
    await runLookup(rawId, opts)
  }
}

main().catch(err => {
  console.error(chalk.red(`Unexpected error: ${err.message}`))
  process.exit(1)
})
