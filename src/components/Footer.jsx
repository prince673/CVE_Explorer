export default function Footer() {
  return (
    <footer className="border-t border-dark-border bg-dark-bg2 mt-12 py-8 px-4">
      <div className="max-w-5xl mx-auto">

        {/* Disclaimer box */}
        <div className="border border-red-500/25 bg-red-500/8 rounded-xl
                        px-6 py-4 text-center mb-4">
          <p className="text-sm text-gray-300">
            <strong className="text-red-400">Legal Disclaimer:</strong>{' '}
            CVE Explorer is for{' '}
            <strong className="text-white">authorized security research and education only</strong>.
            Unauthorized testing is{' '}
            <strong className="text-red-400">illegal</strong>.
            Developers assume no liability for misuse.
          </p>
        </div>

        {/* Links row */}
        <div className="flex flex-wrap items-center justify-center gap-4 text-xs text-gray-600">
          <a href="https://nvd.nist.gov" target="_blank" rel="noopener noreferrer"
             className="hover:text-accent-cyan transition-colors">NVD</a>
          <span>·</span>
          <a href="https://cve.mitre.org" target="_blank" rel="noopener noreferrer"
             className="hover:text-accent-cyan transition-colors">MITRE CVE</a>
          <span>·</span>
          <a href="https://cve.circl.lu" target="_blank" rel="noopener noreferrer"
             className="hover:text-accent-cyan transition-colors">CIRCL API</a>
          <span>·</span>
          <a href="https://owasp.org" target="_blank" rel="noopener noreferrer"
             className="hover:text-accent-cyan transition-colors">OWASP</a>
          <span>·</span>
          <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
             target="_blank" rel="noopener noreferrer"
             className="hover:text-accent-cyan transition-colors">CISA KEV</a>
        </div>

        <p className="text-center text-xs text-gray-700 mt-3">
          CVE Explorer v2.0 · Data from CIRCL CVE API & NVD · For authorized use only
        </p>
      </div>
    </footer>
  )
}
