import { useState, useRef } from 'react'
import { parseSBOM } from '../utils/sbomParser'
import { importAssetsFromSBOM } from '../utils/assetStore'
import { logAudit } from '../utils/auditLog'

export default function SBOMScanner({ onPackagesParsed }) {
  const [result, setResult] = useState(null)
  const [importing, setImporting] = useState(false)
  const [imported, setImported] = useState(0)
  const fileRef = useRef()

  function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const content = ev.target?.result
      if (typeof content === 'string') {
        const parsed = parseSBOM(file.name, content)
        setResult(parsed)
        logAudit({ action: 'sbom.parse', entityType: 'sbom', detail: `Parsed ${file.name}: ${parsed.totalPackages} packages (${parsed.format})` })
        onPackagesParsed?.(parsed)
      }
    }
    reader.readAsText(file)
  }

  function handleImport() {
    if (!result?.packages) return
    setImporting(true)
    const importedAssets = importAssetsFromSBOM(result.packages)
    setImported(importedAssets.length)
    setImporting(false)
    logAudit({ action: 'sbom.import', entityType: 'asset', detail: `Imported ${importedAssets.length} assets from SBOM` })
  }

  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-lg">📦</span>
        <h3 className="font-bold text-base text-white">SBOM Scanner</h3>
        <span className="ml-auto text-xs text-gray-600">Package.json, requirements.txt, pom.xml, CycloneDX, SPDX</span>
      </div>

      <div
        className="border-2 border-dashed border-dark-border rounded-lg p-6 text-center
                   hover:border-accent-cyan/40 transition-colors cursor-pointer"
        onClick={() => fileRef.current?.click()}
      >
        <input
          ref={fileRef}
          type="file"
          accept=".json,.txt,.xml,.sbom"
          onChange={handleFile}
          className="hidden"
        />
        <p className="text-sm text-gray-400 mb-1">Click to upload dependency file</p>
        <p className="text-xs text-gray-600">Supports: package.json, requirements.txt, pom.xml, CycloneDX, SPDX</p>
      </div>

      {result && (
        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap gap-3 text-xs">
            <span className="tag bg-accent-cyan/15 text-accent-cyan border-accent-cyan/40">
              Format: {result.format}
            </span>
            <span className="tag bg-accent-purple/15 text-purple-300 border-accent-purple/40">
              {result.totalPackages} packages
            </span>
          </div>

          <div className="max-h-60 overflow-y-auto border border-dark-border/50 rounded-lg">
            <table className="w-full text-xs">
              <thead className="bg-dark-bg/80 sticky top-0">
                <tr>
                  <th className="text-left px-3 py-2 text-gray-500 font-medium">Package</th>
                  <th className="text-left px-3 py-2 text-gray-500 font-medium">Version</th>
                  <th className="text-left px-3 py-2 text-gray-500 font-medium">Ecosystem</th>
                </tr>
              </thead>
              <tbody>
                {result.packages.slice(0, 50).map((pkg, i) => (
                  <tr key={i} className="border-t border-dark-border/30">
                    <td className="px-3 py-1.5 font-mono text-gray-300">{pkg.name}</td>
                    <td className="px-3 py-1.5 text-gray-400">{pkg.version}</td>
                    <td className="px-3 py-1.5 text-gray-500">{pkg.ecosystem}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {result.packages.length > 50 && (
              <p className="text-center text-xs text-gray-600 py-2">
                ... and {result.packages.length - 50} more
              </p>
            )}
          </div>

          <button
            onClick={handleImport}
            disabled={importing}
            className="btn-primary text-sm w-full"
          >
            {importing ? 'Importing...' : imported > 0 ? `Imported ${imported} assets` : 'Import as Assets'}
          </button>
        </div>
      )}
    </div>
  )
}
