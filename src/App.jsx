import { useState, useEffect, useRef } from 'react'
import DisclaimerModal      from './components/DisclaimerModal'
import Header               from './components/Header'
import InputForm            from './components/InputForm'
import LoadingSpinner       from './components/LoadingSpinner'
import VulnerabilityCard    from './components/VulnerabilityCard'
import ExploitationGuide    from './components/ExploitationGuide'
import GuideTypesPanel      from './components/GuideTypesPanel'
import Footer               from './components/Footer'
import RiskScoreCard        from './components/RiskScoreCard'
import ExploitabilityCard   from './components/ExploitabilityCard'
import AffectedAssetsPanel  from './components/AffectedAssetsPanel'
import RemediationTracker   from './components/RemediationTracker'
import AlertPanel           from './components/AlertPanel'
import SBOMScanner          from './components/SBOMScanner'
import AssetManager         from './components/AssetManager'
import AnalyticsDashboard   from './components/AnalyticsDashboard'
import { lookupCVE, getUnreadAlertCount } from './services/api'
import { buildGuide }       from './utils/guideEngine'

const VIEWS = {
  HOME: 'home',
  RESULTS: 'results',
  DASHBOARD: 'dashboard',
  ASSETS: 'assets',
  SBOM: 'sbom',
  ANALYTICS: 'analytics',
  ALERTS: 'alerts',
}

export default function App() {
  const [view, setView] = useState(VIEWS.HOME)
  const [cveData, setCveData] = useState(null)
  const [guide, setGuide] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [alertCount, setAlertCount] = useState(0)
  const searchGenRef = useRef(0)

  useEffect(() => {
    getUnreadAlertCount().then(d => setAlertCount(d.count ?? 0)).catch(() => setAlertCount(0))
  }, [view])

  function handleReset() {
    setCveData(null)
    setGuide(null)
    setError(null)
    setView(VIEWS.HOME)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  function handleNavigate(newView) {
    setView(newView)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  async function handleSearch(id) {
    const gen = ++searchGenRef.current
    setLoading(true)
    setError(null)
    setCveData(null)
    setGuide(null)
    setView(VIEWS.RESULTS)

    try {
      const data = await lookupCVE(id)
      if (gen !== searchGenRef.current) return
      setCveData(data)

      const g = buildGuide({
        cve_id: data.cve_id,
        description: data.description,
        cwes: data.cwes,
        products: data.products,
        references: data.references,
        best_cvss: data.best_cvss,
        cvss_scores: data.cvss_scores,
      })
      if (gen !== searchGenRef.current) return
      setGuide(g)

      setLoading(false)

      getUnreadAlertCount().then(d => setAlertCount(d.count ?? 0)).catch(() => {})

      setTimeout(() => {
        if (gen === searchGenRef.current) {
          document.getElementById('results')?.scrollIntoView({ behavior: 'smooth' })
        }
      }, 100)
    } catch (err) {
      if (gen !== searchGenRef.current) return
      setError(err.message || 'An unexpected error occurred.')
    } finally {
      if (gen === searchGenRef.current) setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-dark-bg text-gray-100 flex flex-col">
      <DisclaimerModal />
      <Header view={view} onNavigate={handleNavigate} alertCount={alertCount} />

      <main className="flex-1 max-w-5xl mx-auto w-full px-4 py-8">
        {view === VIEWS.HOME && (
          <>
            <InputForm onSubmit={handleSearch} loading={loading} />
            <GuideTypesPanel />
          </>
        )}

        {view === VIEWS.RESULTS && (
          <>
            {loading && <LoadingSpinner message="Fetching vulnerability intelligence..." />}

            {error && !loading && (
              <div className="flex items-start gap-4 card border-red-500/40 bg-red-500/8
                              animate-fade-up mb-5">
                <span className="text-2xl shrink-0">❌</span>
                <div>
                  <h3 className="font-bold text-red-400 mb-1">Error</h3>
                  <p className="text-gray-400 text-sm">{error}</p>
                  <p className="text-gray-600 text-xs mt-2">
                    Check the CVE ID format (CVE-YYYY-NNNNN) and your internet connection.
                  </p>
                </div>
              </div>
            )}

            {cveData && !loading && (
              <div id="results">
                <button
                  onClick={handleReset}
                  className="btn-ghost mb-4 flex items-center gap-1.5 text-sm"
                >
                  <span>←</span> New Search
                </button>

                <VulnerabilityCard cve={cveData} />

                {cveData.risk && (
                  <RiskScoreCard risk={cveData.risk} />
                )}

                <ExploitabilityCard cve={cveData} />

                {guide && (
                  <ExploitationGuide guide={guide} />
                )}

                <AffectedAssetsPanel assets={cveData.affected_assets || []} />

                <RemediationTracker cveId={cveData.cve_id} />

                <button
                  onClick={handleReset}
                  className="btn-ghost mt-6 mb-2 flex items-center gap-1.5 text-sm"
                >
                  <span>←</span> Back to Home
                </button>
              </div>
            )}
          </>
        )}

        {view === VIEWS.DASHBOARD && (
          <div className="space-y-5">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-lg">🏠</span>
              <h2 className="font-bold text-lg text-white">Security Dashboard</h2>
            </div>
            <InputForm onSubmit={handleSearch} loading={loading} />
            <GuideTypesPanel />
            <AlertPanel />
          </div>
        )}

        {view === VIEWS.ASSETS && (
          <AssetManager />
        )}

        {view === VIEWS.SBOM && (
          <SBOMScanner onPackagesParsed={() => {
              getUnreadAlertCount().then(d => setAlertCount(d.count ?? 0)).catch(() => {})
            }} />
        )}

        {view === VIEWS.ANALYTICS && (
          <AnalyticsDashboard />
        )}

        {view === VIEWS.ALERTS && (
          <AlertPanel />
        )}
      </main>

      <Footer />
    </div>
  )
}
