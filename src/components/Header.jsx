import { useState, useEffect } from 'react'

export default function Header({ view, onNavigate, alertCount = 0 }) {
  const [dark, setDark] = useState(() => {
    const stored = localStorage.getItem('cve_theme')
    return stored ? stored === 'dark' : true
  })

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('cve_theme', dark ? 'dark' : 'light')
  }, [dark])

  const navItems = [
    { key: 'home', label: '🔍 Search', view: 'home' },
    { key: 'assets', label: '🏗️ Assets', view: 'assets' },
    { key: 'sbom', label: '📦 SBOM', view: 'sbom' },
    { key: 'analytics', label: '📊 Analytics', view: 'analytics' },
    { key: 'alerts', label: '🔔', view: 'alerts', badge: alertCount },
  ]

  return (
    <header className="sticky top-0 z-40 border-b border-dark-border
                       bg-dark-bg2/95 backdrop-blur-md">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">

        <div className="flex items-center gap-2 cursor-pointer" onClick={() => onNavigate?.('home')}>
          <span className="text-xl">🛡️</span>
          <span className="font-extrabold text-lg">
            <span className="text-accent-cyan">CVE</span>
            <span className="text-white"> Explorer</span>
          </span>
          <span className="hidden sm:inline ml-2 text-xs text-gray-500 border border-dark-border
                           rounded-full px-2 py-0.5 font-mono">
            v3.0
          </span>
        </div>

        <nav className="hidden sm:flex items-center gap-1">
          {navItems.map(item => (
            <button
              key={item.key}
              onClick={() => onNavigate?.(item.view)}
              className={`relative text-xs px-3 py-1.5 rounded-lg transition-colors ${
                view === item.view
                  ? 'bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30'
                  : 'text-gray-500 hover:text-gray-300 border border-transparent'
              }`}
            >
              {item.label}
              {item.badge > 0 && (
                <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[9px] font-bold w-4 h-4 rounded-full flex items-center justify-center">
                  {item.badge > 9 ? '9+' : item.badge}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-3 sm:hidden">
          <div className="flex gap-1">
            {navItems.map(item => (
              <button
                key={item.key}
                onClick={() => onNavigate?.(item.view)}
                className={`relative text-xs px-2 py-1 rounded transition-colors ${
                  view === item.view
                    ? 'text-accent-cyan'
                    : 'text-gray-600'
                }`}
              >
                {item.label.split(' ')[0]}
                {item.badge > 0 && (
                  <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[8px] font-bold w-3 h-3 rounded-full flex items-center justify-center">
                    !
                  </span>
                )}
              </button>
            ))}
          </div>
          <a
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden sm:block text-xs text-gray-500 hover:text-accent-cyan transition-colors"
          >
            NVD ↗
          </a>
          <button
            onClick={() => setDark(d => !d)}
            className="btn-ghost text-xs px-3 py-1.5"
            aria-label="Toggle theme"
          >
            {dark ? '☀ Light' : '🌙 Dark'}
          </button>
        </div>

        <div className="hidden sm:flex items-center gap-3">
          <a
            href="https://nvd.nist.gov/"
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-gray-500 hover:text-accent-cyan transition-colors"
          >
            NVD ↗
          </a>
          <button
            onClick={() => setDark(d => !d)}
            className="btn-ghost text-xs px-3 py-1.5"
            aria-label="Toggle theme"
          >
            {dark ? '☀ Light' : '🌙 Dark'}
          </button>
        </div>
      </div>
    </header>
  )
}
