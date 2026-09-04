import { useState } from 'react'

const CVE_REGEX = /^CVE-\d{4}-\d{4,}$/i

export default function InputForm({ onSubmit, loading }) {
  const [value,  setValue]  = useState('CVE-2021-44228')
  const [error,  setError]  = useState('')

  function handleSubmit(e) {
    e?.preventDefault()
    const trimmed = value.trim().toUpperCase()
    if (!CVE_REGEX.test(trimmed)) {
      setError('Please enter a valid CVE ID (format: CVE-YYYY-NNNNN)')
      return
    }
    setError('')
    onSubmit(trimmed)
  }

  return (
    <div className="card dark:bg-gradient-to-br dark:from-dark-bg3 dark:to-dark-card mb-6">

      {/* Heading */}
      <h1 className="text-2xl md:text-3xl font-extrabold mb-1
                     bg-gradient-to-r from-accent-cyan to-accent-purple
                     bg-clip-text text-transparent">
        CVE Vulnerability Explorer
      </h1>
      <p className="text-gray-400 text-sm mb-5">
        Enter a CVE ID to fetch vulnerability details and an educational exploitation guide.
      </p>

      {/* Form */}
      <form onSubmit={handleSubmit} noValidate>
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            className="input-field"
            value={value}
            onChange={e => { setValue(e.target.value); setError('') }}
            onKeyDown={e => e.key === 'Enter' && handleSubmit()}
            placeholder="e.g. CVE-2021-44228"
            spellCheck={false}
            autoComplete="off"
            aria-label="CVE ID input"
          />
          <button
            type="submit"
            disabled={loading}
            className="btn-primary shrink-0"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="w-4 h-4 border-2 border-white/30 border-t-white
                                 rounded-full animate-spin-slow" />
                Fetching…
              </span>
            ) : 'Fetch Details'}
          </button>
        </div>

        {error && (
          <p role="alert" className="mt-2 text-red-400 text-sm flex items-center gap-1">
            <span>⚠</span> {error}
          </p>
        )}
      </form>

      {/* Quick-try sample CVEs */}
      <div className="mt-4 flex flex-wrap gap-2">
        <span className="text-xs text-gray-500">Try:</span>
        {['CVE-2021-44228', 'CVE-2017-0144', 'CVE-2019-0708', 'CVE-2021-41773'].map(id => (
          <button
            key={id}
            onClick={() => { setValue(id); setError('') }}
            className="text-xs font-mono text-accent-cyan hover:underline"
          >
            {id}
          </button>
        ))}
      </div>
    </div>
  )
}
