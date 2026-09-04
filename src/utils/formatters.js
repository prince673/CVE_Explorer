/**
 * Format a date string to a human-readable locale string.
 */
export function formatDate(str) {
  if (!str) return '—'
  try {
    return new Date(str).toLocaleDateString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
    })
  } catch {
    return str
  }
}

/**
 * Return severity label and Tailwind color classes based on CVSS score.
 */
export function getSeverity(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return { label: 'Unknown', bg: 'bg-gray-700/40', text: 'text-gray-400', border: 'border-gray-600', bar: '#6b7280' }
  if (n >= 9.0) return { label: 'Critical', bg: 'bg-red-500/15',    text: 'text-red-400',    border: 'border-red-500/40',    bar: '#ef4444' }
  if (n >= 7.0) return { label: 'High',     bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/40', bar: '#f97316' }
  if (n >= 4.0) return { label: 'Medium',   bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/40', bar: '#eab308' }
  return        { label: 'Low',      bg: 'bg-green-500/15',  text: 'text-green-400',  border: 'border-green-500/40',  bar: '#10b981' }
}

/**
 * Clamp CVSS to a 0-100 percentage value for progress bars.
 */
export function cvssPercent(score) {
  const n = parseFloat(score)
  if (isNaN(n)) return 0
  return Math.min(n * 10, 100)
}
