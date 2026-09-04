export default function ConfidenceBadge({ confidence, label, size = 'sm' }) {
  let color = 'text-gray-400 bg-gray-500/15 border-gray-600'
  if (confidence >= 80) color = 'text-green-400 bg-green-500/15 border-green-500/40'
  else if (confidence >= 50) color = 'text-yellow-400 bg-yellow-500/15 border-yellow-500/40'
  else if (confidence >= 30) color = 'text-orange-400 bg-orange-500/15 border-orange-500/40'
  else color = 'text-red-400 bg-red-500/15 border-red-500/40'

  const sizeClasses = size === 'lg' ? 'text-sm px-3 py-1' : 'text-xs px-2 py-0.5'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-semibold border ${color} ${sizeClasses}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {label || `${confidence}% confidence`}
    </span>
  )
}
