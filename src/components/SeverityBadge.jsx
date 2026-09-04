import { getSeverity } from '../utils/formatters'

export default function SeverityBadge({ score }) {
  const s = getSeverity(score)
  return (
    <span className={`tag ${s.bg} ${s.text} ${s.border} text-xs uppercase`}>
      {s.label}
    </span>
  )
}
