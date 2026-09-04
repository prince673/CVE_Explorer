import { getAllGuideTypes } from '../utils/guideEngine'

const COLORS = {
  sqli: 'text-amber-400', xss: 'text-pink-400', rce: 'text-red-400',
  traversal: 'text-orange-400', lfi: 'text-orange-500', cmdinj: 'text-red-500',
  deser: 'text-purple-400', ssrf: 'text-cyan-400', xxe: 'text-blue-400',
  idor: 'text-green-400', redirect: 'text-yellow-400', ssti: 'text-fuchsia-400',
  jwt: 'text-indigo-400', csrf: 'text-teal-400', fileupload: 'text-rose-400',
  generic: 'text-gray-400',
}

export default function GuideTypesPanel() {
  const types = getAllGuideTypes()

  return (
    <div className="card mb-6 dark:bg-gradient-to-br dark:from-dark-bg3 dark:to-dark-card">
      <div className="flex items-center gap-2 mb-4">
        <span className="text-lg">📚</span>
        <h2 className="font-bold text-base text-white">Supported Vulnerability Types</h2>
        <span className="ml-auto tag bg-accent-purple/20 text-purple-300 border-accent-purple/40 text-xs">
          {types.length} guides
        </span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
        {types.map(({ key, name }) => (
          <div key={key}
               className="flex items-center gap-2 px-3 py-2 rounded-lg
                          bg-dark-bg/60 border border-dark-border/50
                          hover:border-dark-border transition-colors">
            <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${(COLORS[key] || 'text-gray-400').replace('text-', 'bg-')}`} />
            <span className={`text-xs font-medium truncate ${COLORS[key] || 'text-gray-400'}`}>
              {name}
            </span>
          </div>
        ))}
      </div>

      <p className="mt-3 text-xs text-gray-600">
        Guide type is auto-detected from CWE IDs and CVE description keywords.
      </p>
    </div>
  )
}
