import { useState } from 'react'

const AGREED_KEY = 'cve_explorer_agreed'

export default function DisclaimerModal({ onAgree }) {
  // Only show if not already agreed in this session
  const [visible, setVisible] = useState(() => !sessionStorage.getItem(AGREED_KEY))

  function handleAgree() {
    sessionStorage.setItem(AGREED_KEY, '1')
    setVisible(false)
    onAgree?.()
  }

  if (!visible) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4
                    bg-black/85 backdrop-blur-sm">
      <div className="bg-dark-card border border-dark-border rounded-2xl
                      max-w-lg w-full p-8 shadow-[0_8px_48px_rgba(0,0,0,0.6)]
                      animate-fade-up">

        {/* Icon + Title */}
        <div className="flex items-center gap-3 mb-5">
          <span className="text-3xl">⚠️</span>
          <h2 className="text-xl font-extrabold text-amber-400">
            Educational Use Only
          </h2>
        </div>

        <p className="text-gray-300 text-sm mb-4 leading-relaxed font-medium">
          This tool is intended <strong className="text-white">solely</strong> for
          authorized security research and education.
        </p>

        <ul className="text-gray-400 text-sm space-y-2 mb-5 list-none">
          {[
            'Only test systems you own or have explicit written permission to test',
            'Unauthorized access to computer systems is illegal (CFAA, Computer Misuse Act, etc.)',
            'Exploitation guides use placeholder targets — never run against live systems',
            'The developers assume no liability for misuse of this tool',
          ].map((item, i) => (
            <li key={i} className="flex items-start gap-2">
              <span className="text-accent-cyan mt-0.5 text-xs">▸</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>

        <p className="text-gray-500 text-xs mb-6 border-l-2 border-accent-amber pl-3">
          All commands use <code className="text-amber-300">[TARGET_URL]</code>,{' '}
          <code className="text-amber-300">[ATTACKER_IP]</code> placeholders and are
          for educational demonstration only.
        </p>

        <button
          onClick={handleAgree}
          className="btn-primary w-full text-center"
        >
          I Understand — Proceed to CVE Explorer
        </button>
      </div>
    </div>
  )
}
