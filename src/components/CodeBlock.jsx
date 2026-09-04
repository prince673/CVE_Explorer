import { useState } from 'react'
import { PrismLight as SyntaxHighlighter } from 'react-syntax-highlighter'
import bash from 'react-syntax-highlighter/dist/esm/languages/prism/bash'
import python from 'react-syntax-highlighter/dist/esm/languages/prism/python'

SyntaxHighlighter.registerLanguage('bash', bash)
SyntaxHighlighter.registerLanguage('python', python)

// Minimal prism theme that matches our dark palette
const darkTheme = {
  'code[class*="language-"]': {
    color: '#7dd3fc',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: '0.8rem',
    lineHeight: '1.6',
    whiteSpace: 'pre',
  },
  'token.comment':    { color: '#64748b', fontStyle: 'italic' },
  'token.keyword':    { color: '#c084fc' },
  'token.string':     { color: '#86efac' },
  'token.number':     { color: '#fb923c' },
  'token.operator':   { color: '#f59e0b' },
  'token.function':   { color: '#60a5fa' },
  'token.punctuation':{ color: '#94a3b8' },
}

function detectLang(code) {
  if (/import\s|def\s|pickle\.|class\s/.test(code)) return 'python'
  return 'bash'
}

export default function CodeBlock({ code }) {
  const [copied, setCopied] = useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback — silently fail
    }
  }

  const lang = detectLang(code)

  return (
    <div className="relative mt-2 rounded-lg border border-dark-border overflow-hidden group">
      <SyntaxHighlighter
        language={lang}
        style={darkTheme}
        customStyle={{
          margin: 0,
          padding: '0.75rem 1rem',
          background: '#0a0d14',
          borderRadius: 0,
        }}
        wrapLongLines={false}
      >
        {code}
      </SyntaxHighlighter>

      {/* Copy button */}
      <button
        onClick={handleCopy}
        aria-label="Copy command"
        className="absolute top-2 right-2
                   bg-dark-border hover:bg-dark-card2
                   text-gray-400 hover:text-accent-cyan
                   border border-dark-border/50
                   rounded px-2 py-0.5 text-xs font-medium
                   transition-all duration-200
                   opacity-0 group-hover:opacity-100"
      >
        {copied ? '✓ Copied' : 'Copy'}
      </button>
    </div>
  )
}
