# CVE Explorer — React Frontend

A modern, multi-file React application for educational CVE vulnerability research.

## Features
- 🔍 Fetches CVE details from CIRCL API (primary) + NVD (fallback)
- 🧠 Rule-based guide engine mapping CWE → exploitation guide (8 types)
- 📋 Copy-to-clipboard for code blocks, CVE ID, and description
- 🌙 Dark / light theme with persistence
- 📱 Fully responsive (mobile-first)
- ⚠️ Mandatory disclaimer modal

## Quick Start

```bash
# Install dependencies
npm install

# Start dev server
npm run dev
# → http://localhost:5173

# Build for production
npm run build
```

## Project Structure

```
src/
├── components/        # React UI components
│   ├── DisclaimerModal.jsx
│   ├── Header.jsx
│   ├── InputForm.jsx
│   ├── VulnerabilityCard.jsx
│   ├── ExploitationGuide.jsx
│   ├── CodeBlock.jsx
│   ├── SeverityBadge.jsx
│   ├── LoadingSpinner.jsx
│   └── Footer.jsx
├── services/
│   └── cveApi.js      # CIRCL + NVD API integration
├── data/
│   └── guideTemplates.js   # 8 exploitation guide templates
├── utils/
│   ├── guideEngine.js # CWE/keyword → guide mapping
│   └── formatters.js  # Date, severity, CVSS helpers
├── App.jsx            # Root component + state
└── main.jsx           # Entry point
```

## Supported Guide Types
| CWE | Type |
|---|---|
| CWE-89 | SQL Injection |
| CWE-79 | Cross-Site Scripting |
| CWE-78 | OS Command Injection |
| CWE-22/23 | Path Traversal |
| CWE-98 | Local File Inclusion |
| CWE-502 | Insecure Deserialization |
| CWE-94 | Remote Code Execution |
| — | Generic (fallback) |

## Legal
**For authorized security research and education only.**
All commands use `[TARGET_URL]` / `[ATTACKER_IP]` placeholders.
Unauthorized use is illegal.
