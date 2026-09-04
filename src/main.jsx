import { StrictMode } from 'react'
import { createRoot }  from 'react-dom/client'
import './index.css'
import App from './App.jsx'

// Apply saved dark/light theme before first paint to avoid flash
const savedTheme = localStorage.getItem('cve_theme')
if (!savedTheme || savedTheme === 'dark') {
  document.documentElement.classList.add('dark')
} else {
  document.documentElement.classList.remove('dark')
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
)
