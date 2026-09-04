/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      colors: {
        dark: {
          bg:    '#0a0d14',
          bg2:   '#111520',
          bg3:   '#161b2e',
          card:  '#1a2035',
          card2: '#1e2640',
          border:'#2a3450',
        },
        accent: {
          cyan:   '#00d4ff',
          purple: '#7c3aed',
          amber:  '#f59e0b',
        },
      },
      animation: {
        'fade-up': 'fadeUp 0.35s ease both',
        'spin-slow': 'spin 1s linear infinite',
      },
      keyframes: {
        fadeUp: {
          from: { opacity: 0, transform: 'translateY(12px)' },
          to:   { opacity: 1, transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
