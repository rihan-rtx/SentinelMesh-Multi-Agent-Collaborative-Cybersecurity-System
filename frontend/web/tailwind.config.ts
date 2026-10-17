import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        sentinel: {
          bg: '#0B1120',
          card: '#111827',
          'card-hover': '#1F2937',
          primary: '#2563EB',
          'primary-hover': '#3B82F6',
          success: '#22C55E',
          warning: '#F59E0B',
          danger: '#EF4444',
          cyan: '#22D3EE',
          muted: '#9CA3AF',
          border: '#1F2937',
          'border-hover': '#374151',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'shimmer': 'shimmer 2s linear infinite',
        'slide-in': 'slide-in 0.3s ease-out',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.5' },
        },
        'shimmer': {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
        'slide-in': {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
      boxShadow: {
        'glow-green': '0 0 15px rgba(34, 197, 94, 0.3)',
        'glow-red': '0 0 15px rgba(239, 68, 68, 0.3)',
        'glow-amber': '0 0 15px rgba(245, 158, 11, 0.3)',
        'glow-blue': '0 0 15px rgba(37, 99, 235, 0.3)',
        'glow-cyan': '0 0 15px rgba(34, 211, 238, 0.3)',
      },
    },
  },
  plugins: [],
}

export default config
