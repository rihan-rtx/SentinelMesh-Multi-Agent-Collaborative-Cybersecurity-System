'use client'

/**
 * TopBar — top navigation bar with page title and status indicators.
 *
 * Displays the current page title, a live connection status dot,
 * and a hamburger menu button for mobile sidebar toggle.
 */

import { usePathname } from 'next/navigation'
import { Menu } from 'lucide-react'
import { NAV_ITEMS } from '@/lib/constants'

interface TopBarProps {
  /** Callback to toggle mobile sidebar. */
  onToggleMobile: () => void
}

export function TopBar({ onToggleMobile }: TopBarProps) {
  const pathname = usePathname()

  const currentPage = NAV_ITEMS.find(
    (item) => pathname === item.href || pathname.startsWith(item.href + '/')
  )
  const pageTitle = currentPage?.label ?? 'Dashboard'

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-sentinel-border bg-sentinel-bg/80 backdrop-blur-md px-4 sm:px-6">
      <div className="flex items-center gap-3">
        {/* Hamburger — mobile only */}
        <button
          onClick={onToggleMobile}
          className="rounded-lg p-2 text-sentinel-muted hover:bg-sentinel-card hover:text-white transition-colors lg:hidden"
          aria-label="Toggle navigation"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div>
          <h1 className="text-lg font-semibold text-white">{pageTitle}</h1>
          <p className="text-xs text-sentinel-muted hidden sm:block">SentinelMesh Network Security Platform</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-sentinel-success opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-sentinel-success" />
          </span>
          <span className="text-xs text-sentinel-muted">Live</span>
        </div>
      </div>
    </header>
  )
}
