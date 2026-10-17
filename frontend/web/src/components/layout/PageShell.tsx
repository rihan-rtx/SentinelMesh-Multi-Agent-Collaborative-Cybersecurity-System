'use client'

/**
 * PageShell — main content wrapper with sidebar and top bar.
 *
 * Manages sidebar collapse state centrally so the content area
 * margin can respond to sidebar width changes. On mobile (< lg),
 * the sidebar becomes an overlay with a backdrop — no content offset.
 */

import { useState, useCallback, useEffect } from 'react'
import { NavigationSidebar } from './NavigationSidebar'
import { TopBar } from './TopBar'

interface PageShellProps {
  children: React.ReactNode
}

/** Sidebar width constants — must match NavigationSidebar */
const SIDEBAR_EXPANDED = 240
const SIDEBAR_COLLAPSED = 72

/**
 * Hook to detect if the viewport matches a min-width media query.
 * Returns false during SSR and true once client-side hydration confirms
 * the viewport is >= the breakpoint.
 */
function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false)

  useEffect(() => {
    const mql = window.matchMedia(query)
    setMatches(mql.matches)
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches)
    mql.addEventListener('change', handler)
    return () => mql.removeEventListener('change', handler)
  }, [query])

  return matches
}

export function PageShell({ children }: PageShellProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const isDesktop = useMediaQuery('(min-width: 1024px)')

  const toggleCollapse = useCallback(() => setCollapsed((c) => !c), [])
  const toggleMobile = useCallback(() => setMobileOpen((o) => !o), [])
  const closeMobile = useCallback(() => setMobileOpen(false), [])

  // On desktop: dynamic margin matching sidebar width.
  // On mobile: no margin — sidebar is an overlay.
  const contentMargin = isDesktop
    ? collapsed ? SIDEBAR_COLLAPSED : SIDEBAR_EXPANDED
    : 0

  return (
    <div className="min-h-screen bg-sentinel-bg text-white">
      <NavigationSidebar
        collapsed={collapsed}
        onToggleCollapse={toggleCollapse}
        mobileOpen={mobileOpen}
        onCloseMobile={closeMobile}
      />

      {/* Main content area */}
      <div
        className="transition-[margin-left] duration-300 ease-in-out"
        style={{ marginLeft: `${contentMargin}px` }}
      >
        <TopBar onToggleMobile={toggleMobile} />
        <main className="p-4 sm:p-6">
          {children}
        </main>
      </div>
    </div>
  )
}
