'use client'

/**
 * NavigationSidebar — collapsible sidebar with navigation items.
 *
 * Features:
 * - Collapse/expand toggle with spring animation (desktop)
 * - Active route highlighting
 * - Icon-only mode when collapsed
 * - Mobile overlay with backdrop (< lg breakpoint)
 * - SentinelMesh branding at top
 *
 * State is lifted to PageShell for content margin coordination.
 */

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import {
  LayoutDashboard,
  Network,
  Bot,
  Activity,
  AlertTriangle,
  Monitor,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
  X,
} from 'lucide-react'
import { NAV_ITEMS } from '@/lib/constants'

const iconMap: Record<string, React.ElementType> = {
  LayoutDashboard,
  Network,
  Bot,
  Activity,
  AlertTriangle,
  Monitor,
  Settings,
}

interface NavigationSidebarProps {
  /** Whether the sidebar is collapsed (icon-only mode). */
  collapsed: boolean
  /** Toggle collapsed state. */
  onToggleCollapse: () => void
  /** Whether the mobile overlay sidebar is open. */
  mobileOpen: boolean
  /** Close the mobile overlay. */
  onCloseMobile: () => void
}

export function NavigationSidebar({
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
}: NavigationSidebarProps) {
  const pathname = usePathname()

  const sidebarContent = (
    <>
      {/* Branding */}
      <div className="flex h-16 items-center gap-3 px-4 border-b border-sentinel-border flex-shrink-0">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sentinel-primary flex-shrink-0">
          <Shield className="h-4 w-4 text-white" />
        </div>
        <AnimatePresence>
          {!collapsed && (
            <motion.span
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="text-sm font-bold text-white whitespace-nowrap"
            >
              SentinelMesh
            </motion.span>
          )}
        </AnimatePresence>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = iconMap[item.icon]
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/')

          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={onCloseMobile}
              className={`
                flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all
                ${isActive
                  ? 'bg-sentinel-primary/10 text-sentinel-primary-hover border border-sentinel-primary/20'
                  : 'text-sentinel-muted hover:bg-sentinel-card hover:text-white border border-transparent'
                }
              `}
            >
              {Icon && <Icon className="h-4 w-4 flex-shrink-0" />}
              <AnimatePresence>
                {!collapsed && (
                  <motion.span
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="whitespace-nowrap"
                  >
                    {item.label}
                  </motion.span>
                )}
              </AnimatePresence>
            </Link>
          )
        })}
      </nav>

      {/* Collapse toggle — desktop only */}
      <div className="hidden lg:block border-t border-sentinel-border p-2 flex-shrink-0">
        <button
          onClick={onToggleCollapse}
          className="flex w-full items-center justify-center rounded-lg p-2 text-sentinel-muted transition-colors hover:bg-sentinel-card hover:text-white"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </button>
      </div>
    </>
  )

  return (
    <>
      {/* Desktop sidebar — fixed, visible on lg+ */}
      <motion.aside
        animate={{ width: collapsed ? 72 : 240 }}
        transition={{ type: 'spring', stiffness: 300, damping: 30 }}
        className="fixed left-0 top-0 z-40 hidden lg:flex h-screen flex-col border-r border-sentinel-border bg-sentinel-bg"
      >
        {sidebarContent}
      </motion.aside>

      {/* Mobile overlay — visible on < lg when mobileOpen is true */}
      <AnimatePresence>
        {mobileOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={onCloseMobile}
              className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
            />

            {/* Sidebar drawer */}
            <motion.aside
              initial={{ x: -280 }}
              animate={{ x: 0 }}
              exit={{ x: -280 }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
              className="fixed left-0 top-0 z-50 flex h-screen w-[280px] flex-col border-r border-sentinel-border bg-sentinel-bg lg:hidden"
            >
              {/* Close button for mobile */}
              <button
                onClick={onCloseMobile}
                className="absolute top-4 right-4 rounded-lg p-1.5 text-sentinel-muted hover:bg-sentinel-card hover:text-white transition-colors"
                aria-label="Close sidebar"
              >
                <X className="h-4 w-4" />
              </button>
              {sidebarContent}
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </>
  )
}
