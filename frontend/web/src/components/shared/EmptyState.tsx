'use client'

/**
 * EmptyState — displays a placeholder when no data is available.
 *
 * Shows an icon, message, and optional action button when an
 * endpoint returns zero rows.
 *
 * @param message - Description of the empty state
 * @param icon - Optional Lucide icon component
 * @param action - Optional action button configuration
 */

import { Inbox, type LucideIcon } from 'lucide-react'
import { motion } from 'framer-motion'

interface EmptyStateProps {
  /** Message displayed below the icon. */
  message: string
  /** Optional Lucide icon component to display. */
  icon?: LucideIcon
  /** Optional action button. */
  action?: {
    label: string
    onClick: () => void
  }
}

export function EmptyState({ message, icon: Icon = Inbox, action }: EmptyStateProps) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="flex flex-col items-center justify-center py-12 px-6 text-center"
    >
      <div className="rounded-full bg-sentinel-card p-4 mb-4">
        <Icon className="h-8 w-8 text-sentinel-muted" />
      </div>
      <p className="text-sm text-sentinel-muted max-w-xs">{message}</p>
      {action && (
        <button
          onClick={action.onClick}
          className="mt-4 rounded-lg bg-sentinel-primary px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-sentinel-primary-hover"
        >
          {action.label}
        </button>
      )}
    </motion.div>
  )
}
