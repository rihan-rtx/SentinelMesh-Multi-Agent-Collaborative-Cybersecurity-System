'use client'

/**
 * ErrorCard — displays an error state with optional retry button.
 *
 * Used throughout the dashboard when an API call fails or a service is unavailable.
 * Renders a styled alert card with an error message and optional retry action.
 *
 * @param title - Error title (e.g., "Database unavailable")
 * @param message - Optional detailed error message
 * @param onRetry - Optional callback to retry the failed operation
 */

import { AlertCircle, RefreshCw } from 'lucide-react'
import { motion } from 'framer-motion'

interface ErrorCardProps {
  /** Error title displayed prominently. */
  title: string
  /** Optional detailed error message. */
  message?: string
  /** Optional retry callback. If provided, renders a retry button. */
  onRetry?: () => void
}

export function ErrorCard({ title, message, onRetry }: ErrorCardProps) {
  return (
    <motion.div
      role="alert"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl border border-red-500/20 bg-red-500/5 p-6"
    >
      <div className="flex items-start gap-3">
        <AlertCircle className="h-5 w-5 text-red-400 mt-0.5 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-red-400">{title}</h3>
          {message && (
            <p className="mt-1 text-sm text-red-300/70">{message}</p>
          )}
        </div>
        {onRetry && (
          <button
            onClick={onRetry}
            className="flex items-center gap-1.5 rounded-lg bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/20"
          >
            <RefreshCw className="h-3 w-3" />
            Retry
          </button>
        )}
      </div>
    </motion.div>
  )
}
