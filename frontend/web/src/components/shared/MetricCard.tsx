'use client'

/**
 * MetricCard — displays a single metric with title, value, and optional icon.
 *
 * Used on the Dashboard page for stat cards (total detections, open incidents, etc.).
 * Handles null/undefined values by rendering EmptyState behavior.
 *
 * @param title - Metric label
 * @param value - Numeric value to display (null/undefined renders a dash)
 * @param icon - Optional Lucide icon component
 * @param color - Optional accent color for the icon
 * @param subtitle - Optional subtitle text
 */

import { type LucideIcon } from 'lucide-react'
import { motion } from 'framer-motion'
import { formatNumber } from '@/lib/formatters'

interface MetricCardProps {
  /** Metric label displayed above the value. */
  title: string
  /** Numeric value. Shows "—" when null/undefined. */
  value: number | null | undefined
  /** Optional Lucide icon. */
  icon?: LucideIcon
  /** Optional accent color for the icon. */
  color?: string
  /** Optional subtitle below the value. */
  subtitle?: string
}

export function MetricCard({ title, value, icon: Icon, color, subtitle }: MetricCardProps) {
  const displayValue = value !== null && value !== undefined ? formatNumber(value) : '—'

  return (
    <motion.div
      whileHover={{ y: -2 }}
      className="rounded-xl border border-sentinel-border bg-sentinel-card p-5 transition-all hover:border-sentinel-border-hover hover:shadow-lg"
    >
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-sentinel-muted uppercase tracking-wider">
          {title}
        </p>
        {Icon && (
          <div
            className="rounded-lg p-2"
            style={{ backgroundColor: color ? `${color}15` : undefined }}
          >
            <Icon className="h-4 w-4" style={{ color: color ?? '#9CA3AF' }} />
          </div>
        )}
      </div>
      <p className="mt-3 text-2xl font-bold text-white tracking-tight">
        {displayValue}
      </p>
      {subtitle && (
        <p className="mt-1 text-xs text-sentinel-muted">{subtitle}</p>
      )}
    </motion.div>
  )
}
