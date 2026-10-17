'use client'

/**
 * StatusBadge — colored badge for status, severity, and classification values.
 *
 * Renders a small pill with color-coded background matching the value type.
 * Works for agent status, incident severity, and detection classification.
 *
 * @param value - The status/severity/classification value
 * @param type - Badge type: 'status', 'severity', or 'classification'
 */

import { AGENT_STATUS_COLORS, SEVERITY_COLORS, CLASSIFICATION_COLORS } from '@/lib/constants'
import { capitalize } from '@/lib/formatters'

type BadgeType = 'status' | 'severity' | 'classification'

interface StatusBadgeProps {
  /** The value to display (e.g., 'healthy', 'critical', 'malicious'). */
  value: string
  /** Badge color scheme type. */
  type?: BadgeType
}

const colorMaps: Record<BadgeType, Record<string, string>> = {
  status: AGENT_STATUS_COLORS,
  severity: SEVERITY_COLORS,
  classification: CLASSIFICATION_COLORS,
}

export function StatusBadge({ value, type = 'status' }: StatusBadgeProps) {
  const colorMap = colorMaps[type]
  const color = colorMap[value] ?? '#9CA3AF'

  return (
    <span
      className="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium"
      style={{
        backgroundColor: `${color}15`,
        color: color,
        border: `1px solid ${color}30`,
      }}
    >
      {value.split('_').map(w => capitalize(w)).join(' ')}
    </span>
  )
}
