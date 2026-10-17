'use client'

/**
 * HealthIndicator — pulsing dot indicator for agent health status.
 *
 * Renders a small colored circle that pulses for 'healthy' status
 * and remains static for 'down' status. Used in agent cards and
 * architecture nodes.
 *
 * @param status - Agent health status
 * @param size - Dot size in pixels
 */

import { AGENT_STATUS_COLORS } from '@/lib/constants'
import type { AgentStatus } from '@/types'
import { motion } from 'framer-motion'

interface HealthIndicatorProps {
  /** Agent health status. */
  status: AgentStatus
  /** Dot diameter in pixels. */
  size?: number
}

export function HealthIndicator({ status, size = 10 }: HealthIndicatorProps) {
  const color = AGENT_STATUS_COLORS[status]
  const shouldPulse = status === 'healthy'

  return (
    <span className="relative inline-flex" aria-label={`Status: ${status}`}>
      {shouldPulse && (
        <motion.span
          className="absolute inline-flex rounded-full opacity-75"
          style={{
            width: size,
            height: size,
            backgroundColor: color,
          }}
          animate={{ scale: [1, 1.5, 1], opacity: [0.75, 0, 0.75] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'easeInOut' }}
        />
      )}
      <span
        className="relative inline-flex rounded-full"
        style={{
          width: size,
          height: size,
          backgroundColor: color,
        }}
      />
    </span>
  )
}
