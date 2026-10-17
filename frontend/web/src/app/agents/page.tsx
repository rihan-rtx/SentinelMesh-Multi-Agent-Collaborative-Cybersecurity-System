'use client'

/**
 * Agents — per-agent health status and throughput metrics.
 *
 * Displays a card for each agent with:
 * - Live health indicator (healthy/degraded/down)
 * - Throughput (events/sec)
 * - Queue depth
 * - Last ping timestamp
 *
 * Optionally shows Prometheus metrics (events consumed/produced, latency).
 */

import { motion } from 'framer-motion'
import {
  Activity,
  Bot,
  Clock,
  Layers,
  Radio,
  Search,
  Shield,
  ShieldAlert,
  Target,
  Workflow,
  Database,
  Zap,
} from 'lucide-react'

import { useAgentHealth } from '@/hooks/useAgentHealth'
import { useMetrics } from '@/hooks/useMetrics'

import { HealthIndicator } from '@/components/shared/HealthIndicator'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { ErrorCard } from '@/components/shared/ErrorCard'
import { EmptyState } from '@/components/shared/EmptyState'

import { AGENT_STATUS_COLORS, THEME } from '@/lib/constants'
import { formatNumber, formatRelativeTime, formatLatency } from '@/lib/formatters'
import type { AgentMetrics } from '@/types'

// ---------------------------------------------------------------------------
// Agent metadata
// ---------------------------------------------------------------------------

const AGENT_META: Record<string, { icon: React.ElementType; color: string; role: string }> = {
  sniffer: { icon: Radio, color: THEME.cyan, role: 'Packet capture & flow assembly' },
  dpi: { icon: Search, color: '#A78BFA', role: 'Payload inspection & signatures' },
  detection: { icon: ShieldAlert, color: THEME.warning, role: 'Flow classification engine' },
  correlation: { icon: Workflow, color: THEME.danger, role: 'Cross-signal incident correlation' },
  response: { icon: Target, color: THEME.success, role: 'Incident response & audit log' },
  coordinator: { icon: Shield, color: THEME.primary, role: 'Health monitoring & orchestration' },
  'dashboard-writer': { icon: Database, color: '#F472B6', role: 'Kafka → PostgreSQL persistence' },
}

// ---------------------------------------------------------------------------
// Animation
// ---------------------------------------------------------------------------

const stagger = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { staggerChildren: 0.08 } },
}

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4 } },
}

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function AgentsPage() {
  const health = useAgentHealth()
  const metrics = useMetrics()

  // Merge metrics by agent name for lookup
  const metricsMap = new Map<string, AgentMetrics>()
  if (metrics.data) {
    metrics.data.forEach((m) => metricsMap.set(m.agent, m))
  }

  if (health.isLoading) {
    return (
      <div className="space-y-4">
        <LoadingSkeleton variant="card" count={7} className="max-w-md" />
      </div>
    )
  }

  if (health.error) {
    return <ErrorCard title="Failed to load agent health" message={health.error} />
  }

  if (!health.data || health.data.length === 0) {
    return <EmptyState message="No agents are currently reporting health data" icon={Bot} />
  }

  // Summary stats
  const total = health.data.length
  const healthyCount = health.data.filter((a) => a.status === 'healthy').length
  const degradedCount = health.data.filter((a) => a.status === 'degraded').length
  const downCount = health.data.filter((a) => a.status === 'down').length

  return (
    <motion.div
      variants={stagger}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* Summary bar */}
      <motion.div variants={fadeUp} className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2 rounded-lg border border-sentinel-border bg-sentinel-card px-4 py-2">
          <Bot className="h-4 w-4 text-sentinel-muted" />
          <span className="text-sm text-sentinel-muted">Total</span>
          <span className="text-sm font-bold text-white">{total}</span>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-green-500/20 bg-green-500/5 px-4 py-2">
          <span className="h-2 w-2 rounded-full bg-green-500" />
          <span className="text-sm text-green-400">Healthy</span>
          <span className="text-sm font-bold text-white">{healthyCount}</span>
        </div>
        {degradedCount > 0 && (
          <div className="flex items-center gap-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-2">
            <span className="h-2 w-2 rounded-full bg-amber-500" />
            <span className="text-sm text-amber-400">Degraded</span>
            <span className="text-sm font-bold text-white">{degradedCount}</span>
          </div>
        )}
        {downCount > 0 && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-2">
            <span className="h-2 w-2 rounded-full bg-red-500" />
            <span className="text-sm text-red-400">Down</span>
            <span className="text-sm font-bold text-white">{downCount}</span>
          </div>
        )}
      </motion.div>

      {/* Agent Cards */}
      <motion.div variants={fadeUp} className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {health.data.map((agent) => {
          const meta = AGENT_META[agent.agent_name] ?? {
            icon: Bot,
            color: '#9CA3AF',
            role: 'Unknown agent',
          }
          const Icon = meta.icon
          const agentMetrics = metricsMap.get(agent.agent_name)

          return (
            <motion.div
              key={agent.agent_name}
              whileHover={{ y: -3 }}
              className="group relative rounded-xl border border-sentinel-border bg-sentinel-card p-5 transition-all hover:border-sentinel-border-hover hover:shadow-lg"
            >
              {/* Top accent */}
              <div
                className="absolute top-0 left-4 right-4 h-0.5 rounded-full opacity-50 group-hover:opacity-100 transition-opacity"
                style={{ backgroundColor: meta.color }}
              />

              {/* Header */}
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div
                    className="rounded-lg p-2"
                    style={{ backgroundColor: `${meta.color}15` }}
                  >
                    <Icon className="h-4 w-4" style={{ color: meta.color }} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-white capitalize">
                      {agent.agent_name}
                    </h3>
                    <p className="text-[11px] text-sentinel-muted">{meta.role}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <HealthIndicator status={agent.status} size={10} />
                  <StatusBadge value={agent.status} type="status" />
                </div>
              </div>

              {/* Health metrics */}
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Zap className="h-3 w-3 text-sentinel-muted" />
                    <span className="text-[10px] uppercase tracking-wider text-sentinel-muted">
                      Throughput
                    </span>
                  </div>
                  <p className="text-sm font-bold font-mono text-white">
                    {formatNumber(agent.throughput_last_interval)}
                    <span className="text-[10px] text-sentinel-muted font-normal ml-0.5">/s</span>
                  </p>
                </div>

                <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Layers className="h-3 w-3 text-sentinel-muted" />
                    <span className="text-[10px] uppercase tracking-wider text-sentinel-muted">
                      Queue
                    </span>
                  </div>
                  <p className="text-sm font-bold font-mono text-white">
                    {formatNumber(agent.queue_depth)}
                  </p>
                </div>

                {agentMetrics && (
                  <>
                    <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
                      <div className="flex items-center gap-1.5 mb-1">
                        <Activity className="h-3 w-3 text-sentinel-muted" />
                        <span className="text-[10px] uppercase tracking-wider text-sentinel-muted">
                          Consumed
                        </span>
                      </div>
                      <p className="text-sm font-bold font-mono text-white">
                        {formatNumber(agentMetrics.events_consumed)}
                      </p>
                    </div>

                    <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
                      <div className="flex items-center gap-1.5 mb-1">
                        <Clock className="h-3 w-3 text-sentinel-muted" />
                        <span className="text-[10px] uppercase tracking-wider text-sentinel-muted">
                          Latency p50
                        </span>
                      </div>
                      <p className="text-sm font-bold font-mono text-white">
                        {formatLatency(agentMetrics.processing_latency_p50)}
                      </p>
                    </div>
                  </>
                )}
              </div>

              {/* Last seen */}
              <div className="mt-3 flex items-center gap-1 text-[11px] text-sentinel-muted">
                <Clock className="h-3 w-3" />
                Last ping: {formatRelativeTime(agent.timestamp)}
              </div>
            </motion.div>
          )
        })}
      </motion.div>
    </motion.div>
  )
}
