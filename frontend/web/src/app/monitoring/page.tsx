'use client'

/**
 * Monitoring — infrastructure service status and Grafana dashboard embed.
 *
 * Displays:
 * - Service connectivity cards for all infrastructure services
 *   (Kafka, Redis, PostgreSQL, Prometheus, Grafana) using useServices hook
 * - Grafana dashboard iframe with graceful fallback if Grafana is unreachable
 *
 * All data is read-only, fetched from the API bridge's /api/services endpoint.
 */

import { useState } from 'react'
import { motion } from 'framer-motion'
import {
  Activity,
  AlertCircle,
  CheckCircle2,
  Database,
  ExternalLink,
  Gauge,
  Globe,
  Radio,
  Server,
  XCircle,
} from 'lucide-react'

import { useServices } from '@/hooks/useServices'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { ErrorCard } from '@/components/shared/ErrorCard'
import { EmptyState } from '@/components/shared/EmptyState'

import { GRAFANA_URL, THEME } from '@/lib/constants'
import { formatLatency, formatRelativeTime } from '@/lib/formatters'
import type { ServiceName } from '@/types'

// ---------------------------------------------------------------------------
// Service metadata
// ---------------------------------------------------------------------------

const SERVICE_META: Record<string, {
  icon: React.ElementType
  color: string
  description: string
}> = {
  kafka: {
    icon: Radio,
    color: THEME.cyan,
    description: 'Message bus for inter-agent communication',
  },
  redis: {
    icon: Database,
    color: '#EF4444',
    description: 'Sliding window state store for correlation',
  },
  postgres: {
    icon: Database,
    color: '#3B82F6',
    description: 'Dashboard persistence layer',
  },
  prometheus: {
    icon: Gauge,
    color: '#F97316',
    description: 'Agent metrics collection',
  },
  grafana: {
    icon: Activity,
    color: '#22C55E',
    description: 'Metrics visualization dashboards',
  },
  zookeeper: {
    icon: Server,
    color: '#A78BFA',
    description: 'Kafka coordination service',
  },
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

export default function MonitoringPage() {
  const services = useServices()
  const [grafanaError, setGrafanaError] = useState(false)

  if (services.isLoading) {
    return (
      <div className="space-y-4">
        <LoadingSkeleton variant="card" count={6} />
      </div>
    )
  }

  if (services.error) {
    return <ErrorCard title="Failed to load service status" message={services.error} />
  }

  // Summary counts
  const reachableCount = services.data?.filter((s) => s.reachable).length ?? 0
  const totalCount = services.data?.length ?? 0
  const unreachableCount = totalCount - reachableCount

  // Check if Grafana is reachable
  const grafanaService = services.data?.find((s) => s.name === 'grafana')
  const grafanaReachable = grafanaService?.reachable && !grafanaError

  return (
    <motion.div
      variants={stagger}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* Header */}
      <motion.div variants={fadeUp}>
        <h2 className="text-xl font-bold text-white">Monitoring</h2>
        <p className="text-sm text-sentinel-muted">
          Infrastructure service connectivity and observability dashboards
        </p>
      </motion.div>

      {/* Summary bar */}
      <motion.div variants={fadeUp} className="flex flex-wrap gap-3">
        <div className="flex items-center gap-2 rounded-lg border border-sentinel-border bg-sentinel-card px-4 py-2">
          <Server className="h-4 w-4 text-sentinel-muted" />
          <span className="text-sm text-sentinel-muted">Services</span>
          <span className="text-sm font-bold text-white">{totalCount}</span>
        </div>
        <div className="flex items-center gap-2 rounded-lg border border-green-500/20 bg-green-500/5 px-4 py-2">
          <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />
          <span className="text-sm text-green-400">Reachable</span>
          <span className="text-sm font-bold text-white">{reachableCount}</span>
        </div>
        {unreachableCount > 0 && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-2">
            <XCircle className="h-3.5 w-3.5 text-red-400" />
            <span className="text-sm text-red-400">Unreachable</span>
            <span className="text-sm font-bold text-white">{unreachableCount}</span>
          </div>
        )}
      </motion.div>

      {/* Service Cards */}
      {!services.data || services.data.length === 0 ? (
        <EmptyState message="No infrastructure services detected" icon={Server} />
      ) : (
        <motion.div
          variants={fadeUp}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4"
        >
          {services.data.map((service, idx) => {
            const meta = SERVICE_META[service.name] ?? {
              icon: Globe,
              color: '#9CA3AF',
              description: 'Unknown service',
            }
            const Icon = meta.icon

            return (
              <motion.div
                key={service.name}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.06 }}
                whileHover={{ y: -3 }}
                className="group relative rounded-xl border border-sentinel-border bg-sentinel-card p-5 transition-all hover:border-sentinel-border-hover hover:shadow-lg"
              >
                {/* Accent line */}
                <div
                  className="absolute top-0 left-4 right-4 h-0.5 rounded-full opacity-50 group-hover:opacity-100 transition-opacity"
                  style={{ backgroundColor: meta.color }}
                />

                {/* Header */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div
                      className="rounded-lg p-2"
                      style={{ backgroundColor: `${meta.color}15` }}
                    >
                      <Icon className="h-4 w-4" style={{ color: meta.color }} />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-white capitalize">
                        {service.name}
                      </h3>
                      <p className="text-[11px] text-sentinel-muted">{meta.description}</p>
                    </div>
                  </div>
                  {/* Status indicator */}
                  <div className="flex items-center gap-1.5">
                    {service.reachable ? (
                      <CheckCircle2 className="h-4 w-4 text-green-400" />
                    ) : (
                      <AlertCircle className="h-4 w-4 text-red-400" />
                    )}
                  </div>
                </div>

                {/* Metrics */}
                <div className="grid grid-cols-2 gap-2">
                  <div className="rounded-lg bg-sentinel-bg p-2.5 border border-sentinel-border">
                    <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-0.5">
                      Status
                    </p>
                    <p className={`text-xs font-semibold ${service.reachable ? 'text-green-400' : 'text-red-400'}`}>
                      {service.reachable ? 'Reachable' : 'Unreachable'}
                    </p>
                  </div>
                  <div className="rounded-lg bg-sentinel-bg p-2.5 border border-sentinel-border">
                    <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-0.5">
                      Latency
                    </p>
                    <p className="text-xs font-semibold font-mono text-white">
                      {formatLatency(service.latency_ms)}
                    </p>
                  </div>
                </div>

                {/* Last checked */}
                <p className="mt-2.5 text-[11px] text-sentinel-muted">
                  Checked {formatRelativeTime(service.last_checked)}
                </p>
              </motion.div>
            )
          })}
        </motion.div>
      )}

      {/* Grafana Dashboard Embed */}
      <motion.div
        variants={fadeUp}
        className="rounded-xl border border-sentinel-border bg-sentinel-card overflow-hidden"
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-sentinel-border">
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-green-400" />
            <h3 className="text-sm font-semibold text-white">Grafana Dashboard</h3>
          </div>
          <a
            href={GRAFANA_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 rounded-lg border border-sentinel-border bg-sentinel-bg px-3 py-1.5 text-xs text-sentinel-muted hover:text-white hover:border-sentinel-border-hover transition-colors"
          >
            Open in Grafana
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>

        {grafanaReachable ? (
          <div className="relative w-full" style={{ height: '500px' }}>
            <iframe
              src={`${GRAFANA_URL}/d/sentinelmesh/overview?orgId=1&refresh=10s&kiosk`}
              className="absolute inset-0 w-full h-full border-0"
              title="Grafana Dashboard"
              onError={() => setGrafanaError(true)}
            />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
            <div className="rounded-full bg-sentinel-bg p-4 mb-4 border border-sentinel-border">
              <Activity className="h-8 w-8 text-sentinel-muted" />
            </div>
            <p className="text-sm text-sentinel-muted mb-1">
              {grafanaError
                ? 'Could not load the Grafana dashboard'
                : 'Grafana is not reachable'
              }
            </p>
            <p className="text-xs text-sentinel-muted/60 mb-4 max-w-sm">
              Ensure Grafana is running at{' '}
              <span className="font-mono text-sentinel-muted">{GRAFANA_URL}</span>{' '}
              and the SentinelMesh dashboard is provisioned.
            </p>
            <a
              href={GRAFANA_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 rounded-lg bg-sentinel-primary px-4 py-2 text-xs font-medium text-white transition-colors hover:bg-sentinel-primary-hover"
            >
              Try opening Grafana
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        )}
      </motion.div>
    </motion.div>
  )
}
