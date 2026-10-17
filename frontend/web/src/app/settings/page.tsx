'use client'

/**
 * Settings — read-only configuration display and system info.
 *
 * Displays:
 * - Current API and infrastructure URLs
 * - Polling intervals for each data type
 * - Version and build info
 *
 * This page is purely informational — no writes or mutations.
 * All values come from constants.ts and environment variables.
 */

import { motion } from 'framer-motion'
import {
  Clock,
  Code2,
  ExternalLink,
  Globe,
  Info,
  Layers,
  Radio,
  Server,
  Shield,
  Timer,
} from 'lucide-react'

import {
  API_BASE_URL,
  GRAFANA_URL,
  POLL_AGENT_HEALTH_MS,
  POLL_STATS_MS,
  POLL_DETECTIONS_MS,
  POLL_INCIDENTS_MS,
  POLL_METRICS_MS,
  POLL_SERVICES_MS,
  DEFAULT_PAGE_SIZE,
  MAX_EVENT_BUFFER,
  SSE_RECONNECT_DELAY_MS,
} from '@/lib/constants'

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
// Config data
// ---------------------------------------------------------------------------

const CONNECTIONS = [
  { label: 'API Bridge', value: API_BASE_URL, icon: Globe },
  { label: 'Grafana', value: GRAFANA_URL, icon: ExternalLink },
]

const POLLING_INTERVALS = [
  { label: 'Agent Health', interval: POLL_AGENT_HEALTH_MS, icon: Radio },
  { label: 'Dashboard Stats', interval: POLL_STATS_MS, icon: Layers },
  { label: 'Detections', interval: POLL_DETECTIONS_MS, icon: Shield },
  { label: 'Incidents', interval: POLL_INCIDENTS_MS, icon: Shield },
  { label: 'Agent Metrics', interval: POLL_METRICS_MS, icon: Timer },
  { label: 'Service Status', interval: POLL_SERVICES_MS, icon: Server },
]

function formatInterval(ms: number): string {
  if (ms >= 60_000) return `${ms / 60_000}m`
  return `${ms / 1_000}s`
}

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function SettingsPage() {
  return (
    <motion.div
      variants={stagger}
      initial="hidden"
      animate="show"
      className="space-y-6 max-w-4xl"
    >
      {/* Header */}
      <motion.div variants={fadeUp}>
        <h2 className="text-xl font-bold text-white">Settings</h2>
        <p className="text-sm text-sentinel-muted">
          System configuration and connection details (read-only)
        </p>
      </motion.div>

      {/* Connection Endpoints */}
      <motion.div
        variants={fadeUp}
        className="rounded-xl border border-sentinel-border bg-sentinel-card p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Globe className="h-4 w-4 text-sentinel-muted" />
          Connection Endpoints
        </h3>
        <div className="space-y-3">
          {CONNECTIONS.map((conn) => {
            const Icon = conn.icon
            return (
              <div
                key={conn.label}
                className="flex items-center justify-between rounded-lg bg-sentinel-bg p-3 border border-sentinel-border"
              >
                <div className="flex items-center gap-3">
                  <Icon className="h-4 w-4 text-sentinel-muted" />
                  <span className="text-sm text-sentinel-muted">{conn.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <code className="text-xs font-mono text-white bg-sentinel-card px-2 py-1 rounded border border-sentinel-border">
                    {conn.value}
                  </code>
                  <a
                    href={conn.value}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="rounded-lg p-1.5 text-sentinel-muted hover:text-white hover:bg-sentinel-card transition-colors"
                    title={`Open ${conn.label}`}
                  >
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              </div>
            )
          })}
        </div>
      </motion.div>

      {/* Polling Intervals */}
      <motion.div
        variants={fadeUp}
        className="rounded-xl border border-sentinel-border bg-sentinel-card p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Clock className="h-4 w-4 text-sentinel-muted" />
          Polling Intervals
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {POLLING_INTERVALS.map((item) => {
            const Icon = item.icon
            return (
              <div
                key={item.label}
                className="flex items-center justify-between rounded-lg bg-sentinel-bg p-3 border border-sentinel-border"
              >
                <div className="flex items-center gap-2">
                  <Icon className="h-3.5 w-3.5 text-sentinel-muted" />
                  <span className="text-xs text-sentinel-muted">{item.label}</span>
                </div>
                <span className="text-xs font-mono font-semibold text-white">
                  {formatInterval(item.interval)}
                </span>
              </div>
            )
          })}
        </div>
      </motion.div>

      {/* Data Settings */}
      <motion.div
        variants={fadeUp}
        className="rounded-xl border border-sentinel-border bg-sentinel-card p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Layers className="h-4 w-4 text-sentinel-muted" />
          Data Settings
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
            <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
              Page Size
            </p>
            <p className="text-sm font-bold font-mono text-white">{DEFAULT_PAGE_SIZE}</p>
          </div>
          <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
            <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
              Event Buffer
            </p>
            <p className="text-sm font-bold font-mono text-white">{MAX_EVENT_BUFFER}</p>
          </div>
          <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
            <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
              SSE Reconnect
            </p>
            <p className="text-sm font-bold font-mono text-white">
              {formatInterval(SSE_RECONNECT_DELAY_MS)}
            </p>
          </div>
        </div>
      </motion.div>

      {/* About */}
      <motion.div
        variants={fadeUp}
        className="rounded-xl border border-sentinel-border/50 bg-sentinel-bg p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
          <Info className="h-4 w-4 text-sentinel-muted" />
          About SentinelMesh
        </h3>
        <div className="space-y-3 text-xs text-sentinel-muted">
          <p className="leading-relaxed">
            SentinelMesh is a multi-agent collaborative network security system using
            Deep Packet Inspection (DPI) and flow-based behavioral analysis. Seven
            independent agents communicate over Kafka to correlatively detect multi-stage
            threats that no single agent could detect alone.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
            <div className="rounded-lg bg-sentinel-card p-3 border border-sentinel-border">
              <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
                Version
              </p>
              <p className="text-sm font-semibold text-white">1.0.0</p>
            </div>
            <div className="rounded-lg bg-sentinel-card p-3 border border-sentinel-border">
              <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
                Framework
              </p>
              <p className="text-sm font-semibold text-white">Next.js 15</p>
            </div>
            <div className="rounded-lg bg-sentinel-card p-3 border border-sentinel-border">
              <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
                Agents
              </p>
              <p className="text-sm font-semibold text-white">7</p>
            </div>
            <div className="rounded-lg bg-sentinel-card p-3 border border-sentinel-border">
              <p className="text-[10px] uppercase tracking-wider text-sentinel-muted mb-1">
                Kafka Topics
              </p>
              <p className="text-sm font-semibold text-white">6</p>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Tech Stack */}
      <motion.div
        variants={fadeUp}
        className="rounded-xl border border-sentinel-border bg-sentinel-card p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <Code2 className="h-4 w-4 text-sentinel-muted" />
          Technology Stack
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          {[
            { label: 'Frontend', items: ['Next.js 15', 'React 19', 'TypeScript', 'Tailwind CSS'] },
            { label: 'Backend', items: ['Python 3.12', 'FastAPI', 'Scapy', 'Kafka-python'] },
            { label: 'Infrastructure', items: ['Kafka (KRaft)', 'Redis 7', 'PostgreSQL 16', 'Docker'] },
            { label: 'Observability', items: ['Prometheus', 'Grafana', 'Structured logging', 'Health checks'] },
          ].map((group) => (
            <div key={group.label}>
              <p className="font-medium text-white mb-2">{group.label}</p>
              <ul className="space-y-1 text-sentinel-muted">
                {group.items.map((item) => (
                  <li key={item} className="flex items-center gap-1.5">
                    <span className="h-1 w-1 rounded-full bg-sentinel-primary flex-shrink-0" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </motion.div>
    </motion.div>
  )
}
