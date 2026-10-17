'use client'

/**
 * Dashboard — primary overview page for SentinelMesh.
 *
 * Displays:
 * - Stat cards (total detections, open incidents, active agents, flows/sec)
 * - Classification breakdown donut chart (benign/suspicious/malicious)
 * - Recent incidents table
 * - Agent health grid
 *
 * This is the main demo surface. All data auto-refreshes via hooks.
 */

import { motion } from 'framer-motion'
import {
  Activity,
  AlertTriangle,
  Bot,
  Eye,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  Label,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from 'recharts'

import { useStats } from '@/hooks/useStats'
import { useAgentHealth } from '@/hooks/useAgentHealth'
import { useIncidents } from '@/hooks/useIncidents'
import { useDetections } from '@/hooks/useDetections'

import { MetricCard } from '@/components/shared/MetricCard'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { HealthIndicator } from '@/components/shared/HealthIndicator'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { ErrorCard } from '@/components/shared/ErrorCard'
import { EmptyState } from '@/components/shared/EmptyState'

import { CLASSIFICATION_COLORS, SEVERITY_COLORS, THEME } from '@/lib/constants'
import {
  formatRelativeTime,
  formatIncidentType,
  formatNumber,
  formatConfidence,
} from '@/lib/formatters'
import type { Classification } from '@/types'

// ---------------------------------------------------------------------------
// Animation variants
// ---------------------------------------------------------------------------

const stagger = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08 },
  },
}

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4 } },
}

// ---------------------------------------------------------------------------
// Classification chart data builder
// ---------------------------------------------------------------------------

function buildChartData(byClass: Record<Classification, number> | undefined) {
  if (!byClass) return []
  return [
    { name: 'Benign', value: byClass.benign ?? 0, color: CLASSIFICATION_COLORS.benign },
    { name: 'Suspicious', value: byClass.suspicious ?? 0, color: CLASSIFICATION_COLORS.suspicious },
    { name: 'Malicious', value: byClass.malicious ?? 0, color: CLASSIFICATION_COLORS.malicious },
  ].filter((d) => d.value > 0)
}

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const stats = useStats()
  const agents = useAgentHealth()
  const incidents = useIncidents({ limit: 5 })
  const detections = useDetections({ limit: 5 })

  // Aggregate error
  const anyError = stats.error || agents.error
  const isLoading = stats.isLoading && agents.isLoading

  if (isLoading) {
    return (
      <div className="space-y-6">
        <LoadingSkeleton variant="card" count={4} className="grid grid-cols-4 gap-4" />
        <LoadingSkeleton variant="card" count={2} />
      </div>
    )
  }

  const chartData = buildChartData(stats.data?.detections_by_classification)

  return (
    <motion.div
      variants={stagger}
      initial="hidden"
      animate="show"
      className="space-y-6"
    >
      {/* ---- Error banner ---- */}
      {anyError && (
        <ErrorCard
          title="Data fetch error"
          message={anyError}
        />
      )}

      {/* ---- Stat Cards ---- */}
      <motion.div variants={fadeUp} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Detections"
          value={stats.data?.total_detections}
          icon={Eye}
          color={THEME.cyan}
          subtitle="All time"
        />
        <MetricCard
          title="Open Incidents"
          value={stats.data?.open_incidents}
          icon={AlertTriangle}
          color={THEME.warning}
          subtitle="Requiring attention"
        />
        <MetricCard
          title="Active Agents"
          value={stats.data?.active_agents}
          icon={Bot}
          color={THEME.success}
          subtitle="Reporting healthy"
        />
        <MetricCard
          title="Latest Detections"
          value={detections.data?.total}
          icon={Zap}
          color={THEME.primary}
          subtitle="In pipeline"
        />
      </motion.div>

      {/* ---- Middle row: Chart + Agent Health ---- */}
      <motion.div variants={fadeUp} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Classification Chart */}
        <div className="lg:col-span-1 rounded-xl border border-sentinel-border bg-sentinel-card p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Traffic Classification</h2>
          {chartData.length === 0 ? (
            <EmptyState message="No detection data yet" icon={ShieldCheck} />
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={4}
                  dataKey="value"
                  stroke="none"
                >
                  {chartData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                  {/* Center label showing total */}
                  <Label
                    position="center"
                    content={({ viewBox }) => {
                      const total = chartData.reduce((sum, d) => sum + d.value, 0)
                      const { cx, cy } = viewBox as { cx: number; cy: number }
                      return (
                        <g>
                          <text
                            x={cx}
                            y={cy - 6}
                            textAnchor="middle"
                            dominantBaseline="central"
                            className="fill-white text-xl font-bold"
                          >
                            {formatNumber(total)}
                          </text>
                          <text
                            x={cx}
                            y={cy + 14}
                            textAnchor="middle"
                            dominantBaseline="central"
                            className="fill-sentinel-muted text-[10px] uppercase tracking-wider"
                          >
                            Total
                          </text>
                        </g>
                      )
                    }}
                  />
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#1F2937',
                    border: '1px solid #374151',
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                  itemStyle={{ color: '#fff' }}
                />
                <Legend
                  verticalAlign="bottom"
                  iconType="circle"
                  iconSize={8}
                  formatter={(value: string) => (
                    <span className="text-xs text-sentinel-muted">{value}</span>
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Agent Health Grid */}
        <div className="lg:col-span-2 rounded-xl border border-sentinel-border bg-sentinel-card p-5">
          <h2 className="text-sm font-semibold text-white mb-4">Agent Health</h2>
          {agents.error ? (
            <ErrorCard title="Cannot reach health endpoint" message={agents.error} />
          ) : !agents.data || agents.data.length === 0 ? (
            <EmptyState message="No agents reporting" icon={Bot} />
          ) : (
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-4 gap-3">
              {agents.data.map((agent) => (
                <motion.div
                  key={agent.agent_name}
                  whileHover={{ y: -2 }}
                  className="rounded-lg border border-sentinel-border bg-sentinel-bg p-4 transition-all hover:border-sentinel-border-hover"
                >
                  <div className="flex items-center gap-2 mb-3">
                    <HealthIndicator status={agent.status} size={8} />
                    <span className="text-xs font-medium text-white capitalize">
                      {agent.agent_name}
                    </span>
                  </div>
                  <div className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-sentinel-muted">Throughput</span>
                      <span className="text-white font-mono">
                        {formatNumber(agent.throughput_last_interval)}/s
                      </span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-sentinel-muted">Queue</span>
                      <span className="text-white font-mono">
                        {formatNumber(agent.queue_depth)}
                      </span>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </motion.div>

      {/* ---- Recent Incidents ---- */}
      <motion.div variants={fadeUp} className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white">Recent Incidents</h2>
          <a
            href="/incidents"
            className="text-xs text-sentinel-primary hover:text-sentinel-primary-hover transition-colors"
          >
            View all →
          </a>
        </div>
        {incidents.error ? (
          <ErrorCard title="Failed to load incidents" message={incidents.error} />
        ) : !incidents.data || incidents.data.items.length === 0 ? (
          <EmptyState message="No incidents detected — system is clean" icon={ShieldCheck} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-sentinel-border text-sentinel-muted">
                  <th className="pb-3 pr-4 font-medium">Type</th>
                  <th className="pb-3 pr-4 font-medium">Source IP</th>
                  <th className="pb-3 pr-4 font-medium">Severity</th>
                  <th className="pb-3 pr-4 font-medium">Status</th>
                  <th className="pb-3 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {incidents.data.items.map((inc) => (
                  <tr
                    key={inc.incident_id}
                    className="border-b border-sentinel-border/50 hover:bg-sentinel-card-hover/30 transition-colors"
                  >
                    <td className="py-3 pr-4">
                      <a
                        href={`/incidents/${inc.incident_id}`}
                        className="text-white hover:text-sentinel-primary transition-colors font-medium"
                      >
                        {formatIncidentType(inc.incident_type)}
                      </a>
                    </td>
                    <td className="py-3 pr-4 font-mono text-sentinel-muted">
                      {inc.src_ip ?? '—'}
                    </td>
                    <td className="py-3 pr-4">
                      <StatusBadge value={inc.severity} type="severity" />
                    </td>
                    <td className="py-3 pr-4">
                      <StatusBadge value={inc.status} type="status" />
                    </td>
                    <td className="py-3 text-sentinel-muted">
                      {formatRelativeTime(inc.timestamp_updated)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>

      {/* ---- Recent Detections ---- */}
      <motion.div variants={fadeUp} className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold text-white">Recent Detections</h2>
          <a
            href="/events"
            className="text-xs text-sentinel-primary hover:text-sentinel-primary-hover transition-colors"
          >
            View all →
          </a>
        </div>
        {detections.error ? (
          <ErrorCard title="Failed to load detections" message={detections.error} />
        ) : !detections.data || detections.data.items.length === 0 ? (
          <EmptyState message="No detections yet — waiting for traffic" icon={Activity} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-sentinel-border text-sentinel-muted">
                  <th className="pb-3 pr-4 font-medium">Flow ID</th>
                  <th className="pb-3 pr-4 font-medium">Classification</th>
                  <th className="pb-3 pr-4 font-medium">Confidence</th>
                  <th className="pb-3 pr-4 font-medium">Attack Type</th>
                  <th className="pb-3 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {detections.data.items.map((det) => (
                  <tr
                    key={det.detection_id}
                    className="border-b border-sentinel-border/50 hover:bg-sentinel-card-hover/30 transition-colors"
                  >
                    <td className="py-3 pr-4 font-mono text-sentinel-muted text-[11px]">
                      {det.flow_id.slice(0, 8)}…
                    </td>
                    <td className="py-3 pr-4">
                      <StatusBadge value={det.classification} type="classification" />
                    </td>
                    <td className="py-3 pr-4 font-mono text-white">
                      {formatConfidence(det.confidence)}
                    </td>
                    <td className="py-3 pr-4 text-white">
                      {det.attack_type ? formatIncidentType(det.attack_type) : '—'}
                    </td>
                    <td className="py-3 text-sentinel-muted">
                      {formatRelativeTime(det.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>
    </motion.div>
  )
}
