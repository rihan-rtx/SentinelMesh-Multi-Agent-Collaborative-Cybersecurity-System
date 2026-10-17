'use client'

/**
 * Architecture — interactive system architecture visualization.
 *
 * Shows the SentinelMesh 7-agent pipeline as a visual flow diagram
 * with live health status indicators on each node. Uses Framer Motion
 * for animated interactions and SVG arrows for data-flow connections.
 *
 * Agent nodes are arranged in a 3-row grid. SVG arrows connect them
 * based on Kafka topic flows, drawn with animated dashed lines.
 */

import { useRef, useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import {
  ArrowRight,
  Database,
  Gauge,
  Radio,
  Search,
  Shield,
  ShieldAlert,
  Target,
  Workflow,
} from 'lucide-react'

import { useAgentHealth } from '@/hooks/useAgentHealth'
import { HealthIndicator } from '@/components/shared/HealthIndicator'
import { THEME } from '@/lib/constants'
import type { AgentStatus } from '@/types'

// ---------------------------------------------------------------------------
// Agent node definitions for the architecture diagram
// ---------------------------------------------------------------------------

interface AgentNode {
  id: string
  label: string
  description: string
  icon: React.ElementType
  consumes: string[]
  produces: string[]
  color: string
}

const AGENT_NODES: AgentNode[] = [
  {
    id: 'sniffer',
    label: 'Sniffer Agent',
    description: 'Packet capture (live/pcap), flow assembly by 5-tuple',
    icon: Radio,
    consumes: ['Raw NIC / pcap'],
    produces: ['flow-events'],
    color: THEME.cyan,
  },
  {
    id: 'dpi',
    label: 'DPI Agent',
    description: '5 signatures + entropy anomaly detection on payloads',
    icon: Search,
    consumes: ['flow-events'],
    produces: ['dpi-findings'],
    color: '#A78BFA',
  },
  {
    id: 'detection',
    label: 'Detection Agent',
    description: 'Rule-based classification: benign / suspicious / malicious',
    icon: ShieldAlert,
    consumes: ['flow-events', 'dpi-findings'],
    produces: ['detections'],
    color: THEME.warning,
  },
  {
    id: 'coordinator',
    label: 'Coordinator Agent',
    description: 'Health checks, agent registration, restart signals',
    icon: Shield,
    consumes: ['health pings'],
    produces: ['agent status'],
    color: THEME.primary,
  },
  {
    id: 'correlation',
    label: 'Correlation Agent',
    description: 'Time-windowed cross-signal aggregation, Redis-backed',
    icon: Workflow,
    consumes: ['detections', 'dpi-findings', 'flow-events'],
    produces: ['incidents'],
    color: THEME.danger,
  },
  {
    id: 'response',
    label: 'Response Agent',
    description: 'Decide log_only / alert per incident, audit trail',
    icon: Target,
    consumes: ['incidents'],
    produces: ['actions'],
    color: THEME.success,
  },
  {
    id: 'dashboard-writer',
    label: 'Dashboard Writer',
    description: 'Kafka → PostgreSQL persistence for dashboard queries',
    icon: Database,
    consumes: ['detections', 'incidents', 'actions'],
    produces: ['PostgreSQL rows'],
    color: '#F472B6',
  },
]

// Kafka topic flow connections
const CONNECTIONS: { from: string; to: string; topic: string; color: string }[] = [
  { from: 'sniffer', to: 'dpi', topic: 'flow-events', color: THEME.cyan },
  { from: 'sniffer', to: 'detection', topic: 'flow-events', color: THEME.cyan },
  { from: 'dpi', to: 'detection', topic: 'dpi-findings', color: '#A78BFA' },
  { from: 'detection', to: 'correlation', topic: 'detections', color: THEME.warning },
  { from: 'dpi', to: 'correlation', topic: 'dpi-findings', color: '#A78BFA' },
  { from: 'correlation', to: 'response', topic: 'incidents', color: THEME.danger },
  { from: 'detection', to: 'dashboard-writer', topic: 'detections', color: THEME.warning },
  { from: 'correlation', to: 'dashboard-writer', topic: 'incidents', color: THEME.danger },
  { from: 'response', to: 'dashboard-writer', topic: 'actions', color: THEME.success },
]

// ---------------------------------------------------------------------------
// Arrow drawing helpers
// ---------------------------------------------------------------------------

interface Rect {
  x: number
  y: number
  width: number
  height: number
}

/**
 * Compute a curved SVG path between two node rects.
 * Chooses the best exit/entry edges based on relative positions.
 */
function computeArrowPath(fromRect: Rect, toRect: Rect): string {
  const fromCx = fromRect.x + fromRect.width / 2
  const fromCy = fromRect.y + fromRect.height / 2
  const toCx = toRect.x + toRect.width / 2
  const toCy = toRect.y + toRect.height / 2

  const dx = toCx - fromCx
  const dy = toCy - fromCy

  let startX: number, startY: number, endX: number, endY: number

  // Determine exit and entry points
  if (Math.abs(dx) > Math.abs(dy)) {
    // Horizontal dominant — exit right/left
    if (dx > 0) {
      startX = fromRect.x + fromRect.width
      startY = fromCy
      endX = toRect.x
      endY = toCy
    } else {
      startX = fromRect.x
      startY = fromCy
      endX = toRect.x + toRect.width
      endY = toCy
    }
  } else {
    // Vertical dominant — exit bottom/top
    if (dy > 0) {
      startX = fromCx
      startY = fromRect.y + fromRect.height
      endX = toCx
      endY = toRect.y
    } else {
      startX = fromCx
      startY = fromRect.y
      endX = toCx
      endY = toRect.y + toRect.height
    }
  }

  // Cubic bezier with control points for smooth curves
  const cpOffset = Math.min(Math.abs(endX - startX), Math.abs(endY - startY)) * 0.5 + 20
  let cp1x: number, cp1y: number, cp2x: number, cp2y: number

  if (Math.abs(dx) > Math.abs(dy)) {
    cp1x = startX + (dx > 0 ? cpOffset : -cpOffset)
    cp1y = startY
    cp2x = endX + (dx > 0 ? -cpOffset : cpOffset)
    cp2y = endY
  } else {
    cp1x = startX
    cp1y = startY + (dy > 0 ? cpOffset : -cpOffset)
    cp2x = endX
    cp2y = endY + (dy > 0 ? -cpOffset : cpOffset)
  }

  return `M ${startX} ${startY} C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${endX} ${endY}`
}

// ---------------------------------------------------------------------------
// FlowArrows SVG overlay component
// ---------------------------------------------------------------------------

function FlowArrows({
  containerRef,
  nodeRefs,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>
  nodeRefs: React.MutableRefObject<Map<string, HTMLDivElement>>
}) {
  const [paths, setPaths] = useState<{ path: string; color: string; topic: string }[]>([])

  const updatePaths = useCallback(() => {
    const container = containerRef.current
    if (!container) return

    const containerRect = container.getBoundingClientRect()
    const newPaths: { path: string; color: string; topic: string }[] = []

    for (const conn of CONNECTIONS) {
      const fromEl = nodeRefs.current.get(conn.from)
      const toEl = nodeRefs.current.get(conn.to)
      if (!fromEl || !toEl) continue

      const fromBr = fromEl.getBoundingClientRect()
      const toBr = toEl.getBoundingClientRect()

      const fromRect: Rect = {
        x: fromBr.left - containerRect.left,
        y: fromBr.top - containerRect.top,
        width: fromBr.width,
        height: fromBr.height,
      }
      const toRect: Rect = {
        x: toBr.left - containerRect.left,
        y: toBr.top - containerRect.top,
        width: toBr.width,
        height: toBr.height,
      }

      newPaths.push({
        path: computeArrowPath(fromRect, toRect),
        color: conn.color,
        topic: conn.topic,
      })
    }

    setPaths(newPaths)
  }, [containerRef, nodeRefs])

  useEffect(() => {
    // Initial calculation + recalc on resize
    const timer = setTimeout(updatePaths, 100)
    window.addEventListener('resize', updatePaths)
    return () => {
      clearTimeout(timer)
      window.removeEventListener('resize', updatePaths)
    }
  }, [updatePaths])

  if (paths.length === 0) return null

  return (
    <svg
      className="absolute inset-0 w-full h-full pointer-events-none z-0"
      style={{ overflow: 'visible' }}
    >
      <defs>
        {/* Arrowhead marker for each connection color */}
        {[...new Set(CONNECTIONS.map((c) => c.color))].map((color) => (
          <marker
            key={color}
            id={`arrowhead-${color.replace('#', '')}`}
            markerWidth="8"
            markerHeight="6"
            refX="7"
            refY="3"
            orient="auto"
          >
            <polygon points="0 0, 8 3, 0 6" fill={color} opacity="0.7" />
          </marker>
        ))}
      </defs>

      {paths.map((p, i) => (
        <g key={i}>
          {/* Glow effect */}
          <path
            d={p.path}
            fill="none"
            stroke={p.color}
            strokeWidth="3"
            opacity="0.1"
            strokeLinecap="round"
          />
          {/* Main line */}
          <path
            d={p.path}
            fill="none"
            stroke={p.color}
            strokeWidth="1.5"
            opacity="0.5"
            strokeDasharray="6 4"
            strokeLinecap="round"
            markerEnd={`url(#arrowhead-${p.color.replace('#', '')})`}
          >
            <animate
              attributeName="stroke-dashoffset"
              from="20"
              to="0"
              dur="1.5s"
              repeatCount="indefinite"
            />
          </path>
        </g>
      ))}
    </svg>
  )
}

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

const fadeUp = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.5 } },
}

export default function ArchitecturePage() {
  const { data: agents, isLoading } = useAgentHealth()

  const containerRef = useRef<HTMLDivElement>(null)
  const nodeRefs = useRef<Map<string, HTMLDivElement>>(new Map())

  const setNodeRef = useCallback((id: string, el: HTMLDivElement | null) => {
    if (el) {
      nodeRefs.current.set(id, el)
    } else {
      nodeRefs.current.delete(id)
    }
  }, [])

  // Build a lookup map: agent_name → status
  const healthMap = new Map<string, AgentStatus>()
  if (agents) {
    agents.forEach((a) => healthMap.set(a.agent_name, a.status))
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div
        variants={fadeUp}
        initial="hidden"
        animate="show"
      >
        <h2 className="text-xl font-bold text-white mb-1">System Architecture</h2>
        <p className="text-sm text-sentinel-muted">
          SentinelMesh multi-agent pipeline — 7 agents communicating over Kafka topics,
          with Redis-backed sliding windows and PostgreSQL persistence.
          <span className="ml-2 text-sentinel-muted/60 text-xs">
            Dashed lines show Kafka topic data flows between agents.
          </span>
        </p>
      </motion.div>

      {/* Architecture Grid with SVG overlay */}
      <div className="relative" ref={containerRef}>
        {/* SVG flow arrows — drawn on top of everything, pointer-events none */}
        <FlowArrows containerRef={containerRef} nodeRefs={nodeRefs} />

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-4 relative z-10"
        >
          {AGENT_NODES.map((node, index) => {
            const status = healthMap.get(node.id)
            const Icon = node.icon

            return (
              <motion.div
                key={node.id}
                ref={(el) => setNodeRef(node.id, el)}
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.1, duration: 0.4 }}
                whileHover={{ y: -4, scale: 1.02 }}
                className="group relative rounded-xl border border-sentinel-border bg-sentinel-card p-5 transition-all hover:border-sentinel-border-hover hover:shadow-lg cursor-default"
              >
                {/* Glow accent line at top */}
                <div
                  className="absolute top-0 left-4 right-4 h-0.5 rounded-full opacity-60 group-hover:opacity-100 transition-opacity"
                  style={{ backgroundColor: node.color }}
                />

                <div className="flex items-start gap-3">
                  <div
                    className="flex-shrink-0 rounded-lg p-2.5"
                    style={{ backgroundColor: `${node.color}15` }}
                  >
                    <Icon className="h-5 w-5" style={{ color: node.color }} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-sm font-semibold text-white">{node.label}</h3>
                      {status && <HealthIndicator status={status} size={8} />}
                      {isLoading && (
                        <span className="h-2 w-2 rounded-full bg-sentinel-muted animate-pulse" />
                      )}
                    </div>
                    <p className="text-xs text-sentinel-muted leading-relaxed">
                      {node.description}
                    </p>
                  </div>
                </div>

                {/* Topics */}
                <div className="mt-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-wider text-sentinel-muted font-medium">
                      Consumes
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {node.consumes.map((t) => (
                        <span
                          key={t}
                          className="rounded-md bg-sentinel-bg px-2 py-0.5 text-[10px] font-mono text-sentinel-muted border border-sentinel-border"
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-wider text-sentinel-muted font-medium">
                      Produces
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {node.produces.map((t) => (
                        <span
                          key={t}
                          className="rounded-md px-2 py-0.5 text-[10px] font-mono border"
                          style={{
                            backgroundColor: `${node.color}10`,
                            borderColor: `${node.color}30`,
                            color: node.color,
                          }}
                        >
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </motion.div>
      </div>

      {/* Data Flow Legend */}
      <motion.div
        variants={fadeUp}
        initial="hidden"
        animate="show"
        transition={{ delay: 0.8 }}
        className="rounded-xl border border-sentinel-border bg-sentinel-card p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-4">Kafka Topic Flow</h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {CONNECTIONS.map((conn, i) => (
            <div
              key={i}
              className="flex items-center gap-2 text-xs text-sentinel-muted"
            >
              <span className="font-medium text-white capitalize">{conn.from}</span>
              <ArrowRight className="h-3 w-3 flex-shrink-0" style={{ color: conn.color }} />
              <span
                className="font-mono text-[11px] bg-sentinel-bg px-1.5 py-0.5 rounded border border-sentinel-border"
                style={{ color: conn.color }}
              >
                {conn.topic}
              </span>
              <ArrowRight className="h-3 w-3 flex-shrink-0" style={{ color: conn.color }} />
              <span className="font-medium text-white capitalize">{conn.to}</span>
            </div>
          ))}
        </div>
      </motion.div>

      {/* Infrastructure note */}
      <motion.div
        variants={fadeUp}
        initial="hidden"
        animate="show"
        transition={{ delay: 1.0 }}
        className="rounded-xl border border-sentinel-border/50 bg-sentinel-bg p-5"
      >
        <h3 className="text-sm font-semibold text-white mb-2 flex items-center gap-2">
          <Gauge className="h-4 w-4 text-sentinel-muted" />
          Infrastructure
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs text-sentinel-muted">
          <div>
            <p className="font-medium text-white">Message Bus</p>
            <p>Kafka (KRaft mode)</p>
          </div>
          <div>
            <p className="font-medium text-white">State Store</p>
            <p>Redis 7 (sliding windows)</p>
          </div>
          <div>
            <p className="font-medium text-white">Dashboard DB</p>
            <p>PostgreSQL 16</p>
          </div>
          <div>
            <p className="font-medium text-white">Monitoring</p>
            <p>Prometheus + Grafana</p>
          </div>
        </div>
      </motion.div>
    </div>
  )
}
