'use client'

/**
 * Incident Detail — single incident view with actions timeline.
 *
 * Shows full incident details: type, severity, status, source IP,
 * related flow/detection IDs, and actions taken. Uses fetchIncidentDetail
 * for the nested actions array.
 */

import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import {
  AlertTriangle,
  ArrowLeft,
  Bell,
  BookOpen,
  Clock,
  FileText,
  Globe,
  Hash,
  Layers,
  Shield,
} from 'lucide-react'

import { fetchIncidentDetail } from '@/lib/api'

import { StatusBadge } from '@/components/shared/StatusBadge'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { ErrorCard } from '@/components/shared/ErrorCard'

import { SEVERITY_COLORS, THEME } from '@/lib/constants'
import {
  formatDateTime,
  formatRelativeTime,
  formatIncidentType,
  capitalize,
} from '@/lib/formatters'
import type { IncidentDetail } from '@/types'

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function IncidentDetailPage() {
  const params = useParams()
  const id = params.id as string

  const [incident, setIncident] = useState<IncidentDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const data = await fetchIncidentDetail(id)
      setIncident(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load incident')
    } finally {
      setIsLoading(false)
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  if (isLoading) {
    return (
      <div className="space-y-4">
        <LoadingSkeleton variant="card" count={3} />
      </div>
    )
  }

  if (error || !incident) {
    return (
      <div className="space-y-4">
        <a
          href="/incidents"
          className="inline-flex items-center gap-1.5 text-xs text-sentinel-muted hover:text-white transition-colors"
        >
          <ArrowLeft className="h-3 w-3" />
          Back to incidents
        </a>
        <ErrorCard
          title="Failed to load incident"
          message={error ?? 'Incident not found'}
          onRetry={load}
        />
      </div>
    )
  }

  const severityColor = SEVERITY_COLORS[incident.severity as keyof typeof SEVERITY_COLORS] ?? '#9CA3AF'

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      {/* Back link */}
      <a
        href="/incidents"
        className="inline-flex items-center gap-1.5 text-xs text-sentinel-muted hover:text-white transition-colors"
      >
        <ArrowLeft className="h-3 w-3" />
        Back to incidents
      </a>

      {/* Header card */}
      <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <div
              className="rounded-xl p-3"
              style={{ backgroundColor: `${severityColor}15` }}
            >
              <AlertTriangle className="h-6 w-6" style={{ color: severityColor }} />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">
                {formatIncidentType(incident.incident_type)}
              </h2>
              <p className="text-xs text-sentinel-muted mt-1 font-mono">
                {incident.incident_id}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <StatusBadge value={incident.severity} type="severity" />
            <StatusBadge value={incident.status} type="status" />
          </div>
        </div>

        {/* Detail grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6">
          <DetailItem
            icon={Globe}
            label="Source IP"
            value={incident.src_ip ?? 'N/A (distributed)'}
            mono
          />
          <DetailItem
            icon={Clock}
            label="Opened"
            value={formatDateTime(incident.timestamp_opened)}
          />
          <DetailItem
            icon={Clock}
            label="Last Updated"
            value={formatRelativeTime(incident.timestamp_updated)}
          />
          <DetailItem
            icon={Layers}
            label="Related Flows"
            value={String(incident.related_flow_ids?.length ?? 0)}
          />
        </div>
      </div>

      {/* Related IDs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Flow IDs */}
        <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Hash className="h-4 w-4 text-sentinel-muted" />
            Related Flow IDs
          </h3>
          {(!incident.related_flow_ids || incident.related_flow_ids.length === 0) ? (
            <p className="text-xs text-sentinel-muted">No related flows</p>
          ) : (
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {incident.related_flow_ids.map((fid) => (
                <div
                  key={fid}
                  className="rounded-md bg-sentinel-bg px-3 py-1.5 text-[11px] font-mono text-sentinel-muted border border-sentinel-border"
                >
                  {fid}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Detection IDs */}
        <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
          <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
            <Shield className="h-4 w-4 text-sentinel-muted" />
            Related Detection IDs
          </h3>
          {(!incident.related_detection_ids || incident.related_detection_ids.length === 0) ? (
            <p className="text-xs text-sentinel-muted">No related detections</p>
          ) : (
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {incident.related_detection_ids.map((did) => (
                <div
                  key={did}
                  className="rounded-md bg-sentinel-bg px-3 py-1.5 text-[11px] font-mono text-sentinel-muted border border-sentinel-border"
                >
                  {did}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Actions timeline */}
      <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-5">
        <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <FileText className="h-4 w-4 text-sentinel-muted" />
          Actions Taken
        </h3>
        {(!incident.actions || incident.actions.length === 0) ? (
          <p className="text-xs text-sentinel-muted">No actions recorded yet</p>
        ) : (
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-4 top-0 bottom-0 w-px bg-sentinel-border" />

            <div className="space-y-4">
              {incident.actions.map((action, idx) => {
                const isAlert = action.action_type === 'alert'
                return (
                  <motion.div
                    key={action.action_id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                    className="relative flex items-start gap-4 pl-4"
                  >
                    {/* Timeline dot */}
                    <div
                      className="absolute left-0 top-1.5 h-3 w-3 rounded-full border-2 z-10"
                      style={{
                        backgroundColor: isAlert ? THEME.warning : THEME.primary,
                        borderColor: THEME.card,
                      }}
                    />

                    <div className="ml-6 flex-1 rounded-lg border border-sentinel-border bg-sentinel-bg p-4">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          {isAlert ? (
                            <Bell className="h-3.5 w-3.5 text-amber-400" />
                          ) : (
                            <BookOpen className="h-3.5 w-3.5 text-sentinel-primary" />
                          )}
                          <span className="text-xs font-medium text-white">
                            {isAlert ? 'Alert Raised' : 'Logged'}
                          </span>
                          <StatusBadge
                            value={action.action_type}
                            type="status"
                          />
                        </div>
                        <span className="text-[11px] text-sentinel-muted">
                          {formatRelativeTime(action.timestamp)}
                        </span>
                      </div>

                      <div className="text-xs text-sentinel-muted space-y-1">
                        <p>
                          <span className="text-sentinel-muted">Target:</span>{' '}
                          <span className="font-mono text-white">
                            {action.target ?? 'None'}
                          </span>
                        </p>
                        <p className="font-mono text-[10px] text-sentinel-muted/60">
                          ID: {action.action_id}
                        </p>
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </motion.div>
  )
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function DetailItem({
  icon: Icon,
  label,
  value,
  mono = false,
}: {
  icon: React.ElementType
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="rounded-lg bg-sentinel-bg p-3 border border-sentinel-border">
      <div className="flex items-center gap-1.5 mb-1">
        <Icon className="h-3 w-3 text-sentinel-muted" />
        <span className="text-[10px] uppercase tracking-wider text-sentinel-muted font-medium">
          {label}
        </span>
      </div>
      <p className={`text-sm text-white ${mono ? 'font-mono text-[11px]' : ''}`}>
        {value}
      </p>
    </div>
  )
}
