'use client'

/**
 * Incidents — paginated incident list with severity/status/type filters.
 *
 * Displays a table of correlated incidents from the Correlation Agent,
 * with filter controls and click-through to detail view.
 */

import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Filter,
  ShieldCheck,
  X,
} from 'lucide-react'

import { useIncidents } from '@/hooks/useIncidents'

import { StatusBadge } from '@/components/shared/StatusBadge'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { ErrorCard } from '@/components/shared/ErrorCard'
import { EmptyState } from '@/components/shared/EmptyState'

import { DEFAULT_PAGE_SIZE } from '@/lib/constants'
import {
  formatRelativeTime,
  formatDateTime,
  formatIncidentType,
} from '@/lib/formatters'

// ---------------------------------------------------------------------------
// Filter options
// ---------------------------------------------------------------------------

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low'] as const
const STATUS_OPTIONS = ['all', 'open', 'escalated', 'resolved', 'false_positive'] as const
const TYPE_OPTIONS = [
  'all',
  'coordinated_scan',
  'multi_stage_attack',
  'repeated_malicious',
  'dpi_confirmed_scan',
  'distributed_target_attack',
] as const

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function IncidentsPage() {
  const [page, setPage] = useState(0)
  const [severity, setSeverity] = useState<string>('all')
  const [status, setStatus] = useState<string>('all')
  const [incidentType, setIncidentType] = useState<string>('all')
  const [showFilters, setShowFilters] = useState(false)

  const incidents = useIncidents({
    limit: DEFAULT_PAGE_SIZE,
    offset: page * DEFAULT_PAGE_SIZE,
    severity: severity === 'all' ? undefined : severity,
    status: status === 'all' ? undefined : status,
    incident_type: incidentType === 'all' ? undefined : incidentType,
  })

  const totalPages = incidents.data
    ? Math.ceil(incidents.data.total / DEFAULT_PAGE_SIZE)
    : 0

  const resetFilters = useCallback(() => {
    setSeverity('all')
    setStatus('all')
    setIncidentType('all')
    setPage(0)
  }, [])

  const hasActiveFilters = severity !== 'all' || status !== 'all' || incidentType !== 'all'

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white">Incidents</h2>
          <p className="text-sm text-sentinel-muted">
            Correlated security incidents from cross-agent analysis
            {incidents.data && (
              <span className="ml-2 text-white font-medium">
                ({incidents.data.total.toLocaleString()} total)
              </span>
            )}
          </p>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-medium transition-all border ${
            hasActiveFilters
              ? 'bg-sentinel-primary/10 text-sentinel-primary border-sentinel-primary/30'
              : 'bg-sentinel-card text-sentinel-muted border-sentinel-border hover:border-sentinel-border-hover'
          }`}
        >
          <Filter className="h-3.5 w-3.5" />
          Filters
          {hasActiveFilters && (
            <span className="h-1.5 w-1.5 rounded-full bg-sentinel-primary" />
          )}
        </button>
      </div>

      {/* Filters */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="rounded-xl border border-sentinel-border bg-sentinel-card p-4 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-medium text-sentinel-muted uppercase tracking-wider">
                  Filter Incidents
                </h3>
                {hasActiveFilters && (
                  <button
                    onClick={resetFilters}
                    className="flex items-center gap-1 text-xs text-sentinel-muted hover:text-white transition-colors"
                  >
                    <X className="h-3 w-3" />
                    Clear all
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {/* Severity */}
                <div>
                  <label className="text-[11px] text-sentinel-muted mb-2 block">Severity</label>
                  <div className="flex flex-wrap gap-1.5">
                    {SEVERITY_OPTIONS.map((opt) => (
                      <button
                        key={opt}
                        onClick={() => { setSeverity(opt); setPage(0) }}
                        className={`rounded-lg px-2.5 py-1 text-[11px] font-medium transition-all border ${
                          severity === opt
                            ? 'bg-sentinel-primary/10 text-sentinel-primary border-sentinel-primary/30'
                            : 'bg-sentinel-bg text-sentinel-muted border-sentinel-border hover:border-sentinel-border-hover'
                        }`}
                      >
                        {opt === 'all' ? 'All' : opt.charAt(0).toUpperCase() + opt.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Status */}
                <div>
                  <label className="text-[11px] text-sentinel-muted mb-2 block">Status</label>
                  <div className="flex flex-wrap gap-1.5">
                    {STATUS_OPTIONS.map((opt) => (
                      <button
                        key={opt}
                        onClick={() => { setStatus(opt); setPage(0) }}
                        className={`rounded-lg px-2.5 py-1 text-[11px] font-medium transition-all border ${
                          status === opt
                            ? 'bg-sentinel-primary/10 text-sentinel-primary border-sentinel-primary/30'
                            : 'bg-sentinel-bg text-sentinel-muted border-sentinel-border hover:border-sentinel-border-hover'
                        }`}
                      >
                        {opt === 'all' ? 'All' : formatIncidentType(opt)}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Type */}
                <div>
                  <label className="text-[11px] text-sentinel-muted mb-2 block">Incident Type</label>
                  <div className="flex flex-wrap gap-1.5">
                    {TYPE_OPTIONS.map((opt) => (
                      <button
                        key={opt}
                        onClick={() => { setIncidentType(opt); setPage(0) }}
                        className={`rounded-lg px-2.5 py-1 text-[11px] font-medium transition-all border ${
                          incidentType === opt
                            ? 'bg-sentinel-primary/10 text-sentinel-primary border-sentinel-primary/30'
                            : 'bg-sentinel-bg text-sentinel-muted border-sentinel-border hover:border-sentinel-border-hover'
                        }`}
                      >
                        {opt === 'all' ? 'All' : formatIncidentType(opt)}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error */}
      {incidents.error && (
        <ErrorCard title="Failed to load incidents" message={incidents.error} />
      )}

      {/* Loading */}
      {incidents.isLoading && <LoadingSkeleton variant="card" count={3} />}

      {/* Table */}
      {incidents.data && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="rounded-xl border border-sentinel-border bg-sentinel-card overflow-hidden"
        >
          {incidents.data.items.length === 0 ? (
            <div className="p-8">
              <EmptyState
                message={
                  hasActiveFilters
                    ? 'No incidents match the selected filters'
                    : 'No incidents detected — system is clean'
                }
                icon={ShieldCheck}
                action={
                  hasActiveFilters
                    ? { label: 'Clear filters', onClick: resetFilters }
                    : undefined
                }
              />
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-sentinel-border bg-sentinel-bg/50">
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Type</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Source IP</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Severity</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Status</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Opened</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Updated</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted w-10"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.data.items.map((inc, idx) => (
                      <motion.tr
                        key={inc.incident_id}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.03 }}
                        className="border-b border-sentinel-border/30 hover:bg-sentinel-card-hover/30 transition-colors"
                      >
                        <td className="px-4 py-3">
                          <a
                            href={`/incidents/${inc.incident_id}`}
                            className="text-white hover:text-sentinel-primary transition-colors font-medium"
                          >
                            {formatIncidentType(inc.incident_type)}
                          </a>
                        </td>
                        <td className="px-4 py-3 font-mono text-sentinel-muted text-[11px]">
                          {inc.src_ip ?? '—'}
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge value={inc.severity} type="severity" />
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge value={inc.status} type="status" />
                        </td>
                        <td
                          className="px-4 py-3 text-sentinel-muted"
                          title={formatDateTime(inc.timestamp_opened)}
                        >
                          {formatRelativeTime(inc.timestamp_opened)}
                        </td>
                        <td
                          className="px-4 py-3 text-sentinel-muted"
                          title={formatDateTime(inc.timestamp_updated)}
                        >
                          {formatRelativeTime(inc.timestamp_updated)}
                        </td>
                        <td className="px-4 py-3">
                          <a
                            href={`/incidents/${inc.incident_id}`}
                            className="text-sentinel-muted hover:text-sentinel-primary transition-colors"
                            title="View details"
                          >
                            <ExternalLink className="h-3.5 w-3.5" />
                          </a>
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between border-t border-sentinel-border px-4 py-3">
                  <span className="text-xs text-sentinel-muted">
                    Page {page + 1} of {totalPages}
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setPage(Math.max(0, page - 1))}
                      disabled={page === 0}
                      className="flex items-center gap-1 rounded-lg border border-sentinel-border px-3 py-1.5 text-xs text-sentinel-muted transition-colors hover:bg-sentinel-card-hover disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      <ChevronLeft className="h-3 w-3" />
                      Previous
                    </button>
                    <button
                      onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                      disabled={page >= totalPages - 1}
                      className="flex items-center gap-1 rounded-lg border border-sentinel-border px-3 py-1.5 text-xs text-sentinel-muted transition-colors hover:bg-sentinel-card-hover disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Next
                      <ChevronRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </motion.div>
      )}
    </div>
  )
}
