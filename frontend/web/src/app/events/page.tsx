'use client'

/**
 * Events — live detection event feed with classification/attack_type filters.
 *
 * Displays a paginated table of DetectionResult events from the pipeline,
 * with filter controls for classification (benign/suspicious/malicious)
 * and attack type. Auto-refreshes via useDetections hook.
 */

import { useState, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  Filter,
  Search,
  X,
} from 'lucide-react'

import { useDetections } from '@/hooks/useDetections'

import { StatusBadge } from '@/components/shared/StatusBadge'
import { LoadingSkeleton } from '@/components/shared/LoadingSkeleton'
import { ErrorCard } from '@/components/shared/ErrorCard'
import { EmptyState } from '@/components/shared/EmptyState'

import { DEFAULT_PAGE_SIZE, CLASSIFICATION_COLORS } from '@/lib/constants'
import {
  formatRelativeTime,
  formatDateTime,
  formatConfidence,
  formatIncidentType,
} from '@/lib/formatters'

// ---------------------------------------------------------------------------
// Filter options
// ---------------------------------------------------------------------------

const CLASSIFICATION_OPTIONS = ['all', 'benign', 'suspicious', 'malicious'] as const
const ATTACK_TYPE_OPTIONS = [
  'all',
  'port_scan',
  'syn_flood',
  'exploit_attempt',
  'suspicious_payload',
  'possible_exfiltration',
] as const

// ---------------------------------------------------------------------------
// Page Component
// ---------------------------------------------------------------------------

export default function EventsPage() {
  const [page, setPage] = useState(0)
  const [classification, setClassification] = useState<string>('all')
  const [attackType, setAttackType] = useState<string>('all')
  const [showFilters, setShowFilters] = useState(false)

  const detections = useDetections({
    limit: DEFAULT_PAGE_SIZE,
    offset: page * DEFAULT_PAGE_SIZE,
    classification: classification === 'all' ? undefined : classification,
    attack_type: attackType === 'all' ? undefined : attackType,
  })

  const totalPages = detections.data
    ? Math.ceil(detections.data.total / DEFAULT_PAGE_SIZE)
    : 0

  const resetFilters = useCallback(() => {
    setClassification('all')
    setAttackType('all')
    setPage(0)
  }, [])

  const hasActiveFilters = classification !== 'all' || attackType !== 'all'

  return (
    <div className="space-y-6">
      {/* Header + Filter toggle */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white">Live Events</h2>
          <p className="text-sm text-sentinel-muted">
            Real-time detection results from the pipeline
            {detections.data && (
              <span className="ml-2 text-white font-medium">
                ({detections.data.total.toLocaleString()} total)
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

      {/* Filters panel */}
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
                  Filter Events
                </h3>
                {hasActiveFilters && (
                  <button
                    onClick={resetFilters}
                    className="flex items-center gap-1 text-xs text-sentinel-muted hover:text-white transition-colors"
                  >
                    <X className="h-3 w-3" />
                    Clear
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Classification filter */}
                <div>
                  <label className="text-[11px] text-sentinel-muted mb-2 block">
                    Classification
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {CLASSIFICATION_OPTIONS.map((opt) => (
                      <button
                        key={opt}
                        onClick={() => {
                          setClassification(opt)
                          setPage(0)
                        }}
                        className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all border ${
                          classification === opt
                            ? 'bg-sentinel-primary/10 text-sentinel-primary border-sentinel-primary/30'
                            : 'bg-sentinel-bg text-sentinel-muted border-sentinel-border hover:border-sentinel-border-hover'
                        }`}
                      >
                        {opt === 'all' ? 'All' : opt.charAt(0).toUpperCase() + opt.slice(1)}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Attack Type filter */}
                <div>
                  <label className="text-[11px] text-sentinel-muted mb-2 block">
                    Attack Type
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {ATTACK_TYPE_OPTIONS.map((opt) => (
                      <button
                        key={opt}
                        onClick={() => {
                          setAttackType(opt)
                          setPage(0)
                        }}
                        className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all border ${
                          attackType === opt
                            ? 'bg-sentinel-primary/10 text-sentinel-primary border-sentinel-primary/30'
                            : 'bg-sentinel-bg text-sentinel-muted border-sentinel-border hover:border-sentinel-border-hover'
                        }`}
                      >
                        {opt === 'all'
                          ? 'All'
                          : formatIncidentType(opt)}
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
      {detections.error && (
        <ErrorCard title="Failed to load detections" message={detections.error} />
      )}

      {/* Loading */}
      {detections.isLoading && (
        <LoadingSkeleton variant="card" count={3} />
      )}

      {/* Table */}
      {detections.data && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="rounded-xl border border-sentinel-border bg-sentinel-card overflow-hidden"
        >
          {detections.data.items.length === 0 ? (
            <div className="p-8">
              <EmptyState
                message={
                  hasActiveFilters
                    ? 'No detections match the selected filters'
                    : 'No detection events yet — waiting for traffic'
                }
                icon={Activity}
                action={
                  hasActiveFilters ? { label: 'Clear filters', onClick: resetFilters } : undefined
                }
              />
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-sentinel-border bg-sentinel-bg/50">
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Detection ID</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Flow ID</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Classification</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Confidence</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Attack Type</th>
                      <th className="px-4 py-3 font-medium text-sentinel-muted">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detections.data.items.map((det, idx) => (
                      <motion.tr
                        key={det.detection_id}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: idx * 0.03 }}
                        className="border-b border-sentinel-border/30 hover:bg-sentinel-card-hover/30 transition-colors"
                      >
                        <td className="px-4 py-3 font-mono text-[11px] text-sentinel-muted">
                          {det.detection_id.slice(0, 8)}…
                        </td>
                        <td className="px-4 py-3 font-mono text-[11px] text-sentinel-muted">
                          {det.flow_id.slice(0, 8)}…
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge value={det.classification} type="classification" />
                        </td>
                        <td className="px-4 py-3 font-mono text-white">
                          {formatConfidence(det.confidence)}
                        </td>
                        <td className="px-4 py-3 text-white">
                          {det.attack_type ? formatIncidentType(det.attack_type) : (
                            <span className="text-sentinel-muted">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sentinel-muted" title={formatDateTime(det.timestamp)}>
                          {formatRelativeTime(det.timestamp)}
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
