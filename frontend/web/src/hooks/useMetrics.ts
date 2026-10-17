'use client'

/**
 * useMetrics — polls agent metrics from Prometheus via bridge.
 *
 * Fetches /api/metrics at POLL_METRICS_MS intervals.
 *
 * @returns { data, error, isLoading } state object
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchMetrics } from '@/lib/api'
import { POLL_METRICS_MS } from '@/lib/constants'
import type { AgentMetrics } from '@/types'

interface UseMetricsResult {
  data: AgentMetrics[] | null
  error: string | null
  isLoading: boolean
}

export function useMetrics(): UseMetricsResult {
  const [data, setData] = useState<AgentMetrics[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const result = await fetchMetrics()
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch metrics')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, POLL_METRICS_MS)
    return () => clearInterval(interval)
  }, [load])

  return { data, error, isLoading }
}
