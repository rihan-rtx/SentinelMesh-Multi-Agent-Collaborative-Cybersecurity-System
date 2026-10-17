'use client'

/**
 * useStats — polls dashboard stats from PostgreSQL via bridge.
 *
 * Fetches /api/stats at POLL_STATS_MS intervals.
 *
 * @returns { data, error, isLoading } state object
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchStats } from '@/lib/api'
import { POLL_STATS_MS } from '@/lib/constants'
import type { Stats } from '@/types'

interface UseStatsResult {
  data: Stats | null
  error: string | null
  isLoading: boolean
}

export function useStats(): UseStatsResult {
  const [data, setData] = useState<Stats | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const result = await fetchStats()
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch stats')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, POLL_STATS_MS)
    return () => clearInterval(interval)
  }, [load])

  return { data, error, isLoading }
}
