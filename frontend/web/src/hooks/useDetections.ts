'use client'

/**
 * useDetections — polls paginated detections from PostgreSQL via bridge.
 *
 * Fetches /api/detections at POLL_DETECTIONS_MS intervals with filters.
 *
 * @param options - Pagination and filter options
 * @returns { data, error, isLoading } state object
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchDetections } from '@/lib/api'
import { POLL_DETECTIONS_MS } from '@/lib/constants'
import type { Detection, Paginated } from '@/types'

interface UseDetectionsOptions {
  limit?: number
  offset?: number
  classification?: string
  attack_type?: string
}

interface UseDetectionsResult {
  data: Paginated<Detection> | null
  error: string | null
  isLoading: boolean
}

export function useDetections(options?: UseDetectionsOptions): UseDetectionsResult {
  const [data, setData] = useState<Paginated<Detection> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const result = await fetchDetections(options)
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch detections')
    } finally {
      setIsLoading(false)
    }
  }, [options?.limit, options?.offset, options?.classification, options?.attack_type])

  useEffect(() => {
    load()
    const interval = setInterval(load, POLL_DETECTIONS_MS)
    return () => clearInterval(interval)
  }, [load])

  return { data, error, isLoading }
}
