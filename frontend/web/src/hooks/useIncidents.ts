'use client'

/**
 * useIncidents — polls paginated incidents from PostgreSQL via bridge.
 *
 * Fetches /api/incidents at POLL_INCIDENTS_MS intervals with filters.
 *
 * @param options - Pagination and filter options
 * @returns { data, error, isLoading } state object
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchIncidents } from '@/lib/api'
import { POLL_INCIDENTS_MS } from '@/lib/constants'
import type { Incident, Paginated } from '@/types'

interface UseIncidentsOptions {
  limit?: number
  offset?: number
  severity?: string
  status?: string
  incident_type?: string
}

interface UseIncidentsResult {
  data: Paginated<Incident> | null
  error: string | null
  isLoading: boolean
}

export function useIncidents(options?: UseIncidentsOptions): UseIncidentsResult {
  const [data, setData] = useState<Paginated<Incident> | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const result = await fetchIncidents(options)
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch incidents')
    } finally {
      setIsLoading(false)
    }
  }, [options?.limit, options?.offset, options?.severity, options?.status, options?.incident_type])

  useEffect(() => {
    load()
    const interval = setInterval(load, POLL_INCIDENTS_MS)
    return () => clearInterval(interval)
  }, [load])

  return { data, error, isLoading }
}
