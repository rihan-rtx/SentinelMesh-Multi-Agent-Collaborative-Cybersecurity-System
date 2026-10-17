'use client'

/**
 * useServices — polls service connectivity status via bridge.
 *
 * Fetches /api/services at POLL_SERVICES_MS intervals.
 *
 * @returns { data, error, isLoading } state object
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchServices } from '@/lib/api'
import { POLL_SERVICES_MS } from '@/lib/constants'
import type { ServiceStatus } from '@/types'

interface UseServicesResult {
  data: ServiceStatus[] | null
  error: string | null
  isLoading: boolean
}

export function useServices(): UseServicesResult {
  const [data, setData] = useState<ServiceStatus[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const result = await fetchServices()
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch services')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, POLL_SERVICES_MS)
    return () => clearInterval(interval)
  }, [load])

  return { data, error, isLoading }
}
