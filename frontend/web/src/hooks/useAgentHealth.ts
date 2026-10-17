'use client'

/**
 * useAgentHealth — polls agent health data from Redis via bridge.
 *
 * Fetches /api/health at POLL_AGENT_HEALTH_MS intervals.
 *
 * @returns { data, error, isLoading } state object
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchHealth } from '@/lib/api'
import { POLL_AGENT_HEALTH_MS } from '@/lib/constants'
import type { AgentHealth } from '@/types'

interface UseAgentHealthResult {
  data: AgentHealth[] | null
  error: string | null
  isLoading: boolean
}

export function useAgentHealth(): UseAgentHealthResult {
  const [data, setData] = useState<AgentHealth[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const load = useCallback(async () => {
    try {
      const result = await fetchHealth()
      setData(result)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch health data')
    } finally {
      setIsLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
    const interval = setInterval(load, POLL_AGENT_HEALTH_MS)
    return () => clearInterval(interval)
  }, [load])

  return { data, error, isLoading }
}
