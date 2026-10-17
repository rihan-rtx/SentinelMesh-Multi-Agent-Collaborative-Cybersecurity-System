/**
 * SentinelMesh — API Client
 *
 * Centralized fetch functions for all bridge API endpoints.
 * Every function handles errors and returns typed data.
 */

import { API_BASE_URL, DEFAULT_PAGE_SIZE } from './constants'
import type {
  AgentHealth,
  AgentMetrics,
  Detection,
  Incident,
  IncidentDetail,
  Paginated,
  ServiceStatus,
  Stats,
} from '@/types'

// ---------------------------------------------------------------------------
// Generic fetcher
// ---------------------------------------------------------------------------

/**
 * Generic fetch wrapper that handles errors consistently.
 *
 * @param endpoint - API endpoint path (e.g., '/api/health')
 * @param params - Optional query parameters
 * @returns Parsed JSON response
 * @throws Error with status and detail message on failure
 */
async function apiFetch<T>(endpoint: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(endpoint, API_BASE_URL)
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        url.searchParams.set(key, value)
      }
    })
  }

  const response = await fetch(url.toString())

  if (!response.ok) {
    const body = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(body.detail || `HTTP ${response.status}`)
  }

  return response.json()
}

// ---------------------------------------------------------------------------
// Endpoint functions
// ---------------------------------------------------------------------------

/**
 * Fetch agent health data from Redis via bridge.
 *
 * @returns Array of AgentHealth objects
 * @throws Error if Redis is unavailable (503)
 */
export async function fetchHealth(): Promise<AgentHealth[]> {
  return apiFetch<AgentHealth[]>('/api/health')
}

/**
 * Fetch aggregate dashboard stats.
 *
 * @returns Stats object with counts and classification breakdown
 * @throws Error if PostgreSQL is unavailable (503)
 */
export async function fetchStats(): Promise<Stats> {
  return apiFetch<Stats>('/api/stats')
}

/**
 * Fetch paginated detections with optional filters.
 *
 * @param options - Pagination and filter options
 * @returns Paginated detection list
 * @throws Error if PostgreSQL is unavailable (503)
 */
export async function fetchDetections(options?: {
  limit?: number
  offset?: number
  classification?: string
  attack_type?: string
}): Promise<Paginated<Detection>> {
  const params: Record<string, string> = {
    limit: String(options?.limit ?? DEFAULT_PAGE_SIZE),
    offset: String(options?.offset ?? 0),
  }
  if (options?.classification) params.classification = options.classification
  if (options?.attack_type) params.attack_type = options.attack_type

  return apiFetch<Paginated<Detection>>('/api/detections', params)
}

/**
 * Fetch paginated incidents with optional filters.
 *
 * @param options - Pagination and filter options
 * @returns Paginated incident list
 * @throws Error if PostgreSQL is unavailable (503)
 */
export async function fetchIncidents(options?: {
  limit?: number
  offset?: number
  severity?: string
  status?: string
  incident_type?: string
}): Promise<Paginated<Incident>> {
  const params: Record<string, string> = {
    limit: String(options?.limit ?? DEFAULT_PAGE_SIZE),
    offset: String(options?.offset ?? 0),
  }
  if (options?.severity) params.severity = options.severity
  if (options?.status) params.status = options.status
  if (options?.incident_type) params.incident_type = options.incident_type

  return apiFetch<Paginated<Incident>>('/api/incidents', params)
}

/**
 * Fetch a single incident with its actions.
 *
 * @param id - Incident UUID
 * @returns Incident detail with nested actions
 * @throws Error if not found (404) or PostgreSQL unavailable (503)
 */
export async function fetchIncidentDetail(id: string): Promise<IncidentDetail> {
  return apiFetch<IncidentDetail>(`/api/incidents/${id}`)
}

/**
 * Fetch agent metrics from Prometheus via bridge.
 *
 * @returns Array of AgentMetrics objects
 * @throws Error if Prometheus is unavailable (503)
 */
export async function fetchMetrics(): Promise<AgentMetrics[]> {
  return apiFetch<AgentMetrics[]>('/api/metrics')
}

/**
 * Fetch infrastructure service connectivity status.
 *
 * @returns Array of ServiceStatus objects (always succeeds)
 */
export async function fetchServices(): Promise<ServiceStatus[]> {
  return apiFetch<ServiceStatus[]>('/api/services')
}
