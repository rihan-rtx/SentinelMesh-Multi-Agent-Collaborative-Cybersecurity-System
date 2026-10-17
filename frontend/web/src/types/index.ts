/**
 * SentinelMesh — TypeScript Type Definitions
 *
 * Single source of truth for all data types used in the frontend.
 * These types mirror the FastAPI bridge response shapes and the
 * shared/schemas.py Pydantic models.
 */

// ---------------------------------------------------------------------------
// Enums / Union Types
// ---------------------------------------------------------------------------

/** Agent health status. */
export type AgentStatus = 'healthy' | 'degraded' | 'down'

/** Flow classification. */
export type Classification = 'benign' | 'suspicious' | 'malicious'

/** Incident severity level. */
export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical'

/** Incident lifecycle status. */
export type IncidentStatus = 'open' | 'escalated' | 'resolved' | 'false_positive'

/** Action type. */
export type ActionType = 'log_only' | 'alert'

/** Infrastructure service name. */
export type ServiceName = 'kafka' | 'redis' | 'postgres' | 'grafana' | 'prometheus' | 'zookeeper'

// ---------------------------------------------------------------------------
// Data Models
// ---------------------------------------------------------------------------

/** Agent health data from Redis. */
export interface AgentHealth {
  agent_name: string
  timestamp: string
  status: AgentStatus
  throughput_last_interval: number
  queue_depth: number
}

/** Detection result from PostgreSQL. */
export interface Detection {
  detection_id: string
  flow_id: string
  timestamp: string
  classification: Classification
  confidence: number
  attack_type: string | null
}

/** Incident from PostgreSQL. */
export interface Incident {
  incident_id: string
  timestamp_opened: string
  timestamp_updated: string
  src_ip: string | null
  incident_type: string
  severity: IncidentSeverity
  status: IncidentStatus
}

/** Action taken in response to an incident. */
export interface Action {
  action_id: string
  incident_id: string
  timestamp: string
  action_type: ActionType
  target: string | null
}

/** Incident with nested actions array. */
export interface IncidentDetail extends Incident {
  actions: Action[]
  related_flow_ids?: string[]
  related_detection_ids?: string[]
}

/** Infrastructure service connectivity status. */
export interface ServiceStatus {
  name: ServiceName
  reachable: boolean
  latency_ms: number | null
  last_checked: string
}

/** Aggregate stats from the dashboard. */
export interface Stats {
  total_detections: number
  open_incidents: number
  active_agents: number
  detections_by_classification: Record<Classification, number>
}

/** Agent metrics from Prometheus. */
export interface AgentMetrics {
  agent: string
  events_consumed: number
  events_produced: number
  queue_depth: number
  processing_latency_p50: number | null
}

/** Paginated response wrapper. */
export interface Paginated<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

/** API error response. */
export interface ApiError {
  detail: string
}

// ---------------------------------------------------------------------------
// SSE Event Types
// ---------------------------------------------------------------------------

/** Base SSE event. */
export interface SSEEvent {
  type: 'detection' | 'incident' | 'error'
}

/** SSE detection event. */
export interface SSEDetectionEvent extends SSEEvent {
  type: 'detection'
  detection_id: string
  flow_id: string
  timestamp: string
  classification: Classification
  confidence: number
  attack_type: string | null
}

/** SSE incident event. */
export interface SSEIncidentEvent extends SSEEvent {
  type: 'incident'
  incident_id: string
  timestamp_opened: string
  timestamp_updated: string
  src_ip: string | null
  incident_type: string
  severity: IncidentSeverity
  status: IncidentStatus
}

/** SSE error event. */
export interface SSEErrorEvent extends SSEEvent {
  type: 'error'
  detail: string
}
