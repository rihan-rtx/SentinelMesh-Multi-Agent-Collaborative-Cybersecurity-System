/**
 * SentinelMesh — Centralized Constants
 *
 * Single source of truth for all configuration constants used
 * across the frontend. No magic numbers or hardcoded URLs elsewhere.
 */

// ---------------------------------------------------------------------------
// API Configuration
// ---------------------------------------------------------------------------

/** Base URL for the FastAPI bridge server. */
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000'

/** Base URL for Grafana dashboards. */
export const GRAFANA_URL = process.env.NEXT_PUBLIC_GRAFANA_URL ?? 'http://localhost:3000'

// ---------------------------------------------------------------------------
// Polling Intervals (milliseconds)
// ---------------------------------------------------------------------------

/** Agent health polling interval. */
export const POLL_AGENT_HEALTH_MS = 5_000

/** Dashboard stats polling interval. */
export const POLL_STATS_MS = 10_000

/** Detections list polling interval. */
export const POLL_DETECTIONS_MS = 15_000

/** Incidents list polling interval. */
export const POLL_INCIDENTS_MS = 15_000

/** Agent metrics polling interval. */
export const POLL_METRICS_MS = 10_000

/** Service status polling interval. */
export const POLL_SERVICES_MS = 30_000

/** SSE reconnect delay after disconnect. */
export const SSE_RECONNECT_DELAY_MS = 3_000

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

/** Default page size for paginated endpoints. */
export const DEFAULT_PAGE_SIZE = 20

/** Maximum events in the SSE event buffer. */
export const MAX_EVENT_BUFFER = 500

// ---------------------------------------------------------------------------
// Color Palettes
// ---------------------------------------------------------------------------

/** Severity level colors. */
export const SEVERITY_COLORS = {
  critical: '#EF4444',
  high: '#F97316',
  medium: '#F59E0B',
  low: '#3B82F6',
} as const

/** Classification colors. */
export const CLASSIFICATION_COLORS = {
  malicious: '#EF4444',
  suspicious: '#F59E0B',
  benign: '#22C55E',
} as const

/** Agent status colors. */
export const AGENT_STATUS_COLORS = {
  healthy: '#22C55E',
  degraded: '#F59E0B',
  down: '#EF4444',
} as const

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

/** Core theme colors. */
export const THEME = {
  background: '#0B1120',
  card: '#111827',
  primary: '#2563EB',
  success: '#22C55E',
  warning: '#F59E0B',
  danger: '#EF4444',
  text: '#FFFFFF',
  muted: '#9CA3AF',
  cyan: '#22D3EE',
} as const

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

/** Sidebar navigation items. */
export const NAV_ITEMS = [
  { label: 'Dashboard', href: '/dashboard', icon: 'LayoutDashboard' },
  { label: 'Architecture', href: '/architecture', icon: 'Network' },
  { label: 'Agents', href: '/agents', icon: 'Bot' },
  { label: 'Live Events', href: '/events', icon: 'Activity' },
  { label: 'Incidents', href: '/incidents', icon: 'AlertTriangle' },
  { label: 'Monitoring', href: '/monitoring', icon: 'Monitor' },
  { label: 'Settings', href: '/settings', icon: 'Settings' },
] as const
