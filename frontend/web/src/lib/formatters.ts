/**
 * SentinelMesh — Formatting Utilities
 *
 * Pure functions for formatting dates, numbers, and labels
 * used across the dashboard UI.
 */

/**
 * Format an ISO timestamp as a relative time string (e.g., "2m ago").
 *
 * @param iso - ISO 8601 timestamp string
 * @returns Human-readable relative time
 */
export function formatRelativeTime(iso: string): string {
  const date = new Date(iso)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffS = Math.floor(diffMs / 1000)

  if (diffS < 60) return `${diffS}s ago`
  const diffM = Math.floor(diffS / 60)
  if (diffM < 60) return `${diffM}m ago`
  const diffH = Math.floor(diffM / 60)
  if (diffH < 24) return `${diffH}h ago`
  const diffD = Math.floor(diffH / 24)
  return `${diffD}d ago`
}

/**
 * Format an ISO timestamp as a full date/time string.
 *
 * @param iso - ISO 8601 timestamp string
 * @returns Formatted string like "Aug 1, 2026 12:00:00 PM"
 */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  })
}

/**
 * Format a number with locale-aware thousand separators.
 *
 * @param n - Number to format
 * @returns Formatted string like "15,281"
 */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US')
}

/**
 * Format a latency value in milliseconds.
 *
 * @param ms - Latency in milliseconds, or null
 * @returns Formatted string like "12.5ms" or "—" for null
 */
export function formatLatency(ms: number | null): string {
  if (ms === null) return '—'
  return `${ms.toFixed(1)}ms`
}

/**
 * Format a confidence score as a percentage.
 *
 * @param confidence - Score between 0 and 1
 * @returns Formatted string like "95.0%"
 */
export function formatConfidence(confidence: number): string {
  return `${(confidence * 100).toFixed(1)}%`
}

/**
 * Capitalize the first letter of a string.
 *
 * @param s - Input string
 * @returns Capitalized string
 */
export function capitalize(s: string): string {
  if (!s) return s
  return s.charAt(0).toUpperCase() + s.slice(1)
}

/**
 * Format an incident type string for display (replace underscores with spaces).
 *
 * @param type - Incident type like "coordinated_scan"
 * @returns Formatted string like "Coordinated Scan"
 */
export function formatIncidentType(type: string): string {
  return type
    .split('_')
    .map(word => capitalize(word))
    .join(' ')
}
