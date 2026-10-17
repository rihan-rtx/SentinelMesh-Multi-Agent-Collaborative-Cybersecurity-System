/**
 * LoadingSkeleton — shimmer loading placeholder.
 *
 * Renders a pulsing gradient skeleton matching the shape of the
 * content that will replace it. Uses CSS animation for performance.
 *
 * @param className - Additional CSS classes for sizing
 * @param variant - Shape variant: 'line', 'card', 'circle'
 * @param count - Number of skeleton lines to render
 */

interface LoadingSkeletonProps {
  /** Additional CSS classes for width/height. */
  className?: string
  /** Shape variant. */
  variant?: 'line' | 'card' | 'circle'
  /** Number of skeleton items to render. */
  count?: number
}

export function LoadingSkeleton({
  className = '',
  variant = 'line',
  count = 1,
}: LoadingSkeletonProps) {
  const baseClasses = 'animate-pulse bg-gradient-to-r from-sentinel-card via-sentinel-card-hover to-sentinel-card bg-[length:200%_100%] animate-shimmer'

  const variantClasses = {
    line: 'h-4 rounded',
    card: 'h-32 rounded-xl',
    circle: 'h-10 w-10 rounded-full',
  }

  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className={`${baseClasses} ${variantClasses[variant]} ${className}`}
        />
      ))}
    </div>
  )
}
