import type { Metadata } from 'next'
import './globals.css'
import { PageShell } from '@/components/layout/PageShell'

export const metadata: Metadata = {
  title: 'SentinelMesh — Network Security Dashboard',
  description: 'Real-time network threat detection, incident correlation, and response dashboard for the SentinelMesh multi-agent security platform.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body>
        <PageShell>{children}</PageShell>
      </body>
    </html>
  )
}
