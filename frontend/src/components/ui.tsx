import type { ReactNode } from 'react'
import type { Severity } from '../api/client'

export const SEV_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#d4f8b8',
  informational: '#9a9a97',
}

export function SevBadge({ sev }: { sev: Severity }) {
  return (
    <span
      className="inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase"
      style={{
        background: SEV_COLOR[sev] + '26',
        color: SEV_COLOR[sev],
        border: `1px solid ${SEV_COLOR[sev]}66`,
      }}
    >
      {sev}
    </span>
  )
}

export function SyntheticTag({ show }: { show: boolean }) {
  return show ? (
    <span
      className="ml-1 rounded border border-purple-500/50 bg-purple-500/10 px-1 text-[10px] uppercase text-purple-300"
      title="Synthetic demo data"
    >
      synthetic
    </span>
  ) : null
}

export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h1 className="text-xl font-semibold text-white">{title}</h1>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  )
}

/** Uniform loading / error / empty handling. `empty` is evaluated only once loading has finished. */
export function State({
  loading,
  error,
  empty,
  emptyText = 'Nothing to show yet.',
  onRetry,
  children,
}: {
  loading: boolean
  error: string | null
  empty?: boolean
  emptyText?: string
  onRetry?: () => void
  children: ReactNode
}) {
  if (error)
    return (
      <div role="alert" className="card border-red-700 text-red-300">
        <p>Error: {error}</p>
        {onRetry && (
          <button className="btn mt-2" onClick={onRetry}>
            Retry
          </button>
        )}
      </div>
    )
  if (loading && empty) return <p className="text-slate-400">Loading…</p>
  if (empty) return <p className="card text-slate-400">{emptyText}</p>
  return <>{children}</>
}

export function Pagination({
  page,
  size,
  total,
  onPage,
}: {
  page: number
  size: number
  total: number
  onPage: (p: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / size))
  return (
    <div className="mt-3 flex items-center justify-between text-sm text-slate-400">
      <span>
        {total} result{total === 1 ? '' : 's'} · page {page} of {pages}
      </span>
      <span className="flex gap-2">
        <button className="btn" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          Previous
        </button>
        <button className="btn" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          Next
        </button>
      </span>
    </div>
  )
}

export const fmt = (iso: string) => new Date(iso).toLocaleString()
