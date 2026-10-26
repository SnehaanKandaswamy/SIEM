import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from './api/client'

export interface AsyncState<T> {
  data: T | null
  error: string | null
  loading: boolean
  reload: () => void
}

/** Runs `fn` on mount and whenever `deps` change; optional polling interval in ms. */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[], pollMs?: number): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)
  const fnRef = useRef(fn)
  useEffect(() => {
    fnRef.current = fn
  })
  useEffect(() => {
    let alive = true
    // eslint-disable-next-line react-hooks/set-state-in-effect -- marks the start of an external fetch
    setLoading(true)
    fnRef
      .current()
      .then((d) => {
        if (alive) {
          setData(d)
          setError(null)
        }
      })
      .catch((e: unknown) => {
        if (alive) setError(e instanceof ApiError || e instanceof Error ? e.message : 'Unexpected error')
      })
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])
  useEffect(() => {
    if (!pollMs) return
    const id = setInterval(() => setTick((t) => t + 1), pollMs)
    return () => clearInterval(id)
  }, [pollMs])
  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload }
}
