"use client"

import { useCallback, useEffect, useState } from "react"

import { api, ApiError } from "./api"

export interface PollState<T> {
  data: T | undefined
  error: ApiError | Error | undefined
  loading: boolean
  refresh: () => Promise<void>
}

interface Snapshot<T> {
  path: string | null
  data?: T
  error?: ApiError | Error
}

/**
 * Fetch `path` now and every `intervalMs` (0 = once). Polling pauses while the
 * tab is hidden so an idle dashboard does not keep the backend busy. Responses
 * for an old path are ignored after the path changes (e.g. a new filter).
 */
export function usePoll<T>(path: string | null, intervalMs = 0): PollState<T> {
  const [snap, setSnap] = useState<Snapshot<T>>({ path: null })

  const refresh = useCallback(async () => {
    if (!path) return
    try {
      const data = await api<T>(path)
      setSnap({ path, data })
    } catch (e) {
      setSnap((prev) => ({ path, data: prev.path === path ? prev.data : undefined, error: e as Error }))
    }
  }, [path])

  useEffect(() => {
    if (!path) return
    void refresh()
    if (!intervalMs) return
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh()
    }, intervalMs)
    return () => window.clearInterval(id)
  }, [path, intervalMs, refresh])

  const current = snap.path === path
  return {
    data: current ? snap.data : undefined,
    error: current ? snap.error : undefined,
    loading: Boolean(path) && !current,
    refresh,
  }
}
