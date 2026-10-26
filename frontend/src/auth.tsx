import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, loadSession, setLogoutHandler, setSession, type Role, type Session } from './api/client'

interface AuthCtx {
  session: Session | null
  login: (u: string, p: string) => Promise<void>
  logout: () => void
  can: (min: Role) => boolean
}
const RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 }
const Ctx = createContext<AuthCtx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setS] = useState<Session | null>(() => loadSession())
  const logout = useCallback(() => {
    setSession(null)
    setS(null)
  }, [])
  useEffect(() => setLogoutHandler(logout), [logout])
  const value = useMemo<AuthCtx>(
    () => ({
      session,
      logout,
      login: async (u, p) => setS(await api.login(u, p)),
      // UI hint only; every action is authorised again by the backend.
      can: (min) => !!session && RANK[session.role] >= RANK[min],
    }),
    [session, logout],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthCtx {
  const c = useContext(Ctx)
  if (!c) throw new Error('useAuth outside AuthProvider')
  return c
}
