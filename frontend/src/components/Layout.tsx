import { NavLink, Outlet } from 'react-router-dom'
import type { Role } from '../api/client'
import { useAuth } from '../auth'

const NAV: { to: string; label: string; min: Role }[] = [
  { to: '/', label: 'Overview', min: 'viewer' },
  { to: '/live', label: 'Live stream', min: 'viewer' },
  { to: '/alerts', label: 'Alerts', min: 'viewer' },
  { to: '/incidents', label: 'Incidents', min: 'viewer' },
  { to: '/explorer', label: 'Log explorer', min: 'viewer' },
  { to: '/geo', label: 'Attack map', min: 'viewer' },
  { to: '/mitre', label: 'MITRE ATT&CK', min: 'viewer' },
  { to: '/reports', label: 'Reports', min: 'analyst' },
  { to: '/admin', label: 'Administration', min: 'admin' },
]

export function Layout() {
  const { session, logout, can } = useAuth()
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <aside className="border-line bg-panel md:w-56 md:shrink-0 md:border-r">
        <div className="px-4 py-4 text-lg font-bold text-white">🛡 SIEM for DevOps</div>
        <nav
          aria-label="Main"
          className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col md:overflow-visible"
        >
          {NAV.filter((n) => can(n.min)).map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                `whitespace-nowrap rounded-md px-3 py-2 text-sm ${isActive ? 'bg-sky-700 text-white' : 'text-slate-300 hover:bg-panel2'}`
              }
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="hidden border-t border-line p-3 text-xs text-slate-400 md:block">
          Signed in as <b className="text-slate-200">{session?.username}</b> ({session?.role})
          <button className="btn mt-2 w-full justify-center" onClick={logout}>
            Sign out
          </button>
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-4 md:p-6">
        <div className="mb-3 flex items-center justify-end gap-3 text-xs text-slate-400 md:hidden">
          {session?.username} ({session?.role})
          <button className="btn" onClick={logout}>
            Sign out
          </button>
        </div>
        <Outlet />
      </main>
    </div>
  )
}
