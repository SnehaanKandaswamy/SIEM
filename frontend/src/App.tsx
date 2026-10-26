import type { ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import type { Role } from './api/client'
import { useAuth } from './auth'
import { Layout } from './components/Layout'
import { Admin } from './pages/Admin'
import { AlertDetail } from './pages/AlertDetail'
import { Alerts } from './pages/Alerts'
import { Explorer } from './pages/Explorer'
import { Geo } from './pages/Geo'
import { IncidentDetail, Incidents } from './pages/Incidents'
import { Live } from './pages/Live'
import { Login } from './pages/Login'
import { Mitre } from './pages/Mitre'
import { Overview } from './pages/Overview'
import { Reports } from './pages/Reports'

function Guard({ min, children }: { min: Role; children: ReactNode }) {
  const { can } = useAuth()
  return can(min) ? (
    <>{children}</>
  ) : (
    <p className="card text-amber-300">You do not have permission to view this page.</p>
  )
}

export function App() {
  const { session } = useAuth()
  if (!session) return <Login />
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="live" element={<Live />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="alerts/:id" element={<AlertDetail />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="explorer" element={<Explorer />} />
        <Route path="geo" element={<Geo />} />
        <Route path="mitre" element={<Mitre />} />
        <Route
          path="reports"
          element={
            <Guard min="analyst">
              <Reports />
            </Guard>
          }
        />
        <Route
          path="admin"
          element={
            <Guard min="admin">
              <Admin />
            </Guard>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
