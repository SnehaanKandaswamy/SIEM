import { useState, type FormEvent } from 'react'
import { SEVERITIES, api, type Role, type Rule, type Severity } from '../api/client'
import { PageHeader, Pagination, State, fmt } from '../components/ui'
import { useAsync } from '../hooks'

const TABS = ['Users', 'Detection rules', 'Collectors', 'Integrations', 'Audit log', 'System'] as const
type Tab = (typeof TABS)[number]

export function Admin() {
  const [tab, setTab] = useState<Tab>('Users')
  return (
    <>
      <PageHeader title="Administration" />
      <div role="tablist" className="mb-4 flex flex-wrap gap-1">
        {TABS.map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            className={`btn ${tab === t ? 'btn-primary' : ''}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>
      {tab === 'Users' && <Users />}
      {tab === 'Detection rules' && <Rules />}
      {tab === 'Collectors' && <Collectors />}
      {tab === 'Integrations' && <Integrations />}
      {tab === 'Audit log' && <Audit />}
      {tab === 'System' && <System />}
    </>
  )
}

function Flash({ m }: { m: { ok: boolean; text: string } | null }) {
  return m ? (
    <p role="status" className={`my-2 text-sm ${m.ok ? 'text-green-400' : 'text-red-400'}`}>
      {m.text}
    </p>
  ) : null
}
const errText = (e: unknown) => (e instanceof Error ? e.message : 'Action failed')

function Users() {
  const { data, error, loading, reload } = useAsync(() => api.users(), [])
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [f, setF] = useState({ username: '', email: '', password: '', role: 'viewer' as Role })
  async function create(e: FormEvent) {
    e.preventDefault()
    try {
      await api.createUser(f)
      setMsg({ ok: true, text: `User ${f.username} created` })
      setF({ username: '', email: '', password: '', role: 'viewer' })
      reload()
    } catch (err) {
      setMsg({ ok: false, text: errText(err) })
    }
  }
  async function update(id: number, body: Parameters<typeof api.updateUser>[1], ok: string) {
    try {
      await api.updateUser(id, body)
      setMsg({ ok: true, text: ok })
      reload()
    } catch (err) {
      setMsg({ ok: false, text: errText(err) })
    }
  }
  return (
    <div className="space-y-4">
      <Flash m={msg} />
      <form onSubmit={create} className="card grid gap-2 md:grid-cols-5" aria-label="Create user">
        <input
          className="input"
          placeholder="Username"
          value={f.username}
          onChange={(e) => setF({ ...f, username: e.target.value })}
          required
          minLength={3}
        />
        <input
          className="input"
          type="email"
          placeholder="Email"
          value={f.email}
          onChange={(e) => setF({ ...f, email: e.target.value })}
          required
        />
        <input
          className="input"
          type="password"
          placeholder="Password (12+ chars)"
          value={f.password}
          onChange={(e) => setF({ ...f, password: e.target.value })}
          required
          minLength={12}
          autoComplete="new-password"
        />
        <select
          aria-label="Role"
          className="input"
          value={f.role}
          onChange={(e) => setF({ ...f, role: e.target.value as Role })}
        >
          <option value="viewer">viewer</option>
          <option value="analyst">analyst</option>
          <option value="admin">admin</option>
        </select>
        <button className="btn btn-primary">Create user</button>
      </form>
      <State loading={loading} error={error} empty={!!data && data.length === 0} onRetry={reload}>
        <div className="card overflow-x-auto p-0">
          <table className="w-full">
            <thead className="border-b border-line">
              <tr>
                {['User', 'Email', 'Role', 'Active', 'Actions'].map((h) => (
                  <th key={h} className="th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.map((u) => (
                <tr key={u.id} className="border-b border-line/50">
                  <td className="td">{u.username}</td>
                  <td className="td">{u.email}</td>
                  <td className="td">
                    <select
                      aria-label={`Role for ${u.username}`}
                      className="input"
                      value={u.role}
                      onChange={(e) =>
                        update(u.id, { role: e.target.value as Role }, `Role updated for ${u.username}`)
                      }
                    >
                      <option>viewer</option>
                      <option>analyst</option>
                      <option>admin</option>
                    </select>
                  </td>
                  <td className="td">{u.is_active ? 'yes' : 'no'}</td>
                  <td className="td">
                    <button
                      className="btn"
                      onClick={() =>
                        update(
                          u.id,
                          { is_active: !u.is_active },
                          `${u.username} ${u.is_active ? 'disabled' : 'enabled'}`,
                        )
                      }
                    >
                      {u.is_active ? 'Disable' : 'Enable'}
                    </button>{' '}
                    <button
                      className="btn"
                      onClick={() => {
                        const pw = window.prompt(`New password for ${u.username} (min 12 characters)`)
                        if (pw) void update(u.id, { password: pw }, `Password reset for ${u.username}`)
                      }}
                    >
                      Reset password
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </State>
    </div>
  )
}

function Rules() {
  const { data, error, loading, reload } = useAsync(() => api.rules(), [])
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [editing, setEditing] = useState<{ rule: Rule; text: string } | null>(null)
  async function patch(id: string, body: Parameters<typeof api.updateRule>[1], ok: string) {
    try {
      await api.updateRule(id, body)
      setMsg({ ok: true, text: ok })
      setEditing(null)
      reload()
    } catch (err) {
      setMsg({ ok: false, text: errText(err) })
    }
  }
  return (
    <div className="space-y-3">
      <Flash m={msg} />
      <State loading={loading} error={error} empty={!!data && data.length === 0} onRetry={reload}>
        {data?.map((r) => (
          <div key={r.rule_id} className="card">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <b>
                  {r.rule_id} · {r.name}
                </b>
                <p className="text-sm text-slate-400">{r.description}</p>
                <p className="text-xs text-slate-500">
                  MITRE: {r.mitre.length ? r.mitre.map((m) => m.technique_id).join(', ') : 'none claimed'}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <select
                  aria-label={`Severity for ${r.rule_id}`}
                  className="input"
                  value={r.severity}
                  onChange={(e) =>
                    patch(
                      r.rule_id,
                      { severity: e.target.value as Severity },
                      `${r.rule_id} severity updated`,
                    )
                  }
                >
                  {SEVERITIES.map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
                <button
                  className="btn"
                  onClick={() =>
                    patch(
                      r.rule_id,
                      { enabled: !r.enabled },
                      `${r.rule_id} ${r.enabled ? 'disabled' : 'enabled'}`,
                    )
                  }
                >
                  {r.enabled ? 'Disable' : 'Enable'}
                </button>
                <button
                  className="btn"
                  onClick={() => setEditing({ rule: r, text: JSON.stringify(r.config, null, 2) })}
                >
                  Edit config
                </button>
              </div>
            </div>
            {editing?.rule.rule_id === r.rule_id && (
              <div className="mt-3 space-y-2">
                <textarea
                  aria-label={`Config for ${r.rule_id}`}
                  className="input h-48 w-full font-mono text-xs"
                  value={editing.text}
                  onChange={(e) => setEditing({ ...editing, text: e.target.value })}
                />
                <div className="flex gap-2">
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      try {
                        void patch(
                          r.rule_id,
                          { config: JSON.parse(editing.text) as Record<string, unknown> },
                          `${r.rule_id} configuration saved`,
                        )
                      } catch {
                        setMsg({ ok: false, text: 'Config is not valid JSON' })
                      }
                    }}
                  >
                    Save
                  </button>
                  <button className="btn" onClick={() => setEditing(null)}>
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        ))}
      </State>
    </div>
  )
}

function Collectors() {
  const { data, error, loading, reload } = useAsync(() => api.collectors(), [], 15000)
  const diag = useAsync(() => api.diagnostics(), [], 15000)
  return (
    <div className="space-y-4">
      <State
        loading={loading}
        error={error}
        empty={!!data && data.length === 0}
        emptyText="No collector has reported yet."
        onRetry={reload}
      >
        <div className="card overflow-x-auto p-0">
          <table className="w-full">
            <thead className="border-b border-line">
              <tr>
                {['Collector', 'Type', 'Status', 'Events', 'Errors', 'Last seen'].map((h) => (
                  <th key={h} className="th">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data?.map((c) => (
                <tr key={c.name} className="border-b border-line/50">
                  <td className="td">{c.name}</td>
                  <td className="td">{c.source_type}</td>
                  <td className={`td ${c.healthy ? 'text-green-400' : 'text-red-400'}`}>
                    {c.healthy ? 'healthy' : 'silent >5 min'}
                  </td>
                  <td className="td">{c.events_total}</td>
                  <td className="td">{c.errors_total}</td>
                  <td className="td text-xs">{fmt(c.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </State>
      <div className="card">
        <h2 className="mb-2 font-semibold">Recent parse failures</h2>
        {(diag.data?.recent_parse_errors.length ?? 0) === 0 ? (
          <p className="text-sm text-slate-400">None.</p>
        ) : (
          <ul className="space-y-1 text-xs">
            {diag.data?.recent_parse_errors.map((e, i) => (
              <li key={i} className="font-mono">
                {fmt(e.at)} [{e.collector}] {e.error} — {e.snippet}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}

function Integrations() {
  const { data, error, loading, reload } = useAsync(() => api.integrations(), [])
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  async function test(ch: 'email' | 'slack') {
    try {
      await api.testNotify(ch)
      setMsg({ ok: true, text: `Test ${ch} message sent` })
    } catch (e) {
      setMsg({ ok: false, text: errText(e) })
    }
  }
  return (
    <State loading={loading} error={error} empty={!data} onRetry={reload}>
      {data && (
        <div className="space-y-3">
          <Flash m={msg} />
          {(['email', 'slack'] as const).map((ch) => (
            <div key={ch} className="card flex flex-wrap items-center justify-between gap-2">
              <div>
                <b className="capitalize">{ch}</b>{' '}
                <span className={data[ch].configured ? 'text-green-400' : 'text-slate-500'}>
                  {data[ch].configured ? 'configured' : 'not configured'}
                </span>
                <p className="text-xs text-slate-400">
                  Minimum severity: {data[ch].min_severity}. Configure via environment variables (see
                  docs/DEPLOYMENT.md).
                </p>
              </div>
              <button className="btn" disabled={!data[ch].configured} onClick={() => test(ch)}>
                Send test
              </button>
            </div>
          ))}
          <div className="card text-sm">
            GeoIP:{' '}
            {data.geoip.mmdb_configured
              ? 'MaxMind database configured'
              : data.geoip.static_configured
                ? 'static mapping only'
                : 'not configured (public IPs stay unlocated)'}
            <p className="mt-1 text-xs text-slate-400">Deliveries: {JSON.stringify(data.deliveries)}</p>
          </div>
        </div>
      )}
    </State>
  )
}

function Audit() {
  const [page, setPage] = useState(1)
  const { data, error, loading, reload } = useAsync(() => api.audit({ page, size: 50 }), [page])
  return (
    <State loading={loading} error={error} empty={!!data && data.items.length === 0} onRetry={reload}>
      {data && (
        <>
          <div className="card overflow-x-auto p-0">
            <table className="w-full">
              <thead className="border-b border-line">
                <tr>
                  {['Time', 'Actor', 'Action', 'Target', 'Outcome', 'IP', 'Detail'].map((h) => (
                    <th key={h} className="th">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.items.map((a) => (
                  <tr key={a.id} className="border-b border-line/50">
                    <td className="td whitespace-nowrap text-xs">{fmt(a.created_at)}</td>
                    <td className="td">{a.actor}</td>
                    <td className="td">{a.action}</td>
                    <td className="td">{a.target}</td>
                    <td className={`td ${a.outcome === 'success' ? '' : 'text-amber-400'}`}>{a.outcome}</td>
                    <td className="td font-mono text-xs">{a.remote_ip}</td>
                    <td className="td text-xs">{a.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pagination page={page} size={50} total={data.total} onPage={setPage} />
        </>
      )}
    </State>
  )
}

function System() {
  const { data, error, loading, reload } = useAsync(() => api.settings(), [])
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  async function demo() {
    try {
      const r = await api.demoIngest()
      setMsg({ ok: true, text: `Loaded ${r.indexed} synthetic events, ${r.alerts_created} alerts created` })
    } catch (e) {
      setMsg({ ok: false, text: errText(e) })
    }
  }
  return (
    <State loading={loading} error={error} empty={!data} onRetry={reload}>
      {data && (
        <div className="space-y-3">
          <div className="card">
            <h2 className="mb-2 font-semibold">Effective settings (read-only; set via environment)</h2>
            <dl className="grid grid-cols-2 gap-1 text-sm">
              {Object.entries(data).map(([k, v]) => (
                <div key={k} className="contents">
                  <dt className="text-slate-400">{k}</dt>
                  <dd className="font-mono text-xs">{String(v)}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="card">
            <h2 className="mb-1 font-semibold">Synthetic demo data</h2>
            <p className="mb-2 text-sm text-slate-400">
              Loads clearly labelled synthetic events that trigger every detection. Available only when
              SIEM_ALLOW_DEMO_ENDPOINTS=true (never enabled in production).
            </p>
            <button className="btn" disabled={data.demo_endpoints_enabled !== true} onClick={demo}>
              Load synthetic scenarios
            </button>
            <Flash m={msg} />
          </div>
        </div>
      )}
    </State>
  )
}
