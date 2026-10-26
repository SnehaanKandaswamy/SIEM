import { api } from '../api/client'
import { useAsync } from '../hooks'
import { PageHeader, SEV_COLOR, State } from '../components/ui'
import type { Severity } from '../api/client'

export function Mitre() {
  const { data, error, loading, reload } = useAsync(() => api.mitre(), [])
  return (
    <>
      <PageHeader title="MITRE ATT&CK coverage">
        <a className="btn" href="https://attack.mitre.org/" target="_blank" rel="noreferrer noopener">
          attack.mitre.org ↗
        </a>
      </PageHeader>
      <p className="mb-3 text-sm text-slate-400">
        Only mappings justified by the detected behaviour are shown. Techniques below are implemented by an
        enabled or disabled rule; anything not listed is not covered.
      </p>
      <State
        loading={loading}
        error={error}
        empty={!!data && data.techniques.length === 0}
        emptyText="No technique mappings."
        onRetry={reload}
      >
        {data && (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {data.techniques.map((t) => (
                <div key={t.technique_id} className="card">
                  <div className="flex items-start justify-between">
                    <div>
                      <a
                        className="font-mono text-sky-300 hover:underline"
                        href={t.url}
                        target="_blank"
                        rel="noreferrer noopener"
                      >
                        {t.technique_id}
                      </a>
                      <div className="font-semibold">{t.technique}</div>
                      <div className="text-xs text-slate-400">Tactic: {t.tactic}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold">{t.alert_count}</div>
                      <div className="text-xs text-slate-400">alerts</div>
                    </div>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1 text-xs">
                    {Object.entries(t.by_severity).map(([s, c]) => (
                      <span key={s} style={{ color: SEV_COLOR[s as Severity] }}>
                        {s}: {c}
                      </span>
                    ))}
                  </div>
                  <ul className="mt-2 text-xs text-slate-400">
                    {t.rules.map((r) => (
                      <li key={r.rule_id}>
                        {r.rule_id} {r.name} {r.enabled ? '' : '(disabled)'}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
            {data.unmapped_rules.length > 0 && (
              <div className="card">
                <h2 className="mb-1 font-semibold">Rules without a technique mapping</h2>
                <ul className="text-sm text-slate-400">
                  {data.unmapped_rules.map((r) => (
                    <li key={r.rule_id}>
                      {r.rule_id} {r.name}: {r.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </State>
    </>
  )
}
