import { api } from '../api/client'
import { useAsync } from '../hooks'
import { PageHeader, State } from '../components/ui'
import { LAND_PATH, MAP_H as H, MAP_W as W, projX as x, projY as y } from '../worldMap'

/**
 * Plots only IPs that a configured GeoIP source located. The basemap is bundled Natural Earth land data, so no
 * tiles are fetched (no third-party requests). Private/reserved/unknown addresses are counted, never placed.
 */
export function Geo() {
  const { data, error, loading, reload } = useAsync(() => api.geo(), [], 30000)
  return (
    <>
      <PageHeader title="Attack map">
        <button className="btn" onClick={reload}>
          Refresh
        </button>
      </PageHeader>
      <State loading={loading} error={error} empty={!data} onRetry={reload}>
        {data && (
          <div className="grid gap-4 lg:grid-cols-3">
            <div className="card lg:col-span-2">
              <svg
                viewBox={`0 0 ${W} ${H}`}
                role="img"
                aria-label="Map of suspicious source locations"
                className="w-full rounded bg-bg"
              >
                <path d={LAND_PATH} fill="#17181a" stroke="#3a3d40" strokeWidth={0.4} />
                {[-30, 0, 30, 60].map((lat) => (
                  <line
                    key={lat}
                    x1={0}
                    x2={W}
                    y1={y(lat)}
                    y2={y(lat)}
                    stroke="#2a2c2f"
                    strokeWidth={lat === 0 ? 1 : 0.5}
                  />
                ))}
                {[-120, -60, 0, 60, 120].map((lon) => (
                  <line
                    key={lon}
                    y1={0}
                    y2={H}
                    x1={x(lon)}
                    x2={x(lon)}
                    stroke="#2a2c2f"
                    strokeWidth={lon === 0 ? 1 : 0.5}
                  />
                ))}
                {data.points.map((p) => (
                  <g key={p.ip}>
                    <circle cx={x(p.lon)} cy={y(p.lat)} r={4} fill="none" stroke="#ef4444" strokeWidth={1.5}>
                      <animate attributeName="r" from="4" to="22" dur="2.4s" repeatCount="indefinite" />
                      <animate
                        attributeName="opacity"
                        from="0.9"
                        to="0"
                        dur="2.4s"
                        repeatCount="indefinite"
                      />
                    </circle>
                    <circle
                      cx={x(p.lon)}
                      cy={y(p.lat)}
                      r={Math.min(4 + Math.log2(p.count + 1) * 1.5, 12)}
                      fill="#ef444488"
                      stroke="#ef4444"
                    />
                    <title>{`${p.ip} — ${p.city || 'unknown city'}, ${p.country || 'unknown country'}: ${p.count} events (${p.rules.join(', ')})`}</title>
                  </g>
                ))}
              </svg>
              {data.points.length === 0 && (
                <p className="mt-2 text-sm text-slate-400">
                  No located suspicious sources. Public IPs are placed only when a GeoIP source is configured
                  (SIEM_GEOIP_DB_PATH, or SIEM_GEOIP_STATIC_PATH for the demo data); private, reserved and
                  unknown addresses are never given coordinates.
                </p>
              )}
            </div>
            <div className="card">
              <h2 className="mb-2 font-semibold">Located sources</h2>
              <ul className="space-y-1 text-sm">
                {data.points.map((p) => (
                  <li key={p.ip} className="flex justify-between font-mono text-xs">
                    <span>
                      {p.ip}{' '}
                      <span className="text-slate-500">{[p.city, p.country].filter(Boolean).join(', ')}</span>
                    </span>
                    <span>{p.count}</span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-slate-400">
                Detection-related events without a location (private, reserved or unknown source):{' '}
                <b>{data.unlocated_events}</b>
              </p>
            </div>
          </div>
        )}
      </State>
    </>
  )
}
