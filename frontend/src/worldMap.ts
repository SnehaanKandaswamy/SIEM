import { feature } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import land110m from 'world-atlas/land-110m.json'

/** Equirectangular projection of the populated latitudes (Antarctica and the high Arctic are cropped). */
export const LAT_MAX = 84
export const LAT_MIN = -58
export const MAP_W = 720
export const MAP_H = Math.round((MAP_W * (LAT_MAX - LAT_MIN)) / 360)

export const projX = (lon: number) => ((lon + 180) / 360) * MAP_W
export const projY = (lat: number) =>
  ((LAT_MAX - Math.max(LAT_MIN, Math.min(LAT_MAX, lat))) / (LAT_MAX - LAT_MIN)) * MAP_H

/** SVG path for all land masses, built once from the bundled Natural Earth 1:110m data (no network requests). */
export const LAND_PATH: string = (() => {
  const topo = land110m as unknown as Topology<{ land: GeometryCollection }>
  const geo = feature(topo, topo.objects.land)
  const rings: number[][][] = []
  for (const f of geo.features) {
    const g = f.geometry
    if (g.type === 'Polygon') rings.push(...g.coordinates)
    else if (g.type === 'MultiPolygon') g.coordinates.forEach((poly) => rings.push(...poly))
  }
  let d = ''
  for (const ring of rings) {
    if (ring.every(([, lat]) => lat < LAT_MIN)) continue // Antarctica: below the cropped area
    let prevLon: number | null = null
    for (const [lon, lat] of ring) {
      // start a new sub-path where a ring wraps across the antimeridian, so no line spans the whole map
      const jump = prevLon !== null && Math.abs(lon - prevLon) > 180
      d += `${prevLon === null || jump ? 'M' : 'L'}${projX(lon).toFixed(1)},${projY(lat).toFixed(1)}`
      prevLon = lon
    }
    d += 'Z'
  }
  return d
})()
