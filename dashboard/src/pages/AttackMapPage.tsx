// Attack Map (Live): where alerts come from and what they target.
// Data: the same alerts as the rest of the dashboard (useMonitor: /api/alerts plus the /api/stream event stream).
// Locations: only public addresses get a country, from the monitor's local DB-IP Lite lookup (/api/geo).
// Private addresses (172.17.x.x, 192.168.x.x, ...) are never placed on the world map; they appear in the network view.
import { useEffect, useMemo, useRef, useState } from "react";
import * as countries from "i18n-iso-countries";
import { geoCentroid, geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { Feature, FeatureCollection, Geometry } from "geojson";
import worldUrl from "world-atlas/countries-110m.json?url";
import { fetchGeo, type Alert, type GeoResult } from "../api";
import {
  filterAlerts,
  placeLabel,
  placeOf,
  sameNumeric,
  SEV_COLOR,
  SEV_ORDER,
  sourceStats,
  summarize,
  TIME_RANGES,
  topology,
  UNKNOWN_DST,
  type MapFilters,
  type Place,
  type TimeRange,
} from "../attackmap";
import { IconActivity, IconAlert, IconGlobe, IconMinus, IconMonitor, IconPlus, IconShield } from "../components/icons";
import { Donut, Legend, MetricCard, Panel, Select, SeverityBadge } from "../components/ui";
import type { Monitor } from "../data";
import { severityOf, type Severity } from "../lib";
import { countByLabel, fmtTime, toSlices } from "../metrics";

const MAP_W = 960;
const MAP_H = 470;
const NET_H = 380;

// ---------- country lookup for the addresses in the loaded alerts ----------
function useGeo(alerts: Alert[]) {
  const [results, setResults] = useState<Record<string, GeoResult>>({});
  const [available, setAvailable] = useState<boolean | null>(null);
  const [source, setSource] = useState("");
  const [failed, setFailed] = useState(false);
  const asked = useRef(new Set<string>());
  const ips = useMemo(() => {
    const s = new Set<string>();
    for (const a of alerts) {
      s.add(a.src_ip);
      if (a.dst_ip) s.add(a.dst_ip);
    }
    return [...s];
  }, [alerts]);
  useEffect(() => {
    const todo = ips.filter((ip) => !asked.current.has(ip)).slice(0, 200);
    if (todo.length === 0) return;
    todo.forEach((ip) => asked.current.add(ip));
    let alive = true;
    fetchGeo(todo)
      .then((r) => {
        if (!alive) return;
        setAvailable(r.available);
        setSource(r.source);
        setResults((prev) => ({ ...prev, ...r.results }));
        setFailed(false);
      })
      .catch(() => {
        todo.forEach((ip) => asked.current.delete(ip)); // retry on the next update
        if (alive) setFailed(true);
      });
    return () => {
      alive = false;
    };
  }, [ips]);
  return { results, available, source, failed };
}

// ---------- world geometry (Natural Earth 1:110m via world-atlas, bundled with the dashboard) ----------
type Country = Feature<Geometry, { name: string }>;
function useWorld() {
  const [world, setWorld] = useState<Country[] | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    let alive = true;
    fetch(worldUrl)
      .then((r) => r.json())
      .then((topo: Parameters<typeof feature>[0]) => {
        const fc = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry, { name: string }>;
        if (alive) setWorld(fc.features);
      })
      .catch(() => alive && setError(true));
    return () => {
      alive = false;
    };
  }, []);
  return { world, error };
}

export function AttackMapPage({ m }: { m: Monitor }) {
  const [f, setF] = useState<MapFilters>({ range: "24h", label: "all", severity: "all", source: "all" });
  const [view, setView] = useState<"network" | "world">("network");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const known = m.updated !== null;

  const filtered = useMemo(() => filterAlerts(m.alerts, f, m.now), [m.alerts, f, m.now]);
  const geo = useGeo(m.alerts);
  const place = (ip: string | null | undefined): Place =>
    ip ? placeOf(geo.results[ip], geo.available === true) : { kind: "unknown", reason: "destination not recorded" };
  const sum = summarize(filtered);
  const selected = filtered.find((a) => a.id === selectedId) ?? null;

  const labels = useMemo(() => [...new Set(m.alerts.map((a) => a.label))].sort(), [m.alerts]);
  const sources = useMemo(() => [...new Set(m.alerts.map((a) => a.src_ip))].sort(), [m.alerts]);
  const set = <K extends keyof MapFilters>(k: K, v: MapFilters[K]) => {
    setF((prev) => ({ ...prev, [k]: v }));
    setSelectedId(null);
  };
  const select = (a: Alert) => {
    setSelectedId(a.id);
    setView(place(a.src_ip).kind === "country" ? "world" : "network");
  };

  const dash = (v: number) => (known ? v.toLocaleString("en-IN") : "--");
  const rows = countByLabel(filtered);
  const slices = toSlices(rows, 6);

  const SEV_OPTIONS: { value: MapFilters["severity"]; label: string }[] = [
    { value: "all", label: "All severities" },
    ...SEV_ORDER.map((sev): { value: MapFilters["severity"]; label: string } => ({ value: sev, label: sev.charAt(0).toUpperCase() + sev.slice(1) })),
  ];

  return (
    <>
      <div className="map-filters panel">
        <Select label="Time range" showLabel value={f.range} options={TIME_RANGES.map((r) => ({ value: r.value, label: r.label }))} onChange={(v: TimeRange) => set("range", v)} />
        <Select label="Attack type" showLabel value={f.label} options={[{ value: "all", label: "All types" }, ...labels.map((l) => ({ value: l, label: l }))]} onChange={(v) => set("label", v)} />
        <Select
          label="Severity"
          showLabel
          value={f.severity}
          options={SEV_OPTIONS}
          onChange={(v: MapFilters["severity"]) => set("severity", v)}
        />
        <Select label="Device (source)" showLabel value={f.source} options={[{ value: "all", label: "All sources" }, ...sources.map((s) => ({ value: s, label: s }))]} onChange={(v) => set("source", v)} />
        <button type="button" className="btn-ghost" onClick={() => { setF({ range: "24h", label: "all", severity: "all", source: "all" }); setSelectedId(null); }}>
          Reset filters
        </button>
        <span className={`map-live ${m.online && !m.stale ? "on" : "off"}`}>
          <span className="dot" />
          {!known ? "Connecting" : m.online && !m.stale ? "Live: event stream connected" : "Monitor not reachable"}
        </span>
      </div>

      <div className="metrics metrics-5">
        <MetricCard icon={<IconAlert />} label="Alerts in period" value={dash(sum.alerts)} note="Grouped detections, not confirmed attacks" />
        <MetricCard icon={<IconActivity />} label="Unique sources" value={dash(sum.sources)} note="Addresses that triggered alerts" />
        <MetricCard
          icon={<IconMonitor />}
          label="Unique destinations"
          value={dash(sum.destinations)}
          note={sum.withoutDestination ? `${sum.withoutDestination} older alerts have no destination` : "Most frequent target per alert"}
        />
        <MetricCard icon={<IconShield />} label="High or critical" value={dash(sum.highOrCritical)} note="By NetSpectre's severity rules" />
        <MetricCard icon={<IconGlobe />} label="Attack categories" value={dash(sum.categories)} note="Distinct labels in the period" />
      </div>

      <div className="map-row">
        <Panel
          title={view === "world" ? "World view (public addresses)" : "Network view (local addresses)"}
          className="map-panel"
          action={
            <div className="seg" role="group" aria-label="Map view">
              <button type="button" aria-pressed={view === "network"} onClick={() => setView("network")}>
                Network
              </button>
              <button type="button" aria-pressed={view === "world"} onClick={() => setView("world")}>
                World
              </button>
            </div>
          }
        >
          {view === "world" ? (
            <WorldMap alerts={filtered} place={place} selected={selected} onSelect={select} geoAvailable={geo.available} geoFailed={geo.failed} />
          ) : (
            <NetworkMap alerts={filtered} selected={selected} onSelect={select} />
          )}
          <ul className="map-legend">
            {SEV_ORDER.map((s) => (
              <li key={s}>
                <span className="dot" style={{ background: SEV_COLOR[s] }} />
                {s[0].toUpperCase() + s.slice(1)}
              </li>
            ))}
          </ul>
        </Panel>
        <DetailsPanel alert={selected} place={place} onClear={() => setSelectedId(null)} />
      </div>

      <div className="map-row map-row-3">
        <EventsPanel alerts={filtered} place={place} selectedId={selectedId} onSelect={select} known={known} />
        <div className="map-side">
          <Panel title="Attack types in period">
            {sum.alerts === 0 ? (
              <p className="empty">No alerts match the filters.</p>
            ) : (
              <div className="donut-row">
                <Donut slices={slices} total={sum.alerts} caption="alerts" label="Alerts by attack type" size={150} />
                <Legend slices={slices} total={sum.alerts} />
              </div>
            )}
          </Panel>
          <TopSourcesPanel alerts={filtered} place={place} onPick={(ip) => set("source", ip)} />
        </div>
      </div>

      <p className="fine">
        Locations are estimates of where an address is registered, not where a person is, and an address that sends many alerts is not proof of a malicious actor.{" "}
        {geo.available ? (
          <>
            {geo.source.replace(/\s*\(https:\/\/db-ip\.com\).*/, "")}: <a href="https://db-ip.com">IP Geolocation by DB-IP</a>, licensed under{" "}
            <a href="https://creativecommons.org/licenses/by/4.0/">CC BY 4.0</a>.
          </>
        ) : (
          "Country lookup is off: run scripts/get_geoip.sh on the monitor machine and restart the monitor to enable the world view."
        )}
      </p>
    </>
  );
}

// ---------- world view ----------
function WorldMap({
  alerts,
  place,
  selected,
  onSelect,
  geoAvailable,
  geoFailed,
}: {
  alerts: Alert[];
  place: (ip: string | null | undefined) => Place;
  selected: Alert | null;
  onSelect: (a: Alert) => void;
  geoAvailable: boolean | null;
  geoFailed: boolean;
}) {
  const { world, error } = useWorld();
  const [zoom, setZoom] = useState(1);
  const projection = useMemo(() => geoNaturalEarth1().fitSize([MAP_W, MAP_H], { type: "Sphere" }), []);
  const path = useMemo(() => geoPath(projection), [projection]);

  // Alerts whose source has a country: one marker per country.
  const markers = useMemo(() => {
    if (!world) return [];
    const byCountry = new Map<string, { code: string; name: string; alerts: Alert[] }>();
    for (const a of alerts) {
      const p = place(a.src_ip);
      if (p.kind !== "country") continue;
      const row = byCountry.get(p.code) ?? { code: p.code, name: p.name, alerts: [] };
      row.alerts.push(a);
      byCountry.set(p.code, row);
    }
    const out: { code: string; name: string; alerts: Alert[]; xy: [number, number]; worst: Severity }[] = [];
    for (const row of byCountry.values()) {
      const numeric = countries.alpha2ToNumeric(row.code);
      const shape = numeric ? world.find((c) => c.id !== undefined && sameNumeric(c.id, numeric)) : undefined;
      const xy = shape ? projection(geoCentroid(shape)) : null;
      if (!xy) continue; // country not in the 1:110m map (very small states): listed in the table only
      const worst = row.alerts.map((a) => severityOf(a)).sort((x, y) => SEV_ORDER.indexOf(x) - SEV_ORDER.indexOf(y))[0];
      out.push({ ...row, xy: [xy[0], xy[1]], worst });
    }
    return out;
  }, [alerts, world, place, projection]);

  const local = alerts.filter((a) => place(a.src_ip).kind === "local").length;
  const unknown = alerts.length - local - markers.reduce((n, mk) => n + mk.alerts.length, 0);
  const cx = MAP_W / 2;
  const cy = MAP_H / 2;
  const focus = selected ? markers.find((mk) => mk.alerts.some((a) => a.id === selected.id)) : undefined;
  const [tx, ty] = focus && zoom > 1 ? [cx - focus.xy[0], cy - focus.xy[1]] : [0, 0];

  if (error) return <p className="empty">The world map could not be loaded.</p>;
  return (
    <div className="map-box">
      <svg viewBox={`0 0 ${MAP_W} ${MAP_H}`} className="world" role="img" aria-label="World map of alert sources with a known country">
        <g transform={`translate(${cx} ${cy}) scale(${zoom}) translate(${-cx + tx} ${-cy + ty})`}>
          <path d={path({ type: "Sphere" }) ?? ""} className="sphere" />
          {world?.map((c, i) => <path key={String(c.id ?? i)} d={path(c) ?? ""} className="land" />)}
          {markers.map((mk) => {
            const isSel = focus?.code === mk.code;
            const r = 4 + Math.min(10, Math.sqrt(mk.alerts.length) * 2);
            return (
              <g
                key={mk.code}
                className={`marker${isSel ? " sel" : ""}`}
                transform={`translate(${mk.xy[0]} ${mk.xy[1]})`}
                role="button"
                tabIndex={0}
                aria-label={`${mk.name}: ${mk.alerts.length} alerts`}
                onClick={() => onSelect(mk.alerts[0])}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onSelect(mk.alerts[0])}
              >
                <circle r={(r + 6) / zoom} fill={SEV_COLOR[mk.worst]} opacity={0.25} />
                <circle r={r / zoom} fill={SEV_COLOR[mk.worst]} stroke="#0d141b" strokeWidth={1.5 / zoom} />
                <title>{`${mk.name}: ${mk.alerts.length} alert${mk.alerts.length === 1 ? "" : "s"} (source location)`}</title>
              </g>
            );
          })}
        </g>
      </svg>
      <div className="zoom">
        <button type="button" className="btn-ghost btn-icon" aria-label="Zoom in" onClick={() => setZoom((z) => Math.min(8, z * 1.6))}>
          <IconPlus size={16} />
        </button>
        <button type="button" className="btn-ghost btn-icon" aria-label="Zoom out" onClick={() => setZoom((z) => Math.max(1, z / 1.6))}>
          <IconMinus size={16} />
        </button>
        <button type="button" className="btn-ghost btn-small" onClick={() => setZoom(1)}>
          Reset
        </button>
      </div>
      <p className="map-note">
        {!world && "Loading map… "}
        {geoAvailable === false && "Country database not installed, so no public address can be placed. "}
        {geoFailed && "Country lookup failed; retrying on the next update. "}
        {markers.length === 0 && alerts.length > 0 && "No alert in this period comes from a public address with a known country. "}
        {local > 0 && `${local} alert${local === 1 ? "" : "s"} from local addresses are shown in the Network view. `}
        {unknown > 0 && `${unknown} with unknown location. `}
        Markers sit at the centre of the country; zoom centres on the selected one.
      </p>
    </div>
  );
}

// ---------- network view ----------
function NetworkMap({ alerts, selected, onSelect }: { alerts: Alert[]; selected: Alert | null; onSelect: (a: Alert) => void }) {
  const [zoom, setZoom] = useState(1);
  const t = useMemo(() => topology(alerts, NET_H), [alerts]);
  const X = { src: 190, dst: MAP_W - 190 };
  const pos = new Map(t.nodes.map((n) => [`${n.side}:${n.id}`, n]));
  const selSrc = selected?.src_ip;
  const selDst = selected ? selected.dst_ip || UNKNOWN_DST : undefined;
  const latestFrom = (pred: (a: Alert) => boolean) => alerts.find(pred);

  if (alerts.length === 0) return <p className="empty map-empty">No alerts match the filters.</p>;
  return (
    <div className="map-box">
      <svg viewBox={`0 0 ${MAP_W} ${NET_H}`} className="net" role="img" aria-label="Sources and the destinations they targeted">
        <g transform={`translate(${MAP_W / 2} ${NET_H / 2}) scale(${zoom}) translate(${-MAP_W / 2} ${-NET_H / 2})`}>
          <text x={X.src} y={16} className="net-head" textAnchor="middle">
            Sources
          </text>
          <text x={X.dst} y={16} className="net-head" textAnchor="middle">
            Targets
          </text>
          {t.edges.map((e) => {
            const a = pos.get(`src:${e.src}`)!;
            const b = pos.get(`dst:${e.dst}`)!;
            const on = e.src === selSrc && e.dst === selDst;
            const mid = (X.src + X.dst) / 2;
            return (
              <path
                key={`${e.src}>${e.dst}`}
                d={`M ${X.src + 8} ${a.y} C ${mid} ${a.y}, ${mid} ${b.y}, ${X.dst - 8} ${b.y}`}
                className={`edge${on ? " sel" : ""}`}
                stroke={SEV_COLOR[e.worst]}
                strokeWidth={1.2 + Math.min(5, Math.log2(e.alerts + 1))}
              >
                <title>{`${e.src} → ${e.dst}: ${e.alerts} alert${e.alerts === 1 ? "" : "s"}`}</title>
              </path>
            );
          })}
          {t.nodes.map((n) => {
            const x = n.side === "src" ? X.src : X.dst;
            const on = n.side === "src" ? n.id === selSrc : n.id === selDst;
            const pick = latestFrom((a) => (n.side === "src" ? a.src_ip === n.id : (a.dst_ip || UNKNOWN_DST) === n.id));
            return (
              <g
                key={`${n.side}:${n.id}`}
                className={`node${on ? " sel" : ""}`}
                transform={`translate(${x} ${n.y})`}
                role="button"
                tabIndex={0}
                aria-label={`${n.side === "src" ? "Source" : "Target"} ${n.id}: ${n.alerts} alerts`}
                onClick={() => pick && onSelect(pick)}
                onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && pick && onSelect(pick)}
              >
                <circle r={7} fill={SEV_COLOR[n.worst]} stroke="#0d141b" strokeWidth={2} />
                <text x={n.side === "src" ? -14 : 14} y={4} textAnchor={n.side === "src" ? "end" : "start"} className={n.id === UNKNOWN_DST ? "net-label muted-label" : "net-label"}>
                  {n.id} ({n.alerts})
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      <div className="zoom">
        <button type="button" className="btn-ghost btn-icon" aria-label="Zoom in" onClick={() => setZoom((z) => Math.min(3, z * 1.4))}>
          <IconPlus size={16} />
        </button>
        <button type="button" className="btn-ghost btn-icon" aria-label="Zoom out" onClick={() => setZoom((z) => Math.max(1, z / 1.4))}>
          <IconMinus size={16} />
        </button>
        <button type="button" className="btn-ghost btn-small" onClick={() => setZoom(1)}>
          Reset
        </button>
      </div>
      <p className="map-note">
        Line colour shows the worst severity between the two addresses, thickness the number of alerts. Targets are the most frequent destination of each alert's
        flows.{t.hidden > 0 && ` ${t.hidden} less active addresses are not drawn; narrow the filters to see them.`}
      </p>
    </div>
  );
}

// ---------- details of the selected event ----------
function DetailsPanel({ alert: a, place, onClear }: { alert: Alert | null; place: (ip: string | null | undefined) => Place; onClear: () => void }) {
  return (
    <Panel
      title="Event details"
      className="map-details"
      action={
        a ? (
          <button type="button" className="btn-ghost btn-small" onClick={onClear}>
            Clear
          </button>
        ) : undefined
      }
    >
      {!a ? (
        <p className="empty">Select a marker, a node or a row in the table.</p>
      ) : (
        <>
          <dl className="facts explain-facts">
            <div>
              <dt>Attack type</dt>
              <dd>
                {a.label} <SeverityBadge alert={a} />
              </dd>
            </div>
            <div>
              <dt>Time</dt>
              <dd>{fmtTime(a.ts_utc)}</dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd>
                <span className="mono">{a.src_ip}</span> · {placeLabel(place(a.src_ip))}
              </dd>
            </div>
            <div>
              <dt>Target</dt>
              <dd>
                {a.dst_ip ? (
                  <>
                    <span className="mono">{a.dst_ip}</span> · {placeLabel(place(a.dst_ip))}
                    {a.dst_count && a.dst_count > 1 ? ` (and ${a.dst_count - 1} other)` : ""}
                  </>
                ) : (
                  "Not recorded (alert from before destinations were stored)"
                )}
              </dd>
            </div>
            <div>
              <dt>{a.label === "PortScan" ? "Ports probed" : "Flows"}</dt>
              <dd>{a.flow_count}</dd>
            </div>
            <div>
              <dt>Confidence</dt>
              <dd>{Math.round(a.avg_confidence * 100)}%</dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{a.status}</dd>
            </div>
          </dl>
          {a.explanation && a.explanation.length > 0 && (
            <p className="why">Why: {a.explanation.map((r) => r.text).join("; ")}</p>
          )}
        </>
      )}
    </Panel>
  );
}

// ---------- events table ----------
function EventsPanel({
  alerts,
  place,
  selectedId,
  onSelect,
  known,
}: {
  alerts: Alert[];
  place: (ip: string | null | undefined) => Place;
  selectedId: number | null;
  onSelect: (a: Alert) => void;
  known: boolean;
}) {
  const [limit, setLimit] = useState(12);
  const rows = alerts.slice(0, limit);
  return (
    <Panel title="Recent map events">
      {!known ? (
        <p className="empty">Connecting to the monitor…</p>
      ) : alerts.length === 0 ? (
        <p className="empty">No alerts match the filters.</p>
      ) : (
        <>
          <div className="table-scroll">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Source</th>
                  <th scope="col">Target</th>
                  <th scope="col">Attack type</th>
                  <th scope="col">Severity</th>
                  <th scope="col" className="num">
                    Flows
                  </th>
                  <th scope="col">Source location</th>
                  <th scope="col" className="col-actions">
                    Map
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => {
                  const p = place(a.src_ip);
                  return (
                    <tr key={a.id} className={a.id === selectedId ? "row-selected" : undefined}>
                      <td className="nowrap">{fmtTime(a.ts_utc)}</td>
                      <td className="mono nowrap">{a.src_ip}</td>
                      <td className="mono nowrap">{a.dst_ip ?? "—"}</td>
                      <td>{a.label}</td>
                      <td>
                        <SeverityBadge alert={a} />
                      </td>
                      <td className="num">{a.flow_count}</td>
                      <td title={p.kind === "unknown" ? p.reason : undefined}>{placeLabel(p)}</td>
                      <td className="col-actions">
                        <button type="button" className="btn-ghost btn-small" aria-pressed={a.id === selectedId} onClick={() => onSelect(a)}>
                          Show
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {alerts.length > limit && (
            <div className="pager">
              <span className="muted">
                Showing {limit} of {alerts.length}
              </span>
              <button type="button" className="btn-ghost btn-small" onClick={() => setLimit((l) => l + 25)}>
                Show more
              </button>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

// ---------- top sources ----------
function TopSourcesPanel({ alerts, place, onPick }: { alerts: Alert[]; place: (ip: string | null | undefined) => Place; onPick: (ip: string) => void }) {
  const top = sourceStats(alerts).slice(0, 7);
  return (
    <Panel title="Top sources in period">
      {top.length === 0 ? (
        <p className="empty">No alerts match the filters.</p>
      ) : (
        <ul className="srcs">
          {top.map((s) => (
            <li key={s.ip}>
              <button type="button" className="link-btn mono" onClick={() => onPick(s.ip)} title="Show only this source">
                {s.ip}
              </button>
              <span className="muted srcs-place">{placeLabel(place(s.ip))}</span>
              <span className="sevbar" aria-label={SEV_ORDER.map((k) => `${s.bySeverity[k]} ${k}`).join(", ")}>
                {SEV_ORDER.map((k) =>
                  s.bySeverity[k] ? <span key={k} style={{ flex: s.bySeverity[k], background: SEV_COLOR[k] }} title={`${s.bySeverity[k]} ${k}`} /> : null,
                )}
              </span>
              <span className="srcs-n">
                {s.alerts} alerts · {s.flows.toLocaleString("en-IN")} flows
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="fine">Ranked by alerts in the period; many alerts from one address is not by itself proof of an attacker.</p>
    </Panel>
  );
}
