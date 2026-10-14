// Pure helpers behind the Attack Map page (unit-tested in attackmap.test.ts).
import type { Alert, GeoResult } from "./api";
import { severityOf, type Severity } from "./lib";

export type TimeRange = "1h" | "24h" | "7d" | "all";
export const TIME_RANGES: { value: TimeRange; label: string; ms: number | null }[] = [
  { value: "1h", label: "Last hour", ms: 3_600_000 },
  { value: "24h", label: "Last 24 hours", ms: 86_400_000 },
  { value: "7d", label: "Last 7 days", ms: 7 * 86_400_000 },
  { value: "all", label: "All loaded alerts", ms: null },
];

export interface MapFilters {
  range: TimeRange;
  label: string; // "all" or an attack label
  severity: "all" | Severity;
  source: string; // "all" or a source IP
}

export function filterAlerts(alerts: Alert[], f: MapFilters, now: number): Alert[] {
  const ms = TIME_RANGES.find((r) => r.value === f.range)?.ms ?? null;
  return alerts.filter((a) => {
    if (ms !== null) {
      const t = Date.parse(a.ts_utc);
      if (Number.isNaN(t) || t < now - ms) return false;
    }
    if (f.label !== "all" && a.label !== f.label) return false;
    if (f.severity !== "all" && severityOf(a) !== f.severity) return false;
    if (f.source !== "all" && a.src_ip !== f.source) return false;
    return true;
  });
}

export interface MapSummary {
  alerts: number;
  sources: number;
  destinations: number;
  withoutDestination: number;
  highOrCritical: number;
  categories: number;
}

export function summarize(alerts: Alert[]): MapSummary {
  const dst = new Set<string>();
  let missing = 0;
  for (const a of alerts) {
    if (a.dst_ip) dst.add(a.dst_ip);
    else missing += 1;
  }
  return {
    alerts: alerts.length,
    sources: new Set(alerts.map((a) => a.src_ip)).size,
    destinations: dst.size,
    withoutDestination: missing,
    highOrCritical: alerts.filter((a) => {
      const s = severityOf(a);
      return s === "high" || s === "critical";
    }).length,
    categories: new Set(alerts.map((a) => a.label)).size,
  };
}

export const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low"];
export const SEV_COLOR: Record<Severity, string> = { critical: "#f0524d", high: "#f58a1f", medium: "#f5b93a", low: "#6db0ff" };

export interface SourceStat {
  ip: string;
  alerts: number;
  flows: number;
  bySeverity: Record<Severity, number>;
  worst: Severity;
}

export function sourceStats(alerts: Alert[]): SourceStat[] {
  const m = new Map<string, SourceStat>();
  for (const a of alerts) {
    const s = severityOf(a);
    const row = m.get(a.src_ip) ?? { ip: a.src_ip, alerts: 0, flows: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0 }, worst: "low" as Severity };
    row.alerts += 1;
    row.flows += a.flow_count;
    row.bySeverity[s] += 1;
    if (SEV_ORDER.indexOf(s) < SEV_ORDER.indexOf(row.worst)) row.worst = s;
    m.set(a.src_ip, row);
  }
  return [...m.values()].sort((x, y) => y.alerts - x.alerts || y.flows - x.flows || x.ip.localeCompare(y.ip));
}

// Where an address can be placed: never invent a location for private or unknown addresses.
export type Place = { kind: "local" } | { kind: "country"; code: string; name: string } | { kind: "unknown"; reason: string };

export function placeOf(geo: GeoResult | undefined, lookupAvailable: boolean): Place {
  if (!geo) return { kind: "unknown", reason: "not looked up yet" };
  if (geo.scope === "local") return { kind: "local" };
  if (geo.scope === "invalid") return { kind: "unknown", reason: "not an IP address" };
  if (!lookupAvailable) return { kind: "unknown", reason: "country database not installed" };
  if (geo.country) return { kind: "country", code: geo.country, name: geo.name ?? geo.country };
  return { kind: "unknown", reason: "not in the country database" };
}

export function placeLabel(p: Place): string {
  return p.kind === "local" ? "Local network" : p.kind === "country" ? p.name : "Unknown";
}

// Local-network view: sources on the left, destinations on the right, one edge per source/destination pair.
export interface TopoNode {
  id: string;
  side: "src" | "dst";
  alerts: number;
  worst: Severity;
  y: number;
}
export interface TopoEdge {
  src: string;
  dst: string;
  alerts: number;
  worst: Severity;
}

export const UNKNOWN_DST = "destination not recorded";

export function topology(alerts: Alert[], height: number, maxPerSide = 12): { nodes: TopoNode[]; edges: TopoEdge[]; hidden: number } {
  const edgeMap = new Map<string, TopoEdge>();
  const add = (m: Map<string, { alerts: number; worst: Severity }>, k: string, s: Severity) => {
    const r = m.get(k) ?? { alerts: 0, worst: "low" as Severity };
    r.alerts += 1;
    if (SEV_ORDER.indexOf(s) < SEV_ORDER.indexOf(r.worst)) r.worst = s;
    m.set(k, r);
  };
  const srcs = new Map<string, { alerts: number; worst: Severity }>();
  const dsts = new Map<string, { alerts: number; worst: Severity }>();
  for (const a of alerts) {
    const s = severityOf(a);
    const d = a.dst_ip || UNKNOWN_DST;
    add(srcs, a.src_ip, s);
    add(dsts, d, s);
    const key = `${a.src_ip}>${d}`;
    const e = edgeMap.get(key) ?? { src: a.src_ip, dst: d, alerts: 0, worst: "low" as Severity };
    e.alerts += 1;
    if (SEV_ORDER.indexOf(s) < SEV_ORDER.indexOf(e.worst)) e.worst = s;
    edgeMap.set(key, e);
  }
  const top = (m: Map<string, { alerts: number; worst: Severity }>) =>
    [...m.entries()].sort((x, y) => y[1].alerts - x[1].alerts || x[0].localeCompare(y[0])).slice(0, maxPerSide);
  const place = (rows: [string, { alerts: number; worst: Severity }][], side: "src" | "dst"): TopoNode[] =>
    rows.map(([id, r], i) => ({ id, side, alerts: r.alerts, worst: r.worst, y: ((i + 1) * height) / (rows.length + 1) }));
  const nodes = [...place(top(srcs), "src"), ...place(top(dsts), "dst")];
  const shownSrc = new Set(nodes.filter((n) => n.side === "src").map((n) => n.id));
  const shownDst = new Set(nodes.filter((n) => n.side === "dst").map((n) => n.id));
  const edges = [...edgeMap.values()].filter((e) => shownSrc.has(e.src) && shownDst.has(e.dst));
  const hidden = srcs.size - shownSrc.size + (dsts.size - shownDst.size);
  return { nodes, edges, hidden };
}

// ISO numeric codes are compared without leading zeros ("004" and "4" are the same country).
export const sameNumeric = (a: string | number, b: string | number) => Number(a) === Number(b);
