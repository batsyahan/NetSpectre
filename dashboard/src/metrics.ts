// Pure calculations behind the dashboard numbers, kept out of the UI so they can be unit-tested.
import type { Alert, Device, LabelCount } from "./api";

export const ANOMALY = "Anomaly (unknown)";

// A device counts as online if it produced traffic in the last 5 minutes.
export const ONLINE_WINDOW_MS = 5 * 60_000;
// An attack counts as ongoing if a classified, still-unreviewed alert is under 10 minutes old.
export const ONGOING_WINDOW_MS = 10 * 60_000;

export type RangeId = "24h" | "7d" | "all";
export const RANGES: { id: RangeId; label: string; ms: number | null }[] = [
  { id: "24h", label: "Last 24 hours", ms: 24 * 3_600_000 },
  { id: "7d", label: "Last 7 days", ms: 7 * 24 * 3_600_000 },
  { id: "all", label: "All time", ms: null },
];

export function fmtTime(iso: string): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "Unknown";
  return new Date(t).toLocaleString("en-IN", { hourCycle: "h23" });
}

export type DeviceState = "online" | "offline" | "unknown";

export function deviceState(d: Pick<Device, "last_seen">, now: number): DeviceState {
  const t = Date.parse(d.last_seen);
  if (Number.isNaN(t)) return "unknown";
  return now - t <= ONLINE_WINDOW_MS ? "online" : "offline";
}

export function deviceStateCounts(devices: Pick<Device, "last_seen">[], now: number) {
  const c: Record<DeviceState, number> = { online: 0, offline: 0, unknown: 0 };
  for (const d of devices) c[deviceState(d, now)] += 1;
  return c;
}

export function inRange(alerts: Alert[], range: RangeId, now: number): Alert[] {
  const ms = RANGES.find((r) => r.id === range)?.ms ?? null;
  if (ms === null) return alerts;
  const cutoff = now - ms;
  return alerts.filter((a) => {
    const t = Date.parse(a.ts_utc);
    return !Number.isNaN(t) && t >= cutoff;
  });
}

export function countByLabel(alerts: { label: string }[]): LabelCount[] {
  const m = new Map<string, number>();
  for (const a of alerts) m.set(a.label, (m.get(a.label) ?? 0) + 1);
  return [...m.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((x, y) => y.count - x.count || x.label.localeCompare(y.label));
}

export const sum = (rows: { count: number }[]): number => rows.reduce((n, r) => n + r.count, 0);

// Percentage with one decimal, so a set of shares adds up to 100.0 more often than whole numbers do.
export function share(count: number, total: number): string {
  if (total <= 0) return "0.0";
  return ((count / total) * 100).toFixed(1);
}

export function ongoing(alerts: Alert[], now: number): { confirmed: number; anomalies: number } {
  let confirmed = 0;
  let anomalies = 0;
  for (const a of alerts) {
    const t = Date.parse(a.ts_utc);
    if (a.status !== "new" || Number.isNaN(t) || now - t > ONGOING_WINDOW_MS) continue;
    if (a.label === ANOMALY) anomalies += 1;
    else confirmed += 1;
  }
  return { confirmed, anomalies };
}

export interface SourceRow {
  ip: string;
  alerts: number;
  flows: number;
}

// Sources ranked by alert count, then by total flows. Devices with no alerts fill the list
// so a quiet network still shows its busiest hosts.
export function topSources(alerts: Alert[], devices: Device[], limit: number): SourceRow[] {
  const counts = new Map<string, number>();
  for (const a of alerts) counts.set(a.src_ip, (counts.get(a.src_ip) ?? 0) + 1);
  const flows = new Map(devices.map((d) => [d.ip, d.flow_count]));
  const ips = new Set<string>([...counts.keys(), ...devices.map((d) => d.ip)]);
  return [...ips]
    .map((ip) => ({ ip, alerts: counts.get(ip) ?? 0, flows: flows.get(ip) ?? 0 }))
    .sort((x, y) => y.alerts - x.alerts || y.flows - x.flows || x.ip.localeCompare(y.ip))
    .slice(0, limit);
}

export type BarTone = "red" | "orange" | "yellow" | "muted";

export function barTone(value: number, max: number): BarTone {
  if (value <= 0 || max <= 0) return "muted";
  const r = value / max;
  if (r >= 0.6) return "red";
  if (r >= 0.4) return "orange";
  if (r >= 0.25) return "yellow";
  return "muted";
}

// Fixed colors for the attack types the model emits most often, so a color always means the same
// thing. Any other label takes the next free color, in order of appearance.
const FIXED: Record<string, string> = {
  [ANOMALY]: "#2f8cff",
  PortScan: "#f58a1f",
  Heartbleed: "#2fd48f",
};
const EXTRA = ["#e0508f", "#e5b83b", "#18b6c9", "#e8664a", "#9fb0cc"];
export const OTHER_COLOR = "#6f7b8f";

export function attackColors(labels: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  const used = new Set(Object.values(FIXED));
  let next = 0;
  for (const l of labels) {
    if (FIXED[l]) {
      out[l] = FIXED[l];
      continue;
    }
    while (next < EXTRA.length && used.has(EXTRA[next])) next += 1;
    out[l] = EXTRA[next] ?? OTHER_COLOR;
    used.add(out[l]);
  }
  return out;
}

export interface Slice {
  label: string;
  value: number;
  color: string;
}

// At most `max` named slices; the remainder is folded into a gray "Other".
export function toSlices(rows: LabelCount[], max = 5): Slice[] {
  const named = rows.slice(0, max);
  const colors = attackColors(named.map((r) => r.label));
  const slices = named.map((r) => ({ label: r.label, value: r.count, color: colors[r.label] }));
  const rest = sum(rows.slice(max));
  return rest > 0 ? [...slices, { label: "Other", value: rest, color: OTHER_COLOR }] : slices;
}
