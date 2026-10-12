// Typed access to the monitor's REST API (served on :8080, proxied by nginx or vite as /api).

export interface Device {
  ip: string;
  first_seen: string;
  last_seen: string;
  flow_count: number;
  alert_count: number;
}

export interface Explanation {
  feature: string;
  text: string;
  weight: number;
}

export interface Alert {
  id: number;
  ts_utc: string;
  src_ip: string;
  label: string;
  flow_count: number;
  avg_confidence: number;
  status: string;
  explanation?: Explanation[];
}

export interface LabelCount {
  label: string;
  count: number;
}

// GET /api/stats counts across every stored alert. Older monitors do not have this route.
export interface Stats {
  total: number;
  new: number;
  last_24h: number;
  devices: number;
  by_label: LabelCount[];
}

export type AlertStatus = "new" | "acknowledged" | "dismissed";

// The API clamps `limit` to 500.
export const ALERT_LIMIT = 500;

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url} returned ${r.status}`);
  return (await r.json()) as T;
}

export function fetchAlerts(limit: number = ALERT_LIMIT, ip: string = ""): Promise<Alert[]> {
  const filter = ip ? `&src_ip=${encodeURIComponent(ip)}` : "";
  return getJson<Alert[]>(`/api/alerts?limit=${limit}${filter}`);
}

export const fetchDevices = (): Promise<Device[]> => getJson<Device[]>("/api/devices");

export const fetchStats = (): Promise<Stats> => getJson<Stats>("/api/stats");

export async function fetchHealth(): Promise<boolean> {
  try {
    const r = await fetch("/api/health");
    return r.ok;
  } catch {
    return false;
  }
}

export async function postStatus(id: number, status: AlertStatus): Promise<void> {
  const r = await fetch("/api/alerts/status", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, status }),
  });
  if (!r.ok) throw new Error(`status update returned ${r.status}`);
}
