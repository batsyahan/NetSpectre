// Typed access to the monitor's REST API (served on :8080, proxied by nginx or vite as /api).
import { authHeaders } from "./auth";

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
  dst_ip?: string | null; // most frequent destination of the grouped flows (older alerts: null)
  dst_count?: number | null; // number of different destinations among the grouped flows
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

// Thrown when the monitor rejects the request because this device has no (or a wrong) API token.
export class AuthError extends Error {}

async function getJson<T>(url: string): Promise<T> {
  const r = await fetch(url, { headers: authHeaders() });
  if (r.status === 401) throw new AuthError("API token required");
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
    const r = await fetch("/api/health", { headers: authHeaders() });
    return r.ok;
  } catch {
    return false;
  }
}

export async function postStatus(id: number, status: AlertStatus): Promise<void> {
  const r = await fetch("/api/alerts/status", {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: JSON.stringify({ id, status }),
  });
  if (!r.ok) throw new Error(`status update returned ${r.status}`);
}

// ---- ML Advanced ----

// Live classifier counters measured by the monitor since it started (GET /api/ml).
export interface MlStats {
  since: string;
  classified: number;
  errors: number;
  invalid_input: number;
  avg_latency_ms: number;
  max_latency_ms: number;
  by_label: LabelCount[];
  flows_refused: number;
  flows_queue_dropped: number;
}

// One recent non-benign prediction (GET /api/predictions), kept in the monitor's memory.
export interface Prediction {
  ts_utc: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  model_label: string;
  label: string;
  confidence: number;
  anomaly_score: number;
  counts_toward_alert: boolean;
  latency_ms: number;
  flow_duration_us: number;
  fwd_packets: number;
  bwd_packets: number;
  fwd_bytes: number;
  bwd_bytes: number;
  reasons: Explanation[] | null;
}

export interface ClassScore {
  precision: number;
  recall: number;
  f1: number;
  support: number;
}

export interface ModelEval {
  name: string;
  file: string;
  size_bytes: number;
  params: string;
  trained_on: string;
  latency_ms: number;
  deployed: boolean;
  accuracy: number;
  macro_precision: number;
  macro_recall: number;
  macro_f1: number;
  weighted_f1: number;
  benign_fpr: number;
  per_class: Record<string, ClassScore>;
  confusion_matrix: number[][];
}

export interface LodoRow {
  label: string;
  flows: number;
  classifier: number;
  either_ae_0_5: number;
}

// Static evaluation report written by ml/export_model_report.py into dashboard/public/model_report.json.
export interface ModelReport {
  generated_at: string;
  test_set: { flows: number; source: string; split: string };
  features: string[];
  classes: string[];
  deployed_model: string;
  models: ModelEval[];
  feature_importance: { feature: string; share: number }[];
  feature_importance_method?: string;
  autoencoder: {
    model: string;
    threshold: number;
    layers: string;
    cicids_benign_flagged: number;
    own_network: { flows: number; flagged: number } | null;
    attack_flagged: Record<string, number>;
  };
  leave_one_day_out: { day: string; attacks: LodoRow[]; benign_fpr?: LodoRow; all_attacks?: LodoRow }[];
  leave_one_day_out_note?: string;
  cicids2018?: Cic2018 | null;
}

// CSE-CIC-IDS2018 results per model version (values are fractions 0..1), from docs/EVAL_V8.txt.
export interface Cic2018Row {
  label: string;
  flows?: number;
  caught?: Record<string, number>;
  right?: Record<string, number>;
}
export interface Cic2018 {
  models: string[];
  benign?: Cic2018Row;
  all_attacks?: Cic2018Row;
  attacks: Cic2018Row[];
  note: string;
}

export const fetchMlStats = (): Promise<MlStats> => getJson<MlStats>("/api/ml");

export const fetchPredictions = (limit = 300): Promise<Prediction[]> =>
  getJson<Prediction[]>(`/api/predictions?limit=${limit}`);

export async function fetchModelReport(): Promise<ModelReport> {
  const r = await fetch("/model_report.json", { cache: "no-store" });
  if (!r.ok) throw new Error(`model_report.json returned ${r.status}`);
  return (await r.json()) as ModelReport;
}

// ---- Attack Map ----
export interface GeoResult {
  scope: "local" | "public" | "invalid";
  country?: string | null; // ISO 3166-1 alpha-2
  name?: string | null;
}
export interface GeoResponse {
  available: boolean;
  source: string;
  results: Record<string, GeoResult>;
}

export const fetchGeo = (ips: string[]): Promise<GeoResponse> =>
  getJson<GeoResponse>(`/api/geo?ips=${encodeURIComponent(ips.join(","))}`);
