// Pure helpers behind the ML Advanced page (kept out of the UI so they can be unit-tested).
import type { Explanation, ModelEval, Prediction } from "./api";

export const SHORT_CLASS: Record<string, string> = {
  BENIGN: "Benign",
  Bot: "Bot",
  DDoS: "DDoS",
  "DoS GoldenEye": "GoldenEye",
  "DoS Hulk": "Hulk",
  "DoS Slowhttptest": "Slowhttp",
  "DoS slowloris": "Slowloris",
  "FTP-Patator": "FTP-Pat.",
  Heartbleed: "Heartbleed",
  Infiltration: "Infiltr.",
  PortScan: "PortScan",
  "SSH-Patator": "SSH-Pat.",
  "Web Attack - Brute Force": "Web BF",
  "Web Attack - Sql Injection": "SQLi",
  "Web Attack - XSS": "XSS",
};
export const shortClass = (c: string) => SHORT_CLASS[c] ?? c;

export function formatBytes(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}

export const pct = (x: number, digits = 1) => `${(x * 100).toFixed(digits)}%`;

export const PROTOCOLS: Record<number, string> = { 6: "TCP", 17: "UDP" };
export const protocolName = (p: number) => PROTOCOLS[p] ?? `IP proto ${p}`;

export function formatDuration(us: number): string {
  if (us < 1000) return `${Math.round(us)} µs`;
  if (us < 1e6) return `${(us / 1000).toFixed(1)} ms`;
  return `${(us / 1e6).toFixed(2)} s`;
}

// Cell colour intensity for a confusion matrix: log scale, because counts range from 1 to hundreds of thousands.
export function cellIntensity(count: number, max: number): number {
  if (count <= 0 || max <= 0) return 0;
  return Math.log10(count + 1) / Math.log10(max + 1);
}

// Each row divided by its total (share of the true class); rows with no flows stay at 0.
export function rowShares(cm: number[][]): number[][] {
  return cm.map((row) => {
    const t = row.reduce((a, b) => a + b, 0);
    return row.map((v) => (t > 0 ? v / t : 0));
  });
}

export function deployedModel(models: ModelEval[]): ModelEval | undefined {
  return models.find((m) => m.deployed) ?? models[models.length - 1];
}

// Index of the best model for a metric (highest, or lowest when lower is better); ties go to the first.
export function bestIndex(values: number[], lowerIsBetter = false): number {
  let best = 0;
  values.forEach((v, i) => {
    if (lowerIsBetter ? v < values[best] : v > values[best]) best = i;
  });
  return best;
}

// Reasons as bars: weight is each feature's share (%) of the top positive TreeSHAP contributions.
export function reasonBars(reasons: Explanation[] | null | undefined): { text: string; feature: string; share: number }[] {
  if (!reasons) return [];
  const rows = reasons.filter((r) => Number.isFinite(r.weight) && r.weight > 0);
  const total = rows.reduce((a, r) => a + r.weight, 0);
  return rows.map((r) => ({ text: r.text, feature: r.feature, share: total > 0 ? r.weight / total : 0 }));
}

export type PredictionSort = "time" | "confidence";

export function filterPredictions(rows: Prediction[], label: string, sort: PredictionSort): Prediction[] {
  const out = label === "all" ? [...rows] : rows.filter((p) => p.label === label);
  if (sort === "confidence") out.sort((a, b) => b.confidence - a.confidence || b.ts_utc.localeCompare(a.ts_utc));
  else out.sort((a, b) => b.ts_utc.localeCompare(a.ts_utc));
  return out;
}

export function page<T>(rows: T[], pageIndex: number, size: number): { rows: T[]; pages: number; index: number } {
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const index = Math.min(Math.max(pageIndex, 0), pages - 1);
  return { rows: rows.slice(index * size, index * size + size), pages, index };
}
