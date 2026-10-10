// Alert severity rules, kept separate from the UI so they can be unit-tested.
export const SEVERITY: Record<string, "critical" | "high" | "medium"> = {
  DDoS: "critical",
  Bot: "critical",
  Infiltration: "critical",
  Heartbleed: "critical",
  "DoS Hulk": "high",
  "DoS GoldenEye": "high",
  "DoS Slowhttptest": "high",
  "DoS slowloris": "high",
  "SSH-Patator": "high",
  "FTP-Patator": "medium",
  PortScan: "medium",
  "Web Attack - Brute Force": "high",
  "Web Attack - Sql Injection": "high",
  "Web Attack - XSS": "high",
};
// Unknown-anomaly alerts barely above the threshold (confidence < 0.6) are low severity
export const severityOf = (a: { label: string; avg_confidence: number }) =>
  a.label === "Anomaly (unknown)" ? (a.avg_confidence < 0.6 ? "low" : "medium") : SEVERITY[a.label] ?? "medium";

export type Severity = ReturnType<typeof severityOf>;
const SEV_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface AlertLike {
  label: string;
  avg_confidence: number;
  ts_utc: string;
}

// Summary of one device's alerts: counts per attack, worst severity, first/latest alert time.
export function summarize(alerts: AlertLike[]) {
  const counts = new Map<string, number>();
  let top: Severity | null = null;
  let first = "";
  let last = "";
  for (const a of alerts) {
    counts.set(a.label, (counts.get(a.label) ?? 0) + 1);
    const sev = severityOf(a);
    if (top === null || SEV_RANK[sev] > SEV_RANK[top]) top = sev;
    if (first === "" || a.ts_utc < first) first = a.ts_utc;
    if (last === "" || a.ts_utc > last) last = a.ts_utc;
  }
  const byLabel = [...counts.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]));
  return { total: alerts.length, byLabel, top, first, last };
}
