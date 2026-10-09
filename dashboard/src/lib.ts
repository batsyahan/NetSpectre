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
