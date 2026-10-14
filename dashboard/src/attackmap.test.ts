import { describe, expect, it } from "vitest";
import type { Alert } from "./api";
import { filterAlerts, placeOf, placeLabel, sourceStats, summarize, topology, UNKNOWN_DST } from "./attackmap";

const now = Date.parse("2026-10-15T12:00:00Z");
const al = (id: number, minsAgo: number, src: string, label: string, dst: string | null, conf = 0.9, flows = 10): Alert => ({
  id,
  ts_utc: new Date(now - minsAgo * 60_000).toISOString(),
  src_ip: src,
  label,
  flow_count: flows,
  avg_confidence: conf,
  status: "new",
  dst_ip: dst,
});

const alerts = [
  al(1, 5, "172.17.0.3", "PortScan", "172.17.0.1"),
  al(2, 30, "172.17.0.3", "DDoS", "172.17.0.1", 0.95, 40),
  al(3, 120, "8.8.8.8", "Anomaly (unknown)", null, 0.5, 5),
  al(4, 3000, "10.0.0.9", "SSH-Patator", "10.0.0.1"),
];

describe("Attack Map helpers", () => {
  it("filters by time, type, severity and source", () => {
    const base = { range: "all", label: "all", severity: "all", source: "all" } as const;
    expect(filterAlerts(alerts, { ...base, range: "1h" }, now).map((a) => a.id)).toEqual([1, 2]);
    expect(filterAlerts(alerts, { ...base, range: "24h" }, now).map((a) => a.id)).toEqual([1, 2, 3]);
    expect(filterAlerts(alerts, { ...base, label: "DDoS" }, now).map((a) => a.id)).toEqual([2]);
    expect(filterAlerts(alerts, { ...base, severity: "critical" }, now).map((a) => a.id)).toEqual([2]);
    expect(filterAlerts(alerts, { ...base, source: "8.8.8.8" }, now).map((a) => a.id)).toEqual([3]);
  });

  it("summarises the filtered alerts", () => {
    const s = summarize(alerts);
    expect(s).toEqual({ alerts: 4, sources: 3, destinations: 2, withoutDestination: 1, highOrCritical: 2, categories: 4 });
  });

  it("ranks sources and tracks their worst severity", () => {
    const top = sourceStats(alerts)[0];
    expect(top.ip).toBe("172.17.0.3");
    expect(top.alerts).toBe(2);
    expect(top.flows).toBe(50);
    expect(top.worst).toBe("critical");
  });

  it("never invents a location", () => {
    expect(placeLabel(placeOf({ scope: "local" }, true))).toBe("Local network");
    expect(placeOf({ scope: "public", country: "IN", name: "India" }, true)).toEqual({ kind: "country", code: "IN", name: "India" });
    expect(placeOf({ scope: "public", country: "IN", name: "India" }, false).kind).toBe("unknown");
    expect(placeOf({ scope: "public", country: null }, true).kind).toBe("unknown");
    expect(placeOf(undefined, true).kind).toBe("unknown");
  });

  it("builds a source/destination topology", () => {
    const t = topology(alerts, 300);
    expect(t.nodes.filter((n) => n.side === "src").map((n) => n.id)).toEqual(["172.17.0.3", "10.0.0.9", "8.8.8.8"]);
    expect(t.nodes.some((n) => n.id === UNKNOWN_DST)).toBe(true);
    expect(t.edges.find((e) => e.src === "172.17.0.3")).toMatchObject({ dst: "172.17.0.1", alerts: 2, worst: "critical" });
    expect(topology(alerts, 300, 1).hidden).toBe(4);
  });
});
