import { useEffect, useState } from "react";
import { severityOf, summarize } from "./lib";

interface Device {
  ip: string;
  first_seen: string;
  last_seen: string;
  flow_count: number;
  alert_count: number;
}

interface Alert {
  id: number;
  ts_utc: string;
  src_ip: string;
  label: string;
  flow_count: number;
  avg_confidence: number;
  status: string;
  explanation?: { feature: string; text: string; weight: number }[];
}


export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [online, setOnline] = useState(false);
  const [updated, setUpdated] = useState<Date | null>(null);

  useEffect(() => {
    let stop = false;
    const load = async () => {
      try {
        const h = await fetch("/api/health");
        const a = await fetch("/api/alerts?limit=50");
        if (!h.ok || !a.ok) throw new Error("bad response");
        const rows: Alert[] = await a.json();
        const dv = await fetch("/api/devices");
        const devs: Device[] = dv.ok ? await dv.json() : [];
        if (!stop) {
          setAlerts(rows);
          setDevices(devs);
          setOnline(true);
          setUpdated(new Date());
        }
      } catch {
        if (!stop) setOnline(false);
      }
    };
    load();
    // Live push: reload as soon as the monitor stores a new alert. Polling stays as a slow fallback.
    const es = new EventSource("/api/stream");
    es.addEventListener("alert", () => load());
    const t = setInterval(load, 10000);
    return () => {
      stop = true;
      es.close();
      clearInterval(t);
    };
  }, []);

  const counts = new Map<string, number>();
  alerts.forEach((a) => counts.set(a.label, (counts.get(a.label) ?? 0) + 1));
  const top = [...counts.entries()].sort((x, y) => y[1] - x[1])[0];
  const fmt = (iso: string) => new Date(iso).toLocaleString("en-IN", { hour12: false });

  const [statusFilter, setStatusFilter] = useState("all");
  const [labelFilter, setLabelFilter] = useState("all");
  const [deviceFilter, setDeviceFilter] = useState("all");
  // When a device is selected, load that device's own alert history (not just the latest 50 overall).
  const [deviceAlerts, setDeviceAlerts] = useState<Alert[]>([]);
  useEffect(() => {
    if (deviceFilter === "all") {
      setDeviceAlerts([]);
      return;
    }
    let cancelled = false;
    fetch(`/api/alerts?limit=500&src_ip=${encodeURIComponent(deviceFilter)}`)
      .then((r) => (r.ok ? r.json() : []))
      .then((rows: Alert[]) => {
        if (!cancelled) setDeviceAlerts(rows);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [deviceFilter, alerts]);
  const base = deviceFilter === "all" ? alerts : deviceAlerts;
  const summary = deviceFilter === "all" ? null : summarize(deviceAlerts);
  const shown = base.filter(
    (a) =>
      (statusFilter === "all" || a.status === statusFilter) &&
      (labelFilter === "all" || a.label === labelFilter) &&
      (deviceFilter === "all" || a.src_ip === deviceFilter),
  );

  const setStatus = async (id: number, status: string) => {
    const r = await fetch("/api/alerts/status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id, status }),
    });
    if (r.ok) setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, status } : a)));
  };

  return (
    <main>
      <header>
        <h1>NetSpectre</h1>
        <span className={online ? "badge on" : "badge off"}>
          {online ? "Monitor online" : "Monitor offline"}
        </span>
      </header>

      <section className="cards">
        <div className="card">
          <div className="k">Alerts (latest 50)</div>
          <div className="v">{alerts.length}</div>
        </div>
        <div className="card">
          <div className="k">Newest alert</div>
          <div className="v small">{alerts[0] ? fmt(alerts[0].ts_utc) : "—"}</div>
        </div>
        <div className="card">
          <div className="k">Most common attack</div>
          <div className="v small">{top ? `${top[0]} (${top[1]})` : "—"}</div>
        </div>
      </section>

      <section className="panel">
        <h2>Devices</h2>
        {devices.length === 0 ? (
          <p className="empty">No devices seen yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Device (IP)</th>
                <th>First seen</th>
                <th>Last seen</th>
                <th>Flows</th>
                <th>Alerts</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr
                  key={d.ip}
                  className={`device-row${deviceFilter === d.ip ? " selected" : ""}`}
                  title="Click to show only this device's alerts"
                  onClick={() => setDeviceFilter(deviceFilter === d.ip ? "all" : d.ip)}
                >
                  <td className="mono">{d.ip}</td>
                  <td>{fmt(d.first_seen)}</td>
                  <td>{fmt(d.last_seen)}</td>
                  <td>{d.flow_count}</td>
                  <td className={d.alert_count > 0 ? "alert-count" : ""}>{d.alert_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <h2>Alerts</h2>
        {summary && (
          <div className="device-summary">
            <strong className="mono">{deviceFilter}</strong>
            <span>{summary.total} alerts</span>
            {summary.top && <span className={`sev ${summary.top}`}>{summary.top}</span>}
            {summary.first && <span>first {fmt(summary.first)}</span>}
            {summary.last && <span>latest {fmt(summary.last)}</span>}
            <span className="by-label">{summary.byLabel.map(([l, n]) => `${l} ×${n}`).join(" · ")}</span>
            <button className="chip" onClick={() => window.print()}>
              Print / save incident report (PDF)
            </button>
          </div>
        )}
        {summary && (
          <div className="report">
            <h1>NetSpectre incident report</h1>
            <p>
              Device <strong>{deviceFilter}</strong> · generated{" "}
              {new Date().toLocaleString("en-IN", { hour12: false })}
            </p>
            <p>
              {summary.total} alerts · highest severity <strong>{summary.top ?? "none"}</strong>
              {summary.first && <> · first alert {fmt(summary.first)}</>}
              {summary.last && <> · latest alert {fmt(summary.last)}</>}
            </p>
            <p>By attack type: {summary.byLabel.map(([l, n]) => `${l} ×${n}`).join(" · ")}</p>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Attack</th>
                  <th>Flows</th>
                  <th>Confidence</th>
                  <th>Status</th>
                  <th>Main reason</th>
                </tr>
              </thead>
              <tbody>
                {deviceAlerts.map((a) => (
                  <tr key={a.id}>
                    <td>{fmt(a.ts_utc)}</td>
                    <td>{severityOf(a)}</td>
                    <td>{a.label}</td>
                    <td>{a.flow_count}</td>
                    <td>{Math.round(a.avg_confidence * 100)}%</td>
                    <td>{a.status}</td>
                    <td>{a.explanation?.[0]?.text ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="note">
              Generated automatically by NetSpectre. Alerts are machine-learning predictions, not confirmed
              incidents; confidence is the model&apos;s own estimate and may include false positives.
            </p>
          </div>
        )}
        <div className="filters">
          <label>
            Status
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="all">All</option>
              <option value="new">New</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </label>
          <label>
            Attack
            <select value={labelFilter} onChange={(e) => setLabelFilter(e.target.value)}>
              <option value="all">All</option>
              {[...new Set(base.map((a) => a.label))].sort().map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </label>
          {deviceFilter !== "all" && (
            <button className="chip" onClick={() => setDeviceFilter("all")}>
              Device: {deviceFilter} ✕
            </button>
          )}
          <a className="export" href="/api/alerts/export" download>
            Export CSV
          </a>
          <span className="shown">
            Showing {shown.length} of {base.length}
          </span>
        </div>
        {alerts.length === 0 ? (
          <p className="empty">
            {online ? "No alerts yet. The network looks quiet." : "Cannot reach the monitor on port 8080."}
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Severity</th>
                <th>Attack</th>
                <th>Source</th>
                <th>Flows</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <tr key={a.id} className={a.status === "dismissed" ? "dim" : ""}>
                  <td>{fmt(a.ts_utc)}</td>
                  <td>
                    <span className={`sev ${severityOf(a)}`}>{severityOf(a)}</span>
                  </td>
                  <td>
                    {a.label}
                    {a.explanation && a.explanation.length > 0 && (
                      <div className="why">
                        Why: {a.explanation.map((r) => `${r.text} (${Math.round(r.weight)}%)`).join(", ")}
                      </div>
                    )}
                  </td>
                  <td className="mono">{a.src_ip}</td>
                  <td>{a.flow_count}</td>
                  <td>{Math.round(a.avg_confidence * 100)}%</td>
                  <td>{a.status}</td>
                  <td className="actions">
                    {a.status === "new" ? (
                      <>
                        <button onClick={() => setStatus(a.id, "acknowledged")}>Acknowledge</button>
                        <button onClick={() => setStatus(a.id, "dismissed")}>Dismiss</button>
                      </>
                    ) : (
                      <button onClick={() => setStatus(a.id, "new")}>Reopen</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <footer>{updated ? `Updated ${updated.toLocaleTimeString("en-IN", { hour12: false })}` : "Connecting…"}</footer>
    </main>
  );
}
