import { useEffect, useState } from "react";

interface Alert {
  id: number;
  ts_utc: string;
  src_ip: string;
  label: string;
  flow_count: number;
  avg_confidence: number;
  status: string;
}

const SEVERITY: Record<string, "critical" | "high" | "medium"> = {
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
const severityOf = (label: string) => SEVERITY[label] ?? "medium";

export default function App() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
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
        if (!stop) {
          setAlerts(rows);
          setOnline(true);
          setUpdated(new Date());
        }
      } catch {
        if (!stop) setOnline(false);
      }
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  }, []);

  const counts = new Map<string, number>();
  alerts.forEach((a) => counts.set(a.label, (counts.get(a.label) ?? 0) + 1));
  const top = [...counts.entries()].sort((x, y) => y[1] - x[1])[0];
  const fmt = (iso: string) => new Date(iso).toLocaleString("en-IN", { hour12: false });

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
        <h2>Alerts</h2>
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
              {alerts.map((a) => (
                <tr key={a.id} className={a.status === "dismissed" ? "dim" : ""}>
                  <td>{fmt(a.ts_utc)}</td>
                  <td>
                    <span className={`sev ${severityOf(a.label)}`}>{severityOf(a.label)}</span>
                  </td>
                  <td>{a.label}</td>
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
