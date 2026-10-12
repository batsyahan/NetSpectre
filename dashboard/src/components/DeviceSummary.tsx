// Per-device summary bar plus the printable incident report (browser "Save as PDF").
// The report is rendered into document.body and only shown by the @media print rules.
import { createPortal } from "react-dom";
import type { Alert } from "../api";
import { severityOf, summarize } from "../lib";
import { fmtTime } from "../metrics";

export function DeviceSummary({ ip, alerts, onClear }: { ip: string; alerts: Alert[]; onClear?: () => void }) {
  const s = summarize(alerts);
  const byLabel = s.byLabel.map(([l, n]) => `${l} x${n}`).join(", ");
  return (
    <>
      <div className="device-summary">
        <strong className="mono">{ip}</strong>
        <span>{s.total} alerts</span>
        {s.top && <span className={`tag sev-${s.top}`}>{s.top[0].toUpperCase() + s.top.slice(1)}</span>}
        {s.first && <span>First {fmtTime(s.first)}</span>}
        {s.last && <span>Latest {fmtTime(s.last)}</span>}
        {byLabel && <span className="by-label">{byLabel}</span>}
        <span className="grow" />
        {onClear && (
          <button type="button" className="btn-ghost" onClick={onClear}>
            Clear selection
          </button>
        )}
        <button type="button" className="btn-ghost" onClick={() => window.print()}>
          Print or save incident report (PDF)
        </button>
      </div>
      {createPortal(
        <div className="report">
          <h1>NetSpectre incident report</h1>
          <p>
            Device <strong>{ip}</strong>, generated {new Date().toLocaleString("en-IN", { hourCycle: "h23" })}
          </p>
          <p>
            {s.total} alerts, highest severity <strong>{s.top ?? "none"}</strong>
            {s.first && <>, first alert {fmtTime(s.first)}</>}
            {s.last && <>, latest alert {fmtTime(s.last)}</>}
          </p>
          <p>By attack type: {byLabel || "none"}</p>
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
              {alerts.map((a) => (
                <tr key={a.id}>
                  <td>{fmtTime(a.ts_utc)}</td>
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
            Generated automatically by NetSpectre. Alerts are machine-learning predictions, not confirmed incidents;
            confidence is the model&apos;s own estimate and may include false positives.
          </p>
        </div>,
        document.body,
      )}
    </>
  );
}
