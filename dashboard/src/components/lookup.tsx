// IP address lookup: the form, the request logic and the result view are separate so the
// dashboard can show the form in a compact strip and the result as its own panel.
import { useRef, useState, type FormEvent } from "react";
import { fetchAlerts, fetchDevices, type Alert, type Device } from "../api";
import { fmtTime } from "../metrics";
import { countByLabel } from "../metrics";
import { Link } from "../router";
import { IconX } from "./icons";
import { Panel, SeverityBadge, StateBadge, StatusBadge } from "./ui";

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

export interface LookupResult {
  ip: string;
  device: Device | null;
  alerts: Alert[];
}

export type LookupState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "result"; result: LookupResult };

export function useIpLookup() {
  const [state, setState] = useState<LookupState>({ kind: "idle" });
  const request = useRef(0);

  const run = async (raw: string) => {
    const ip = raw.trim();
    const id = ++request.current;
    if (!IPV4.test(ip)) {
      setState({ kind: "error", message: "Enter a valid IPv4 address, for example 172.17.0.2." });
      return;
    }
    setState({ kind: "loading" });
    try {
      const [devices, alerts] = await Promise.all([fetchDevices(), fetchAlerts(500, ip)]);
      if (id !== request.current) return;
      setState({ kind: "result", result: { ip, device: devices.find((d) => d.ip === ip) ?? null, alerts } });
    } catch {
      if (id !== request.current) return;
      setState({ kind: "error", message: "Could not reach the monitor. Try again in a moment." });
    }
  };

  const clear = () => {
    request.current += 1;
    setState({ kind: "idle" });
  };

  return { state, run, clear };
}

export function LookupForm({
  id,
  state,
  onSubmit,
}: {
  id: string;
  state: LookupState;
  onSubmit: (ip: string) => void;
}) {
  const [value, setValue] = useState("");
  const submit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    onSubmit(value);
  };
  const busy = state.kind === "loading";
  return (
    <form className="lookup-form" onSubmit={submit} noValidate>
      <label htmlFor={id} className="sr-only">
        IP address
      </label>
      <input
        id={id}
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="Enter IP address (e.g. 172.17.0.2)"
        inputMode="decimal"
        autoComplete="off"
        spellCheck={false}
        aria-invalid={state.kind === "error"}
        aria-describedby={state.kind === "error" ? `${id}-error` : undefined}
      />
      <button type="submit" className="btn-primary" disabled={busy}>
        {busy ? "Looking up" : "Lookup"}
      </button>
      {state.kind === "error" && (
        <p id={`${id}-error`} className="form-error" role="alert">
          {state.message}
        </p>
      )}
    </form>
  );
}

export function LookupResultPanel({
  result,
  now,
  onClose,
}: {
  result: LookupResult;
  now: number;
  onClose?: () => void;
}) {
  const { ip, device, alerts } = result;
  const rows = countByLabel(alerts);
  const max = rows[0]?.count ?? 1;
  const seen = device !== null || alerts.length > 0;

  return (
    <Panel
      title={`Lookup result for ${ip}`}
      action={
        onClose && (
          <button type="button" className="icon-btn" aria-label="Close lookup result" onClick={onClose}>
            <IconX size={16} />
          </button>
        )
      }
    >
      {!seen ? (
        <p className="empty">The monitor has not seen {ip}.</p>
      ) : (
        <div className="lookup-body">
          {device && (
            <dl className="facts">
              <div>
                <dt>State</dt>
                <dd>
                  <StateBadge lastSeen={device.last_seen} now={now} />
                </dd>
              </div>
              <div>
                <dt>First seen</dt>
                <dd>{fmtTime(device.first_seen)}</dd>
              </div>
              <div>
                <dt>Last seen</dt>
                <dd>{fmtTime(device.last_seen)}</dd>
              </div>
              <div>
                <dt>Flows</dt>
                <dd>{device.flow_count}</dd>
              </div>
              <div>
                <dt>Alerts</dt>
                <dd>{device.alert_count}</dd>
              </div>
            </dl>
          )}
          {rows.length === 0 ? (
            <p className="empty">No alerts for this device.</p>
          ) : (
            <>
              <h3>Alerts by attack type</h3>
              <ul className="bars">
                {rows.map((r) => (
                  <li key={r.label}>
                    <span className="bars-label">{r.label}</span>
                    <span className="bars-track">
                      <span className="bars-fill" style={{ width: `${(r.count / max) * 100}%` }} />
                    </span>
                    <span className="bars-n">{r.count}</span>
                  </li>
                ))}
              </ul>
              <h3>Latest alerts</h3>
              <div className="table-scroll">
                <table className="data compact">
                  <thead>
                    <tr>
                      <th scope="col">Time</th>
                      <th scope="col">Severity</th>
                      <th scope="col">Attack type</th>
                      <th scope="col">Flows</th>
                      <th scope="col">Confidence</th>
                      <th scope="col">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alerts.slice(0, 8).map((a) => (
                      <tr key={a.id}>
                        <td className="nowrap">{fmtTime(a.ts_utc)}</td>
                        <td>
                          <SeverityBadge alert={a} />
                        </td>
                        <td>{a.label}</td>
                        <td className="num">{a.flow_count}</td>
                        <td className="num">{Math.round(a.avg_confidence * 100)}%</td>
                        <td>
                          <StatusBadge status={a.status} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="lookup-links">
                <Link to={`/alerts?device=${encodeURIComponent(ip)}`}>All alerts from this device</Link>
                <Link to={`/devices?device=${encodeURIComponent(ip)}`}>Incident report</Link>
              </p>
            </>
          )}
        </div>
      )}
    </Panel>
  );
}
