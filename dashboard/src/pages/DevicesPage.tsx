import { AlertsTable } from "../components/AlertsTable";
import { DeviceSummary } from "../components/DeviceSummary";
import { Panel, StateBadge } from "../components/ui";
import { useDeviceAlerts, type Monitor } from "../data";
import { fmtTime } from "../metrics";
import { navigate, useLocation } from "../router";

export function DevicesPage({ m }: { m: Monitor }) {
  const { params } = useLocation();
  const selected = params.get("device") ?? "";
  const history = useDeviceAlerts(selected, m.updated?.getTime() ?? 0);

  const pick = (ip: string) => navigate(selected === ip ? "/devices" : `/devices?device=${encodeURIComponent(ip)}`);

  return (
    <>
      <Panel title="Devices seen by the monitor">
        {m.devices.length === 0 ? (
          <p className="empty">{m.loaded ? "No devices seen yet." : "Loading devices."}</p>
        ) : (
          <div className="table-scroll">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Device (IP)</th>
                  <th scope="col">State</th>
                  <th scope="col">First seen</th>
                  <th scope="col">Last seen</th>
                  <th scope="col" className="num">
                    Flows
                  </th>
                  <th scope="col" className="num">
                    Alerts
                  </th>
                </tr>
              </thead>
              <tbody>
                {m.devices.map((d) => (
                  <tr
                    key={d.ip}
                    className={`pick${selected === d.ip ? " selected" : ""}`}
                    onClick={() => pick(d.ip)}
                  >
                    <td>
                      <button type="button" className="ip-btn mono" aria-pressed={selected === d.ip}>
                        {d.ip}
                      </button>
                    </td>
                    <td>
                      <StateBadge lastSeen={d.last_seen} now={m.now} />
                    </td>
                    <td className="nowrap">{fmtTime(d.first_seen)}</td>
                    <td className="nowrap">{fmtTime(d.last_seen)}</td>
                    <td className="num">{d.flow_count}</td>
                    <td className={d.alert_count > 0 ? "num has-alerts" : "num"}>{d.alert_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p className="caption">Select a device to see its alerts and to print an incident report.</p>
      </Panel>

      {selected && (
        <Panel title={`Alerts from ${selected}`}>
          <DeviceSummary ip={selected} alerts={history.rows} onClear={() => navigate("/devices")} />
          {history.failed && <p className="form-error">Could not load this device&apos;s alert history.</p>}
          <AlertsTable
            alerts={history.rows}
            onStatus={m.setStatus}
            showWhy
            empty={history.loading ? "Loading alerts." : "No alerts for this device."}
          />
        </Panel>
      )}
    </>
  );
}
