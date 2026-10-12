import { useState } from "react";
import { ALERT_LIMIT } from "../api";
import { AlertsTable } from "../components/AlertsTable";
import { IconAlert, IconArrowRight, IconBell, IconFile, IconMonitor } from "../components/icons";
import { LookupForm, LookupResultPanel, useIpLookup } from "../components/lookup";
import { Donut, Legend, MetricCard, Panel, Select } from "../components/ui";
import type { Monitor } from "../data";
import {
  RANGES,
  barTone,
  countByLabel,
  deviceStateCounts,
  fmtTime,
  inRange,
  ongoing,
  OTHER_COLOR,
  sum,
  toSlices,
  topSources,
  type RangeId,
} from "../metrics";
import { Link } from "../router";

const RECENT_ROWS = 8;
const LATEST_WINDOW = 50;
const rangeOptions = RANGES.map((r) => ({ value: r.id, label: r.label }));

export function DashboardPage({ m }: { m: Monitor }) {
  const { alerts, devices, stats, now, loaded } = m;
  // `known` is false until the first successful fetch, so an unreachable monitor never shows zeros as data.
  const known = m.updated !== null;
  const [chartRange, setChartRange] = useState<RangeId>("all");
  const [sourceRange, setSourceRange] = useState<RangeId>("all");
  const lookup = useIpLookup();

  const dash = (v: number | string) => (known ? String(v) : "--");

  // Totals come from /api/stats (every stored alert) when the monitor provides it,
  // otherwise from the newest alerts that were loaded.
  const total = stats?.total ?? alerts.length;
  const unreviewed = stats?.new ?? alerts.filter((a) => a.status === "new").length;
  const last24 = stats?.last_24h ?? inRange(alerts, "24h", now).length;
  const states = deviceStateCounts(devices, now);
  const attacks = ongoing(alerts, now);
  const allRows = stats?.by_label ?? countByLabel(alerts);

  const chartRows =
    chartRange === "all" && stats ? stats.by_label : countByLabel(inRange(alerts, chartRange, now));
  const chartTotal = sum(chartRows);
  const chartSlices = toSlices(chartRows);
  const truncated = (chartRange !== "all" || !stats) && alerts.length >= ALERT_LIMIT;

  const deviceSlices = [
    { label: "Online", value: states.online, color: "#2fd48f" },
    { label: "Offline", value: states.offline, color: "#f0524d" },
    { label: "Unknown", value: states.unknown, color: OTHER_COLOR },
  ];

  const sources = topSources(inRange(alerts, sourceRange, now), devices, 7);
  const maxAlerts = Math.max(0, ...sources.map((s) => s.alerts));
  const top = allRows[0];

  return (
    <>
      <div className="metrics">
        <MetricCard
          icon={<IconBell size={22} />}
          label="Total Alerts"
          value={dash(total)}
          note={known ? `${unreviewed} not yet reviewed` : loaded ? "Monitor unreachable" : "Loading"}
        />
        <MetricCard
          icon={<IconFile size={22} />}
          label="New Alerts (24h)"
          value={dash(last24)}
          note={known ? "Created in the last 24 hours" : loaded ? "Monitor unreachable" : "Loading"}
        />
        <MetricCard
          icon={<IconMonitor size={22} />}
          label="Active Devices"
          value={dash(states.online)}
          note={known ? `${states.offline} of ${devices.length} offline` : loaded ? "Monitor unreachable" : "Loading"}
        />
        <MetricCard
          icon={<IconAlert size={22} />}
          label="Ongoing Attacks"
          value={dash(attacks.confirmed)}
          note={
            !known
              ? loaded
                ? "Monitor unreachable"
                : "Loading"
              : attacks.anomalies > 0
              ? `${attacks.anomalies} unclassified in the last 10 min`
              : "Classified alerts, last 10 min"
          }
        />
      </div>

      <div className="row row-charts">
        <Panel
          title="Alerts by attack type"
          action={
            <Select label="Time range for attack types" value={chartRange} options={rangeOptions} onChange={setChartRange} />
          }
        >
          {chartTotal === 0 ? (
            <p className="empty">{!known ? (loaded ? "Alert data unavailable." : "Loading alerts.") : "No alerts in this period."}</p>
          ) : (
            <div className="chart-body">
              <Donut
                slices={chartSlices}
                total={chartTotal}
                caption="alerts"
                label={`Alerts by attack type: ${chartSlices.map((s) => `${s.label} ${s.value}`).join(", ")}`}
              />
              <Legend slices={chartSlices} total={chartTotal} />
            </div>
          )}
          {truncated && chartTotal > 0 && <p className="caption">Based on the newest {ALERT_LIMIT} alerts.</p>}
        </Panel>

        <Panel
          title="Device status"
          action={<span className="caption inline">Online means traffic in the last 5 minutes</span>}
        >
          {devices.length === 0 ? (
            <p className="empty">{!known ? (loaded ? "Device data unavailable." : "Loading devices.") : "No devices seen yet."}</p>
          ) : (
            <div className="chart-body">
              <Donut
                slices={deviceSlices}
                total={devices.length}
                caption="devices"
                label={`Device status: ${states.online} online, ${states.offline} offline, ${states.unknown} unknown`}
              />
              <Legend slices={deviceSlices} total={devices.length} />
            </div>
          )}
        </Panel>
      </div>

      <div className="row row-lookup">
        <Panel title="IP address lookup" className="lookup-panel">
          <LookupForm id="dash-lookup" state={lookup.state} onSubmit={lookup.run} />
        </Panel>
        <div className="mini">
          <div className="mini-label">Latest alerts</div>
          <div className="mini-value">{dash(Math.min(alerts.length, LATEST_WINDOW))}</div>
        </div>
        <div className="mini">
          <div className="mini-label">Newest alert</div>
          <div className="mini-value">{alerts[0] ? fmtTime(alerts[0].ts_utc) : known ? "No alerts yet" : "--"}</div>
        </div>
        <div className="mini">
          <div className="mini-label">Most common attack</div>
          <div className="mini-value">{top ? `${top.label} (${top.count})` : known ? "No alerts yet" : "--"}</div>
        </div>
      </div>

      {lookup.state.kind === "result" && (
        <LookupResultPanel result={lookup.state.result} now={now} onClose={lookup.clear} />
      )}

      <div className="row row-tables">
        <Panel
          title="Recent alerts"
          action={
            <Link to="/alerts" className="view-all">
              View all <IconArrowRight size={14} />
            </Link>
          }
        >
          <AlertsTable
            alerts={alerts.slice(0, RECENT_ROWS)}
            onStatus={m.setStatus}
            empty={
              !loaded
                ? "Loading alerts."
                : !known
                  ? "Cannot reach the monitor on port 8080."
                  : "No alerts yet. The network looks quiet."
            }
          />
        </Panel>

        <Panel
          title="Top source IPs"
          action={
            <Select label="Time range for source IPs" value={sourceRange} options={rangeOptions} onChange={setSourceRange} />
          }
        >
          {sources.length === 0 ? (
            <p className="empty">{!known ? (loaded ? "Device data unavailable." : "Loading devices.") : "No devices seen yet."}</p>
          ) : (
            <table className="data sources">
              <thead>
                <tr>
                  <th scope="col">IP address</th>
                  <th scope="col">Alerts</th>
                  <th scope="col" className="num">
                    Total flows
                  </th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.ip}>
                    <td className="mono">{s.ip}</td>
                    <td>
                      <span className="src-alerts">
                        <span className="src-bar">
                          <span
                            className={`src-fill tone-${barTone(s.alerts, maxAlerts)}`}
                            style={{ width: maxAlerts > 0 ? `${(s.alerts / maxAlerts) * 100}%` : "0%" }}
                          />
                        </span>
                        <span className={`src-n tone-${barTone(s.alerts, maxAlerts)}`}>{s.alerts}</span>
                      </span>
                    </td>
                    <td className="num">{s.flows}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="caption">Alert counts follow the selected range. Flows are lifetime totals per device.</p>
        </Panel>
      </div>
    </>
  );
}
