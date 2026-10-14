import { useState } from "react";
import { AlertsTable } from "../components/AlertsTable";
import { DeviceSummary } from "../components/DeviceSummary";
import { Panel, Select } from "../components/ui";
import { useDeviceAlerts, type Monitor } from "../data";
import { navigate, useLocation } from "../router";
import { withToken } from "../auth";

const STATUS_OPTIONS = [
  { value: "all", label: "All" },
  { value: "new", label: "New" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "dismissed", label: "Dismissed" },
];

export function AlertsPage({ m }: { m: Monitor }) {
  const { params } = useLocation();
  const device = params.get("device") ?? "";
  const [status, setStatus] = useState("all");
  const [label, setLabel] = useState("all");
  const history = useDeviceAlerts(device, m.updated?.getTime() ?? 0);

  const base = device ? history.rows : m.alerts;
  const labels = [...new Set(base.map((a) => a.label))].sort();
  const labelOptions = [{ value: "all", label: "All" }, ...labels.map((l) => ({ value: l, label: l }))];
  const shown = base.filter(
    (a) => (status === "all" || a.status === status) && (label === "all" || a.label === label),
  );

  return (
    <Panel title={device ? `Alerts from ${device}` : "All alerts"}>
      {device && <DeviceSummary ip={device} alerts={history.rows} onClear={() => navigate("/alerts")} />}
      <div className="filters">
        <Select showLabel label="Status" value={status} options={STATUS_OPTIONS} onChange={setStatus} />
        <Select showLabel label="Attack type" value={label} options={labelOptions} onChange={setLabel} />
        <span className="grow" />
        <span className="caption inline">
          Showing {shown.length} of {base.length}
          {!device && base.length >= 500 ? " (newest 500)" : ""}
        </span>
        <a className="btn-ghost" href={withToken("/api/alerts/export")} download>
          Export CSV
        </a>
      </div>
      {history.failed && <p className="form-error">Could not load this device&apos;s alert history.</p>}
      <AlertsTable
        alerts={shown}
        onStatus={m.setStatus}
        showWhy
        empty={
          !m.loaded
            ? "Loading alerts."
            : history.loading
              ? "Loading alerts."
              : base.length === 0
                ? m.online
                  ? "No alerts yet. The network looks quiet."
                  : "Cannot reach the monitor on port 8080."
                : "No alerts match these filters."
        }
      />
    </Panel>
  );
}
