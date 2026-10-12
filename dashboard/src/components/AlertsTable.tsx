import type { Alert, AlertStatus } from "../api";
import { fmtTime } from "../metrics";
import { navigate } from "../router";
import { RowMenu, type MenuItem } from "./RowMenu";
import { SeverityBadge, StatusBadge } from "./ui";

export function AlertsTable({
  alerts,
  onStatus,
  showWhy = false,
  empty,
}: {
  alerts: Alert[];
  onStatus: (id: number, status: AlertStatus) => void;
  showWhy?: boolean;
  empty: string;
}) {
  if (alerts.length === 0) return <p className="empty">{empty}</p>;

  const items = (a: Alert): MenuItem[] => [
    ...(a.status === "new"
      ? [
          { label: "Acknowledge", onSelect: () => onStatus(a.id, "acknowledged") },
          { label: "Dismiss", onSelect: () => onStatus(a.id, "dismissed") },
        ]
      : [{ label: "Reopen", onSelect: () => onStatus(a.id, "new") }]),
    { label: `Alerts from ${a.src_ip}`, onSelect: () => navigate(`/alerts?device=${encodeURIComponent(a.src_ip)}`) },
  ];

  return (
    <div className="table-scroll">
      <table className="data">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Severity</th>
            <th scope="col">Attack type</th>
            <th scope="col">Source IP</th>
            <th scope="col">Flows</th>
            <th scope="col">Confidence</th>
            <th scope="col">Status</th>
            <th scope="col" className="col-actions">
              Actions
            </th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.id} className={a.status === "dismissed" ? "dim" : undefined}>
              <td className="nowrap">{fmtTime(a.ts_utc)}</td>
              <td>
                <SeverityBadge alert={a} />
              </td>
              <td>
                {a.label}
                {showWhy && a.explanation && a.explanation.length > 0 && (
                  <div className="why">
                    Why: {a.explanation.map((r) => `${r.text} (${Math.round(r.weight)}%)`).join(", ")}
                  </div>
                )}
              </td>
              <td className="mono">{a.src_ip}</td>
              <td className="num">{a.flow_count}</td>
              <td className="num">{Math.round(a.avg_confidence * 100)}%</td>
              <td>
                <StatusBadge status={a.status} />
              </td>
              <td className="col-actions">
                <RowMenu label={`Actions for alert ${a.id}`} items={items(a)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
