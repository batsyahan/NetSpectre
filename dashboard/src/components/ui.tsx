// Small shared building blocks: panel, select, badges, metric card, donut chart and legend.
import { useId, type ReactNode } from "react";
import { severityOf } from "../lib";
import { deviceState, share, type DeviceState, type Slice } from "../metrics";
import { IconChevronDown } from "./icons";

export function Panel({
  title,
  action,
  className,
  children,
}: {
  title: string;
  action?: ReactNode;
  className?: string;
  children: ReactNode;
}) {
  const id = useId();
  return (
    <section className={className ? `panel ${className}` : "panel"} aria-labelledby={id}>
      <div className="panel-head">
        <h2 id={id}>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

export function Select<T extends string>({
  label,
  value,
  options,
  onChange,
  showLabel = false,
}: {
  label: string;
  showLabel?: boolean;
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <label className="select">
      <span className={showLabel ? "select-text" : "sr-only"}>{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value as T)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <IconChevronDown size={14} className="select-chevron" />
    </label>
  );
}

export function SeverityBadge({ alert }: { alert: { label: string; avg_confidence: number } }) {
  const sev = severityOf(alert);
  return <span className={`tag sev-${sev}`}>{sev[0].toUpperCase() + sev.slice(1)}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return <span className={`tag status-${status}`}>{status[0].toUpperCase() + status.slice(1)}</span>;
}

const STATE_LABEL: Record<DeviceState, string> = { online: "Online", offline: "Offline", unknown: "Unknown" };

export function StateBadge({ lastSeen, now }: { lastSeen: string; now: number }) {
  const s = deviceState({ last_seen: lastSeen }, now);
  return <span className={`tag state-${s}`}>{STATE_LABEL[s]}</span>;
}

export function MetricCard({
  icon,
  label,
  value,
  note,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  note: ReactNode;
}) {
  return (
    <div className="metric">
      <div className="metric-head">
        <span className="metric-icon">{icon}</span>
        <span className="metric-label">{label}</span>
      </div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </div>
  );
}

export function Donut({
  slices,
  total,
  caption,
  label,
  size = 165,
}: {
  slices: Slice[];
  total: number;
  caption: string;
  label: string;
  size?: number;
}) {
  const R = 60;
  const C = 2 * Math.PI * R;
  const shown = slices.filter((s) => s.value > 0);
  const gap = shown.length > 1 ? 2 : 0;
  let offset = 0;
  return (
    <svg viewBox="0 0 160 160" width={size} height={size} role="img" aria-label={label} className="donut">
      <circle cx="80" cy="80" r={R} fill="none" stroke="var(--track)" strokeWidth="24" />
      <g transform="rotate(-90 80 80)">
        {shown.map((s) => {
          const len = (s.value / total) * C;
          const el = (
            <circle
              key={s.label}
              cx="80"
              cy="80"
              r={R}
              fill="none"
              stroke={s.color}
              strokeWidth="24"
              strokeDasharray={`${Math.max(len - gap, 0)} ${C}`}
              strokeDashoffset={-offset}
            >
              <title>{`${s.label}: ${s.value} (${share(s.value, total)}%)`}</title>
            </circle>
          );
          offset += len;
          return el;
        })}
      </g>
      <text x="80" y="81" textAnchor="middle" className="donut-total">
        {total}
      </text>
      <text x="80" y="100" textAnchor="middle" className="donut-caption">
        {caption}
      </text>
    </svg>
  );
}

export function Legend({ slices, total }: { slices: Slice[]; total: number }) {
  return (
    <ul className="legend">
      {slices.map((s) => (
        <li key={s.label}>
          <span className="dot" style={{ background: s.color }} />
          <span className="legend-label">{s.label}</span>
          <span className="legend-value">
            {s.value} ({share(s.value, total)}%)
          </span>
        </li>
      ))}
    </ul>
  );
}
