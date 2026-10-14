// Page chrome: fixed sidebar and top bar.
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "../router";
import {
  IconBell,
  IconCpu,
  IconChart,
  IconDashboard,
  IconFile,
  IconMonitor,
  IconSearch,
  IconSettings,
  IconShield,
  IconShieldCheck,
} from "./icons";

const NAV: { to: string; label: string; icon: ReactNode }[] = [
  { to: "/", label: "Dashboard", icon: <IconDashboard /> },
  { to: "/alerts", label: "Alerts", icon: <IconBell /> },
  { to: "/devices", label: "Devices", icon: <IconMonitor /> },
  { to: "/attack-types", label: "Attack Types", icon: <IconShield /> },
  { to: "/ip-lookup", label: "IP Lookup", icon: <IconSearch /> },
  { to: "/ml-advanced", label: "ML Advanced", icon: <IconCpu /> },
  { to: "/reports", label: "Reports", icon: <IconChart /> },
  { to: "/attack-guide", label: "Attack Guide", icon: <IconFile /> },
  { to: "/settings", label: "Settings", icon: <IconSettings /> },
];

export function Sidebar({ path }: { path: string }) {
  return (
    <aside className="sidebar">
      <Link to="/" className="brand">
        <IconShieldCheck size={30} className="brand-mark" />
        <span>NetSpectre</span>
      </Link>
      <nav aria-label="Primary" className="nav">
        {NAV.map((n) => (
          <Link key={n.to} to={n.to} current={n.to === path} className="nav-link">
            {n.icon}
            <span>{n.label}</span>
          </Link>
        ))}
      </nav>
      <nav aria-label="Legal" className="legal-nav">
        <Link to="/privacy" current={path === "/privacy"}>
          <IconFile size={16} />
          <span>Privacy Policy</span>
        </Link>
        <Link to="/terms" current={path === "/terms"}>
          <IconFile size={16} />
          <span>Terms &amp; Conditions</span>
        </Link>
      </nav>
    </aside>
  );
}

function Clock() {
  const [d, setD] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setD(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  const parts = new Intl.DateTimeFormat("en-GB", {
    weekday: "short",
    day: "numeric",
    month: "short",
    year: "numeric",
  }).formatToParts(d);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  return (
    <div className="clock">
      <div>{`${get("weekday")}, ${get("day")} ${get("month")} ${get("year")}`}</div>
      <div className="clock-time">{d.toLocaleTimeString("en-GB", { hourCycle: "h23" })}</div>
    </div>
  );
}

export function Header({
  title,
  subtitle,
  online,
  loaded,
  stale,
}: {
  title: string;
  subtitle: string;
  online: boolean;
  loaded: boolean;
  stale: boolean;
}) {
  const state = !loaded ? "connecting" : !online ? "offline" : stale ? "stale" : "live";
  const text = { connecting: "Connecting", offline: "Monitor offline", stale: "Data may be out of date", live: "Monitoring live" }[state];
  return (
    <header className="topbar">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>
      <div className="topbar-right">
        <span className={`live live-${state}`} role="status">
          <span className="dot" />
          {text}
        </span>
        <Clock />
      </div>
    </header>
  );
}
