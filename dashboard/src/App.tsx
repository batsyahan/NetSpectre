import { useEffect, type ReactNode } from "react";
import { Header, Sidebar } from "./components/Shell";
import { IconX } from "./components/icons";
import { TokenPrompt } from "./components/TokenPrompt";
import { useMonitor, type Monitor } from "./data";
import { AlertsPage } from "./pages/AlertsPage";
import { AttackMapPage } from "./pages/AttackMapPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DevicesPage } from "./pages/DevicesPage";
import { MlAdvancedPage } from "./pages/MlAdvancedPage";
import { PrivacyPage, TermsPage } from "./pages/LegalPages";
import { AttackGuidePage, AttackTypesPage, IpLookupPage, ReportsPage, SettingsPage } from "./pages/OtherPages";
import { Link, useLocation } from "./router";

interface Route {
  title: string;
  subtitle: string;
  render: (m: Monitor) => ReactNode;
}

const ROUTES: Record<string, Route> = {
  "/": {
    title: "Dashboard",
    subtitle: "Real-time network threat monitoring and analysis",
    render: (m) => <DashboardPage m={m} />,
  },
  "/alerts": {
    title: "Alerts",
    subtitle: "Review, acknowledge and dismiss detections",
    render: (m) => <AlertsPage m={m} />,
  },
  "/devices": {
    title: "Devices",
    subtitle: "Every device the monitor has seen on the network",
    render: (m) => <DevicesPage m={m} />,
  },
  "/attack-types": {
    title: "Attack Types",
    subtitle: "How detections break down by attack type",
    render: (m) => <AttackTypesPage m={m} />,
  },
  "/ip-lookup": {
    title: "IP Lookup",
    subtitle: "Look up one device by IP address",
    render: (m) => <IpLookupPage m={m} />,
  },
  "/ml-advanced": {
    title: "ML Advanced",
    subtitle: "Model performance, predictions and explainability",
    render: () => <MlAdvancedPage />,
  },
  "/attack-map": {
    title: "Attack Map (Live)",
    subtitle: "Real-time visualization of network threats",
    render: (m) => <AttackMapPage m={m} />,
  },
  "/reports": {
    title: "Reports",
    subtitle: "Export alerts and print incident reports",
    render: (m) => <ReportsPage m={m} />,
  },
  "/attack-guide": {
    title: "Attack Guide",
    subtitle: "What each detected attack is, and how well the model finds it",
    render: () => <AttackGuidePage />,
  },
  "/settings": {
    title: "Settings",
    subtitle: "Dashboard status and monitor configuration",
    render: (m) => <SettingsPage m={m} />,
  },
  "/privacy": {
    title: "Privacy Policy",
    subtitle: "What NetSpectre collects and where it goes",
    render: () => <PrivacyPage />,
  },
  "/terms": {
    title: "Terms & Conditions",
    subtitle: "Rules for using NetSpectre",
    render: () => <TermsPage />,
  },
};

// Pages that show no monitor data stay readable before a token is entered.
const PUBLIC_PAGES = new Set(["/attack-guide", "/privacy", "/terms"]);

const NOT_FOUND: Route = {
  title: "Page not found",
  subtitle: "That address does not exist",
  render: () => (
    <p className="empty">
      There is no page here. <Link to="/">Go to the dashboard</Link>.
    </p>
  ),
};

export default function App() {
  const m = useMonitor();
  const { path } = useLocation();
  const route = ROUTES[path] ?? NOT_FOUND;

  useEffect(() => {
    document.title = `${route.title} | NetSpectre`;
  }, [route.title]);

  return (
    <div className="app">
      <a href="#content" className="skip-link">
        Skip to content
      </a>
      <Sidebar path={path} />
      <div className="main">
        <Header title={route.title} subtitle={route.subtitle} online={m.online} loaded={m.loaded} stale={m.stale} />
        <main id="content" className="content">
          {m.actionError && (
            <div className="banner" role="alert">
              <span>{m.actionError}</span>
              <button type="button" className="icon-btn" aria-label="Dismiss message" onClick={m.clearActionError}>
                <IconX size={16} />
              </button>
            </div>
          )}
          {m.needsToken && !PUBLIC_PAGES.has(path) ? <TokenPrompt /> : route.render(m)}
          <footer className="foot">
            {m.updated ? `Updated ${m.updated.toLocaleTimeString("en-GB", { hourCycle: "h23" })}` : "Connecting"}
          </footer>
        </main>
      </div>
    </div>
  );
}
