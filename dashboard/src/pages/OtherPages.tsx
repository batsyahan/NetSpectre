// Attack types, IP lookup, reports and settings pages.
import { ALERT_LIMIT } from "../api";
import { LookupForm, LookupResultPanel, useIpLookup } from "../components/lookup";
import { Panel, MetricCard } from "../components/ui";
import { IconShield, IconChart, IconFile, IconSearch } from "../components/icons";
import { ATTACK_GUIDE, GUIDE_STATS } from "../attackGuide";
import { SEVERITY } from "../lib";
import { POLL_SECONDS, type Monitor } from "../data";
import { attackColors, countByLabel, fmtTime, share, sum } from "../metrics";
import { Link } from "../router";

export function AttackTypesPage({ m }: { m: Monitor }) {
  const rows = m.stats?.by_label ?? countByLabel(m.alerts);
  const total = sum(rows);
  const colors = attackColors(rows.map((r) => r.label));
  const latest = new Map<string, string>();
  for (const a of m.alerts) if (!latest.has(a.label)) latest.set(a.label, a.ts_utc); // alerts are newest first
  const max = rows[0]?.count ?? 1;

  return (
    <Panel title="Alerts by attack type, all time">
      {rows.length === 0 ? (
        <p className="empty">{m.loaded ? "No alerts yet." : "Loading alerts."}</p>
      ) : (
        <div className="table-scroll">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Attack type</th>
                <th scope="col">Share</th>
                <th scope="col" className="num">
                  Alerts
                </th>
                <th scope="col" className="num">
                  Share of total
                </th>
                <th scope="col">Latest alert</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.label}>
                  <td>
                    <span className="dot" style={{ background: colors[r.label] }} /> {r.label}
                  </td>
                  <td className="bar-cell">
                    <span className="bars-track">
                      <span className="bars-fill" style={{ width: `${(r.count / max) * 100}%`, background: colors[r.label] }} />
                    </span>
                  </td>
                  <td className="num">{r.count}</td>
                  <td className="num">{share(r.count, total)}%</td>
                  <td className="nowrap">{latest.has(r.label) ? fmtTime(latest.get(r.label) ?? "") : "Not in the newest 500"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="caption">
        &quot;Anomaly (unknown)&quot; means the traffic looked unusual to the anomaly detector but matched no known attack.
        It is a warning to investigate, not a confirmed attack.
      </p>
    </Panel>
  );
}

export function IpLookupPage({ m }: { m: Monitor }) {
  const lookup = useIpLookup();
  return (
    <>
      <Panel title="IP address lookup">
        <LookupForm id="page-lookup" state={lookup.state} onSubmit={lookup.run} />
        <p className="caption">Shows what the monitor has recorded for one IPv4 address: when it was seen, its flows and its alerts.</p>
      </Panel>
      {lookup.state.kind === "result" && <LookupResultPanel result={lookup.state.result} now={m.now} />}
    </>
  );
}

export function ReportsPage({ m }: { m: Monitor }) {
  const withAlerts = m.devices.filter((d) => d.alert_count > 0).sort((a, b) => b.alert_count - a.alert_count);
  return (
    <>
      <Panel title="Export">
        <p className="prose">Download every stored alert as a CSV file for a spreadsheet or for the project report.</p>
        <p>
          <a className="btn-ghost" href="/api/alerts/export" download>
            Export all alerts (CSV)
          </a>
        </p>
      </Panel>
      <Panel title="Incident reports">
        <p className="prose">
          An incident report summarises one device&apos;s alerts. Open a device below, then use the print button to save the
          report as a PDF from your browser.
        </p>
        {withAlerts.length === 0 ? (
          <p className="empty">{m.loaded ? "No device has alerts yet." : "Loading devices."}</p>
        ) : (
          <div className="table-scroll">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Device (IP)</th>
                  <th scope="col" className="num">
                    Alerts
                  </th>
                  <th scope="col">Last seen</th>
                  <th scope="col">Report</th>
                </tr>
              </thead>
              <tbody>
                {withAlerts.map((d) => (
                  <tr key={d.ip}>
                    <td className="mono">{d.ip}</td>
                    <td className="num">{d.alert_count}</td>
                    <td className="nowrap">{fmtTime(d.last_seen)}</td>
                    <td>
                      <Link to={`/devices?device=${encodeURIComponent(d.ip)}`}>Open report</Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

const ENV: [string, string][] = [
  ["NS_IFACE", "Network interface the monitor captures on (lo by default)."],
  ["NS_ANOMALY_IGNORE", "Trusted source IPs that never raise Anomaly (unknown) alerts."],
  ["NS_AE_THRESHOLD", "Autoencoder reconstruction-error threshold for anomaly alerts."],
  ["NS_RARE_MIN_CONF", "Minimum confidence before rare attack classes count toward an alert."],
  ["NS_ENSEMBLE", "Set to 1 to average XGBoost and CatBoost (ML service)."],
  ["NS_API_TOKEN", "Token required from API clients that are not on the monitor machine."],
  ["NS_NTFY_TOPIC", "Turns on phone notifications through ntfy. Empty means off."],
  ["NS_NTFY_MIN_SEVERITY", "Lowest severity that sends a notification."],
  ["NS_NTFY_SERVER", "ntfy server to use (defaults to https://ntfy.sh)."],
];

export function SettingsPage({ m }: { m: Monitor }) {
  const facts: [string, string][] = [
    ["Monitor API", !m.loaded ? "Connecting" : m.online ? "Reachable" : "Not reachable"],
    ["Last update", m.updated ? m.updated.toLocaleTimeString("en-GB", { hourCycle: "h23" }) : "None yet"],
    ["Refresh", `Live stream plus a ${POLL_SECONDS} second poll`],
    ["Alerts loaded", `${m.alerts.length} (newest ${ALERT_LIMIT} at most)`],
    ["Devices tracked", String(m.devices.length)],
    ["Statistics endpoint", m.stats ? "Available" : "Not available (totals use loaded alerts)"],
  ];
  return (
    <>
      <Panel title="Dashboard status">
        <dl className="facts wide">
          {facts.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </div>
          ))}
        </dl>
      </Panel>
      <Panel title="Monitor configuration">
        <p className="prose">
          Detection settings are not editable here. They are environment variables read when the monitor and ML service
          start, set in <span className="mono">docker-compose.yml</span> or the git-ignored <span className="mono">.env</span>{" "}
          file. Restart the container after changing one.
        </p>
        <div className="table-scroll">
          <table className="data">
            <thead>
              <tr>
                <th scope="col">Variable</th>
                <th scope="col">Purpose</th>
              </tr>
            </thead>
            <tbody>
              {ENV.map(([k, v]) => (
                <tr key={k}>
                  <td className="mono nowrap">{k}</td>
                  <td>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </>
  );
}

const pct = (x: number) => `${(x * 100).toFixed(x >= 0.9995 ? 0 : 1)}%`;
const f1Class = (f: number) => (f >= 0.9 ? "good" : f >= 0.7 ? "fair" : "weak");

export function AttackGuidePage() {
  return (
    <>
      <div className="metrics">
        <MetricCard icon={<IconShield />} label="Classes detected" value={String(GUIDE_STATS.classes)} note="14 attack types plus normal traffic" />
        <MetricCard icon={<IconChart />} label="Test accuracy" value={`${GUIDE_STATS.accuracy}%`} note={`${GUIDE_STATS.testFlows.toLocaleString("en-GB")} held-out flows`} />
        <MetricCard icon={<IconSearch />} label="Macro F1" value={GUIDE_STATS.macroF1.toFixed(3)} note="Average over all classes, rare ones included" />
        <MetricCard icon={<IconFile />} label="Normal flows flagged" value={`${GUIDE_STATS.benignFalsePositive}%`} note="Benign traffic wrongly marked as an attack" />
      </div>

      <Panel title="How these numbers were produced">
        <ul className="guide-notes">
          <li>
            <strong>Training data:</strong> CICIDS2017, a public research capture of a lab network with labelled normal and attack
            traffic. Each network connection (flow) is turned into {GUIDE_STATS.features} numbers such as duration, packet counts,
            packet sizes and timing. The model never sees packet contents.
          </li>
          <li>
            <strong>Model:</strong> XGBoost classifier. The deployed version was retrained with captured port scans and normal
            traffic from this project&apos;s own network added. A separate autoencoder, trained on normal traffic only, raises
            &quot;Anomaly (unknown)&quot; for traffic that looks unusual but matches none of these classes.
          </li>
          <li>
            <strong>Test:</strong> for every capture day and attack type, the first 80% of the flows (in recorded order) were used for
            training and the last 20% for testing, so the model never saw the test flows. They still come from the same days and
            attack runs as the training flows, so scores are optimistic. Scores below are from the original XGBoost run on that split.
            Real home traffic differs from this dataset, so live accuracy will be lower.
          </li>
          <li>
            <strong>Reading the scores:</strong> precision is how many alerts of a class were correct; recall is how many real attacks
            of that class were caught; F1 combines the two.
          </li>
        </ul>
      </Panel>

      <div className="guide-grid">
        {ATTACK_GUIDE.map((a) => {
          const sev = a.name === "BENIGN" ? null : SEVERITY[a.name] ?? "medium";
          return (
            <article key={a.name} className="guide-card">
              <header>
                <h3>{a.name === "BENIGN" ? "Benign (normal traffic)" : a.name}</h3>
                {sev ? <span className={`tag sev-${sev}`}>{sev[0].toUpperCase() + sev.slice(1)}</span> : <span className="tag state-online">Normal</span>}
              </header>
              <p>{a.what}</p>
              <p className="guide-example">
                <strong>Example:</strong> {a.example}
              </p>
              <dl className="guide-scores">
                <div>
                  <dt>Precision</dt>
                  <dd>{pct(a.precision)}</dd>
                </div>
                <div>
                  <dt>Recall</dt>
                  <dd>{pct(a.recall)}</dd>
                </div>
                <div>
                  <dt>F1</dt>
                  <dd className={`f1-${f1Class(a.f1)}`}>{a.f1.toFixed(2)}</dd>
                </div>
                <div>
                  <dt>Test flows</dt>
                  <dd>{a.support.toLocaleString("en-GB")}</dd>
                </div>
              </dl>
              {a.note && <p className="guide-note">{a.note}</p>}
            </article>
          );
        })}
      </div>
      <p className="caption">
        Classes with fewer than 10 test flows (Infiltration, SQL injection, Heartbleed) have scores that are not statistically
        meaningful. Source: docs/EVAL_TEST_SET.txt.
      </p>
    </>
  );
}
