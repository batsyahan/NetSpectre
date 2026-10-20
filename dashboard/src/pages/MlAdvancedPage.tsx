// ML Advanced: how the models were evaluated, how the live classifier is doing, and why it made each decision.
// Static evaluation numbers come from /model_report.json (written by ml/export_model_report.py);
// live numbers come from the monitor (/api/ml, /api/predictions). Nothing on this page is estimated.
import { useEffect, useMemo, useState } from "react";
import {
  fetchMlStats,
  fetchModelReport,
  fetchPredictions,
  type MlStats,
  type ModelEval,
  type ModelReport,
  type Prediction,
} from "../api";
import { IconActivity, IconClock, IconCpu, IconLayers } from "../components/icons";
import { MetricCard, Panel, Select } from "../components/ui";
import { severityOf } from "../lib";
import {
  bestIndex,
  cellIntensity,
  deployedModel,
  filterPredictions,
  formatBytes,
  formatDuration,
  page,
  pct,
  protocolName,
  reasonBars,
  rowShares,
  shortClass,
  type PredictionSort,
} from "../ml";
import { fmtTime } from "../metrics";

const LIVE_MS = 5000;
const PAGE_SIZE = 10;

function useModelReport() {
  const [report, setReport] = useState<ModelReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    fetchModelReport()
      .then((r) => alive && setReport(r))
      .catch((e: unknown) => alive && setError(String(e)));
    return () => {
      alive = false;
    };
  }, []);
  return { report, error };
}

function useLiveMl() {
  const [stats, setStats] = useState<MlStats | null>(null);
  const [preds, setPreds] = useState<Prediction[]>([]);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let alive = true;
    const load = async () => {
      const [s, p] = await Promise.allSettled([fetchMlStats(), fetchPredictions()]);
      if (!alive) return;
      if (s.status === "fulfilled") setStats(s.value);
      if (p.status === "fulfilled") setPreds(p.value);
      setFailed(s.status === "rejected");
    };
    void load();
    const t = setInterval(() => void load(), LIVE_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  return { stats, preds, failed };
}

export function MlAdvancedPage() {
  const { report, error } = useModelReport();
  const { stats, preds, failed } = useLiveMl();
  const [selected, setSelected] = useState<Prediction | null>(null);
  const dep = report ? deployedModel(report.models) : undefined;

  // Keep the explanation panel on the newest prediction until the user picks one.
  const shown = selected ?? preds[0] ?? null;

  return (
    <>
      <div className="metrics">
        <MetricCard
          icon={<IconCpu />}
          label="Active model"
          value={dep ? dep.name.replace(" (deployed)", "") : "--"}
          note={dep ? `${dep.file} · ONNX · ${formatBytes(dep.size_bytes)}` : "Model report not loaded"}
        />
        <MetricCard
          icon={<IconLayers />}
          label="Classes and features"
          value={report ? `${report.classes.length} / ${report.features.length}` : "--"}
          note="classes (benign + 14 attacks) / input features per flow"
        />
        <MetricCard
          icon={<IconClock />}
          label="Average inference (live)"
          value={stats && stats.classified > 0 ? `${stats.avg_latency_ms.toFixed(1)} ms` : "--"}
          note={
            stats && stats.classified > 0
              ? `monitor → ML service → monitor, incl. explanation · max ${stats.max_latency_ms.toFixed(1)} ms`
              : failed
                ? "Monitor not reachable"
                : "No flows classified yet"
          }
        />
        <MetricCard
          icon={<IconActivity />}
          label="Flows classified (live)"
          value={stats ? stats.classified.toLocaleString("en-IN") : "--"}
          note={stats ? `since ${fmtTime(stats.since)} · ${stats.errors} errors` : failed ? "Monitor not reachable" : "Loading"}
        />
      </div>

      {error && (
        <div className="banner" role="alert">
          <span>
            Evaluation report not available ({error}). Run <span className="mono">python export_model_report.py</span> in{" "}
            <span className="mono">ml/</span>, then rebuild the dashboard.
          </span>
        </div>
      )}

      <div className="ml-row ml-row-2">
        <ComparisonPanel report={report} />
        <ConfusionPanel report={report} />
      </div>

      <div className="ml-row ml-row-2b">
        <ImportancePanel report={report} />
        <ExplainPanel prediction={shown} preds={preds} onPick={setSelected} pinned={selected !== null} report={report} />
      </div>

      <PredictionsPanel preds={preds} failed={failed} selected={shown} onSelect={setSelected} />

      <div className="ml-row ml-row-2">
        <LivePanel stats={stats} failed={failed} />
        <GeneralisationPanel report={report} />
      </div>

      <Cic2018Panel report={report} />
    </>
  );
}

function Loading({ what }: { what: string }) {
  return <p className="empty">Loading {what}…</p>;
}

// ---------- model comparison ----------
function ComparisonPanel({ report }: { report: ModelReport | null }) {
  if (!report) return <Panel title="Model comparison"><Loading what="evaluation report" /></Panel>;
  const ms = report.models;
  const rows: { label: string; get: (m: ModelEval) => number; fmt: (v: number) => string; lower?: boolean }[] = [
    { label: "Accuracy", get: (m) => m.accuracy, fmt: (v) => pct(v, 2) },
    { label: "Precision (macro)", get: (m) => m.macro_precision, fmt: (v) => v.toFixed(3) },
    { label: "Recall (macro)", get: (m) => m.macro_recall, fmt: (v) => v.toFixed(3) },
    { label: "F1-score (macro)", get: (m) => m.macro_f1, fmt: (v) => v.toFixed(3) },
    { label: "Benign false alarms", get: (m) => m.benign_fpr, fmt: (v) => pct(v, 3), lower: true },
    { label: "Model size", get: (m) => m.size_bytes, fmt: (v) => formatBytes(v), lower: true },
    { label: "Inference, 1 flow", get: (m) => m.latency_ms, fmt: (v) => `${v.toFixed(2)} ms`, lower: true },
  ];
  return (
    <Panel title="Model comparison" className="ml-compare">
      <div className="table-scroll">
        <table className="data compare">
          <thead>
            <tr>
              <th scope="col">Metric</th>
              {ms.map((m) => (
                <th key={m.name} scope="col" className={m.deployed ? "num col-deployed" : "num"} title={`${m.params}. Trained on ${m.trained_on}.`}>
                  {m.name}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const vals = ms.map(r.get);
              const best = bestIndex(vals, r.lower);
              return (
                <tr key={r.label} className={r.label.startsWith("F1") ? "row-key" : undefined}>
                  <th scope="row">{r.label}</th>
                  {vals.map((v, i) => (
                    <td key={ms[i].name} className={`num${ms[i].deployed ? " col-deployed" : ""}${i === best ? " best" : ""}`}>
                      {r.fmt(v)}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="fine">
        All models scored on the same {report.test_set.flows.toLocaleString("en-IN")}-flow {report.test_set.source} test set ({report.test_set.split}) with the
        same {report.features.length} features. Random Forest, CatBoost and XGBoost were trained on identical data; XGBoost v3 also saw live flows from this
        monitor{deployedModel(ms) && !deployedModel(ms)!.name.includes("v3") ? `, and the deployed ${deployedModel(ms)!.name.replace(" (deployed)", "")} was trained on ${deployedModel(ms)!.trained_on}` : ""}.
        Hover a column name for its settings. Best value per row in bold. Inference measured as one ONNX call per flow on the machine that built the report.
      </p>
    </Panel>
  );
}

// ---------- confusion matrix ----------
function ConfusionPanel({ report }: { report: ModelReport | null }) {
  const [model, setModel] = useState("");
  const [mode, setMode] = useState<"count" | "share">("share");
  if (!report) return <Panel title="Confusion matrix"><Loading what="evaluation report" /></Panel>;
  const m = report.models.find((x) => x.name === model) ?? deployedModel(report.models)!;
  const cm = m.confusion_matrix;
  const shares = rowShares(cm);
  const max = Math.max(...cm.flat());
  const cls = report.classes;
  return (
    <Panel
      title="Confusion matrix"
      className="ml-cm"
      action={
        <div className="panel-tools">
          <Select label="Model" value={m.name} options={report.models.map((x) => ({ value: x.name, label: x.name }))} onChange={setModel} />
          <Select
            label="Cell values"
            value={mode}
            options={[
              { value: "share", label: "% of true class" },
              { value: "count", label: "Flow counts" },
            ]}
            onChange={setMode}
          />
        </div>
      }
    >
      <div className="cm-wrap">
        <table className="cm">
          <caption className="sr-only">
            Confusion matrix of {m.name}: rows are the true class, columns the predicted class.
          </caption>
          <thead>
            <tr>
              <th scope="col" className="cm-corner">
                True ↓ / Predicted →
              </th>
              {cls.map((c) => (
                <th key={c} scope="col" title={c}>
                  <span>{shortClass(c)}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {cm.map((row, i) => (
              <tr key={cls[i]}>
                <th scope="row" title={cls[i]}>
                  {shortClass(cls[i])}
                </th>
                {row.map((v, j) => {
                  const a = mode === "share" ? shares[i][j] : cellIntensity(v, max);
                  const text = mode === "share" ? (v === 0 ? "" : shares[i][j] >= 0.995 ? "100" : (shares[i][j] * 100).toFixed(shares[i][j] < 0.1 ? 1 : 0)) : v === 0 ? "" : v.toLocaleString("en-IN");
                  return (
                    <td
                      key={cls[j]}
                      className={i === j ? "diag" : undefined}
                      style={{ background: v === 0 ? undefined : `rgba(47, 140, 255, ${0.12 + 0.88 * a})` }}
                      title={`True ${cls[i]}, predicted ${cls[j]}: ${v.toLocaleString("en-IN")} flows (${(shares[i][j] * 100).toFixed(2)}% of ${cls[i]})`}
                    >
                      {text}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="fine">
        {mode === "share" ? "Each row adds up to 100% of that true class." : "Colour uses a log scale: counts range from 1 to hundreds of thousands."} Hover a cell for the
        exact count.
      </p>
    </Panel>
  );
}

// ---------- feature importance ----------
function ImportancePanel({ report }: { report: ModelReport | null }) {
  const [view, setView] = useState<"top" | "all">("top");
  if (!report) return <Panel title="Feature importance"><Loading what="evaluation report" /></Panel>;
  const share = new Map(report.feature_importance.map((f) => [f.feature, f.share]));
  const rows = view === "top" ? report.feature_importance.slice(0, 10) : report.features.map((f) => ({ feature: f, share: share.get(f) ?? 0 }));
  const max = Math.max(...rows.map((r) => r.share), 0.0001);
  return (
    <Panel
      title="Feature importance (deployed model)"
      action={
        <Select
          label="Features shown"
          value={view}
          options={[
            { value: "top", label: "Top 10" },
            { value: "all", label: "All 35, input order" },
          ]}
          onChange={setView}
        />
      }
    >
      <ul className={`hbars${view === "all" ? " hbars-all" : ""}`}>
        {rows.map((r) => (
          <li key={r.feature}>
            <span className="hbar-label" title={r.feature}>
              {r.feature}
            </span>
            <span className="hbar-track">
              <span className="hbar-fill" style={{ width: `${(r.share / max) * 100}%` }} />
            </span>
            <span className="hbar-value">{pct(r.share)}</span>
          </li>
        ))}
      </ul>
      <p className="fine">
        Method: {report.feature_importance_method ?? "mean |TreeSHAP| contribution"}. Shares add up to 100% over all 35 features. This is global behaviour of the
        model, not an explanation of any single alert.
      </p>
    </Panel>
  );
}

// ---------- per-prediction explanation ----------
function ExplainPanel({
  prediction: p,
  preds,
  onPick,
  pinned,
  report,
}: {
  prediction: Prediction | null;
  preds: Prediction[];
  onPick: (p: Prediction | null) => void;
  pinned: boolean;
  report: ModelReport | null;
}) {
  const key = (x: Prediction) => `${x.ts_utc}|${x.src_ip}|${x.src_port}|${x.dst_ip}|${x.dst_port}`;
  const options = [{ value: "latest", label: "Latest prediction" }, ...preds.slice(0, 50).map((x) => ({ value: key(x), label: `${fmtTime(x.ts_utc)} · ${x.label} · ${x.src_ip}` }))];
  const bars = reasonBars(p?.reasons);
  const anomaly = p?.label === "Anomaly (unknown)";
  return (
    <Panel
      title="Explain prediction"
      className="ml-explain"
      action={
        preds.length > 0 ? (
          <Select
            label="Prediction"
            value={pinned && p ? key(p) : "latest"}
            options={options}
            onChange={(v) => onPick(v === "latest" ? null : (preds.find((x) => key(x) === v) ?? null))}
          />
        ) : undefined
      }
    >
      {!p ? (
        <p className="empty">
          No attack or anomaly predictions since the monitor started. Normal (benign) flows are counted below but not listed here.
        </p>
      ) : (
        <div className="explain">
          <dl className="facts explain-facts">
            <div>
              <dt>Predicted class</dt>
              <dd>
                <span className={`tag sev-${severityOf({ label: p.label, avg_confidence: p.confidence })}`}>{p.label}</span>
              </dd>
            </div>
            <div>
              <dt>{anomaly ? "Anomaly confidence" : "Confidence"}</dt>
              <dd>{pct(p.confidence)}</dd>
            </div>
            <div>
              <dt>Source</dt>
              <dd className="mono">
                {p.src_ip}:{p.src_port}
              </dd>
            </div>
            <div>
              <dt>Destination</dt>
              <dd className="mono">
                {p.dst_ip}:{p.dst_port}
              </dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>{protocolName(p.protocol)}</dd>
            </div>
            <div>
              <dt>Packets (fwd / bwd)</dt>
              <dd>
                {p.fwd_packets} / {p.bwd_packets}
              </dd>
            </div>
            <div>
              <dt>Flow duration</dt>
              <dd>{formatDuration(p.flow_duration_us)}</dd>
            </div>
            <div>
              <dt>Model</dt>
              <dd>{anomaly ? `${report?.autoencoder.model ?? "autoencoder"} (classifier said ${p.model_label})` : (report?.deployed_model ?? "classifier")}</dd>
            </div>
            <div>
              <dt>Time</dt>
              <dd>{fmtTime(p.ts_utc)}</dd>
            </div>
          </dl>
          <div className="explain-bars">
            <h3>{anomaly ? "Why it was flagged" : "Top features pushing toward this class"}</h3>
            {anomaly ? (
              <p className="prose">
                The classifier saw nothing it recognises, but the autoencoder could not reconstruct this flow well (anomaly score {p.anomaly_score.toFixed(2)},
                above the threshold{report ? ` of ${report.autoencoder.threshold.toFixed(3)}` : ""}). It means "unusual compared with normal traffic", not a named attack.
              </p>
            ) : bars.length === 0 ? (
              <p className="empty">No explanation was returned for this prediction.</p>
            ) : (
              <ul className="hbars hbars-pos">
                {bars.map((b) => (
                  <li key={b.feature}>
                    <span className="hbar-label" title={b.feature}>
                      {b.text}
                    </span>
                    <span className="hbar-track">
                      <span className="hbar-fill" style={{ width: `${b.share * 100}%` }} />
                    </span>
                    <span className="hbar-value">{pct(b.share, 0)}</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="fine">
              {anomaly
                ? ""
                : "TreeSHAP for this flow and class: the top 3 positive contributions, as shares of their sum. Features that pushed against the class are not stored. "}
              An explanation describes how the model reached its answer; it is not proof of an attack.
              {!p.counts_toward_alert && " This prediction was below the rare-class confidence minimum and did not count toward an alert."}
            </p>
          </div>
        </div>
      )}
    </Panel>
  );
}

// ---------- recent predictions ----------
function PredictionsPanel({
  preds,
  failed,
  selected,
  onSelect,
}: {
  preds: Prediction[];
  failed: boolean;
  selected: Prediction | null;
  onSelect: (p: Prediction) => void;
}) {
  const [label, setLabel] = useState("all");
  const [sort, setSort] = useState<PredictionSort>("time");
  const [pageIndex, setPageIndex] = useState(0);
  const labels = useMemo(() => [...new Set(preds.map((p) => p.label))].sort(), [preds]);
  const rows = filterPredictions(preds, label, sort);
  const pg = page(rows, pageIndex, PAGE_SIZE);
  return (
    <Panel
      title="Recent predictions"
      action={
        <div className="panel-tools">
          <Select
            label="Class"
            value={label}
            options={[{ value: "all", label: "All classes" }, ...labels.map((l) => ({ value: l, label: l }))]}
            onChange={(v) => {
              setLabel(v);
              setPageIndex(0);
            }}
          />
          <Select
            label="Sort"
            value={sort}
            options={[
              { value: "time", label: "Newest first" },
              { value: "confidence", label: "Highest confidence" },
            ]}
            onChange={setSort}
          />
        </div>
      }
    >
      {rows.length === 0 ? (
        <p className="empty">
          {failed
            ? "The monitor is not reachable."
            : "No attack or anomaly predictions yet. The monitor keeps the latest 300 in memory; they reset when it restarts."}
        </p>
      ) : (
        <>
          <div className="table-scroll">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Source</th>
                  <th scope="col">Destination</th>
                  <th scope="col">Protocol</th>
                  <th scope="col">Predicted class</th>
                  <th scope="col" className="num">
                    Confidence
                  </th>
                  <th scope="col">Model</th>
                  <th scope="col" className="col-actions">
                    Details
                  </th>
                </tr>
              </thead>
              <tbody>
                {pg.rows.map((p) => {
                  const isSel = selected === p;
                  return (
                    <tr key={`${p.ts_utc}|${p.src_ip}|${p.src_port}|${p.dst_ip}|${p.dst_port}`} className={isSel ? "row-selected" : undefined}>
                      <td className="nowrap">{fmtTime(p.ts_utc)}</td>
                      <td className="mono nowrap">{p.src_ip}</td>
                      <td className="mono nowrap">
                        {p.dst_ip}:{p.dst_port}
                      </td>
                      <td>{protocolName(p.protocol)}</td>
                      <td>
                        <span className={`tag sev-${severityOf({ label: p.label, avg_confidence: p.confidence })}`}>{p.label}</span>
                      </td>
                      <td className="num">{pct(p.confidence, 0)}</td>
                      <td>{p.label === "Anomaly (unknown)" ? "Autoencoder" : "XGBoost"}</td>
                      <td className="col-actions">
                        <button type="button" className="btn-ghost btn-small" aria-pressed={isSel} onClick={() => onSelect(p)}>
                          Explain
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <span className="muted">
              {rows.length} predictions · page {pg.index + 1} of {pg.pages}
            </span>
            <button type="button" className="btn-ghost btn-small" disabled={pg.index === 0} onClick={() => setPageIndex(pg.index - 1)}>
              Previous
            </button>
            <button type="button" className="btn-ghost btn-small" disabled={pg.index >= pg.pages - 1} onClick={() => setPageIndex(pg.index + 1)}>
              Next
            </button>
          </div>
        </>
      )}
    </Panel>
  );
}

// ---------- live performance ----------
function LivePanel({ stats, failed }: { stats: MlStats | null; failed: boolean }) {
  if (!stats) return <Panel title="Live model performance">{failed ? <p className="empty">The monitor is not reachable.</p> : <Loading what="live counters" />}</Panel>;
  const total = stats.by_label.reduce((a, r) => a + r.count, 0);
  const facts: [string, string][] = [
    ["Counting since", fmtTime(stats.since)],
    ["Flows classified", stats.classified.toLocaleString("en-IN")],
    ["Average / max round trip", stats.classified ? `${stats.avg_latency_ms.toFixed(1)} / ${stats.max_latency_ms.toFixed(1)} ms` : "--"],
    ["Classification errors", String(stats.errors)],
    ["Rejected inputs (wrong feature count)", String(stats.invalid_input)],
    ["Flows refused (flow table full)", stats.flows_refused.toLocaleString("en-IN")],
    ["Flows dropped (classifier queue full)", stats.flows_queue_dropped.toLocaleString("en-IN")],
  ];
  return (
    <Panel title="Live model performance">
      <dl className="facts">
        {facts.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      <h3 className="sub">Classifier output by class</h3>
      {total === 0 ? (
        <p className="empty">No flows classified yet.</p>
      ) : (
        <ul className="hbars">
          {stats.by_label.map((r) => (
            <li key={r.label}>
              <span className="hbar-label">{r.label}</span>
              <span className="hbar-track">
                <span className="hbar-fill" style={{ width: `${(r.count / total) * 100}%` }} />
              </span>
              <span className="hbar-value">{r.count.toLocaleString("en-IN")}</span>
            </li>
          ))}
        </ul>
      )}
      <p className="fine">Measured by the monitor since it last started. Per-flow labels before alert grouping, so most traffic is BENIGN.</p>
    </Panel>
  );
}

// ---------- autoencoder and generalisation ----------
function GeneralisationPanel({ report }: { report: ModelReport | null }) {
  if (!report) return <Panel title="Unknown attacks and generalisation"><Loading what="evaluation report" /></Panel>;
  const ae = report.autoencoder;
  return (
    <Panel title="Unknown attacks and generalisation">
      <dl className="facts">
        <div>
          <dt>Anomaly detector</dt>
          <dd>
            {ae.model} autoencoder ({ae.layers}), threshold {ae.threshold.toFixed(3)}
          </dd>
        </div>
        <div>
          <dt>Normal CICIDS2017 test flows flagged</dt>
          <dd>{pct(ae.cicids_benign_flagged, 2)}</dd>
        </div>
        <div>
          <dt>Normal flows from this network flagged</dt>
          <dd>{ae.own_network ? `${pct(ae.own_network.flagged, 2)} of ${ae.own_network.flows.toLocaleString("en-IN")}` : "No capture available"}</dd>
        </div>
      </dl>
      <h3 className="sub">Attack types never seen in training (leave one capture day out)</h3>
      {report.leave_one_day_out.length === 0 ? (
        <p className="empty">docs/EVAL_LEAVE_DAY_OUT.txt was not found when the report was built.</p>
      ) : (
        <div className="table-scroll">
          <table className="data compact">
            <thead>
              <tr>
                <th scope="col">Held-out day</th>
                <th scope="col">Unseen attacks</th>
                <th scope="col" className="num">
                  Caught
                </th>
                <th scope="col" className="num">
                  Normal flagged
                </th>
              </tr>
            </thead>
            <tbody>
              {report.leave_one_day_out.map((d) => (
                <tr key={d.day}>
                  <td>{d.day}</td>
                  <td>{d.attacks.map((a) => shortClass(a.label)).join(", ")}</td>
                  <td className="num">{d.all_attacks ? pct(d.all_attacks.either_ae_0_5) : "--"}</td>
                  <td className="num">{d.benign_fpr ? pct(d.benign_fpr.either_ae_0_5) : "--"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="fine">
        {report.leave_one_day_out_note ?? ""} Report generated {fmtTime(report.generated_at)}.
      </p>
    </Panel>
  );
}

// ---------- CSE-CIC-IDS2018: a different network, recorded a year later ----------
function Cic2018Panel({ report }: { report: ModelReport | null }) {
  if (!report) return <Panel title="Different network: CSE-CIC-IDS2018"><Loading what="evaluation report" /></Panel>;
  const c = report.cicids2018;
  if (!c) {
    return (
      <Panel title="Different network: CSE-CIC-IDS2018">
        <p className="empty">docs/EVAL_V8.txt was not found when the report was built.</p>
      </Panel>
    );
  }
  const dep = report.deployed_model.split("_").pop() ?? "";
  const cols = ["v3", dep].filter((v, i, a) => v && a.indexOf(v) === i && c.models.includes(v));
  const cell = (m?: Record<string, number>, k?: string) => (m && k && m[k] !== undefined ? pct(m[k], 1) : "--");
  return (
    <Panel title="Different network: CSE-CIC-IDS2018">
      <div className="table-scroll">
        <table className="data compact">
          <thead>
            <tr>
              <th scope="col">2018 attack</th>
              <th scope="col" className="num">Test flows</th>
              {cols.map((k) => (
                <th key={`c${k}`} scope="col" className={k === dep ? "num col-deployed" : "num"}>
                  Caught, {k}
                  {k === dep ? " (deployed)" : ""}
                </th>
              ))}
              {cols.map((k) => (
                <th key={`r${k}`} scope="col" className={k === dep ? "num col-deployed" : "num"}>
                  Right type, {k}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {c.attacks.map((a) => (
              <tr key={a.label}>
                <td>{a.label}</td>
                <td className="num">{a.flows?.toLocaleString("en-IN") ?? "--"}</td>
                {cols.map((k) => (
                  <td key={`c${k}`} className={k === dep ? "num col-deployed" : "num"}>{cell(a.caught, k)}</td>
                ))}
                {cols.map((k) => (
                  <td key={`r${k}`} className={k === dep ? "num col-deployed" : "num"}>{cell(a.right, k)}</td>
                ))}
              </tr>
            ))}
            {c.all_attacks && (
              <tr className="row-key">
                <th scope="row">All attacks</th>
                <td className="num">{c.all_attacks.flows?.toLocaleString("en-IN") ?? "--"}</td>
                {cols.map((k) => (
                  <td key={`c${k}`} className={k === dep ? "num col-deployed" : "num"}>{cell(c.all_attacks!.caught, k)}</td>
                ))}
                {cols.map((k) => (
                  <td key={`r${k}`} className={k === dep ? "num col-deployed" : "num"}>{cell(c.all_attacks!.right, k)}</td>
                ))}
              </tr>
            )}
            {c.benign && (
              <tr>
                <th scope="row">Normal traffic flagged (false alarms)</th>
                <td className="num">{c.benign.flows?.toLocaleString("en-IN") ?? "--"}</td>
                {cols.map((k) => (
                  <td key={`c${k}`} className={k === dep ? "num col-deployed" : "num"}>{cell(c.benign!.caught, k)}</td>
                ))}
                {cols.map((k) => (
                  <td key={`r${k}`} className={k === dep ? "num col-deployed" : "num"} />
                ))}
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <p className="fine">{c.note}</p>
    </Panel>
  );
}
