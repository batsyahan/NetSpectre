use pcap::{Capture, Device};
use std::collections::HashMap;
use std::env;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod pb {
    tonic::include_proto!("netspectre.v1");
}
#[allow(unused_imports)]
use pb::inference_client::InferenceClient;

struct Pkt {
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    proto: u8,
    payload: u32,
    hdr_len: u32,
    flags: u8,
    win: u32,
    l4hdr: u32,
    ts_us: u64,
}

fn parse(data: &[u8], ts_us: u64) -> Option<Pkt> {
    if data.len() < 14 {
        return None;
    }
    let ip = &data[14..];
    // v6_extra: how many header bytes longer this packet is than the same packet over IPv4
    let (src, dst, proto, ihl, v6_extra) = match u16::from_be_bytes([data[12], data[13]]) {
        0x0800 => {
            if ip.len() < 20 || ip[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            if ihl < 20 || ip.len() < ihl {
                return None;
            }
            (IpAddr::from([ip[12], ip[13], ip[14], ip[15]]), IpAddr::from([ip[16], ip[17], ip[18], ip[19]]), ip[9], ihl, 0)
        }
        // IPv6: fixed 40-byte header; TCP/UDP directly after it (extension headers are not followed).
        0x86DD => {
            if ip.len() < 40 || ip[0] >> 4 != 6 {
                return None;
            }
            let s: [u8; 16] = ip[8..24].try_into().ok()?;
            let d: [u8; 16] = ip[24..40].try_into().ok()?;
            (IpAddr::from(s), IpAddr::from(d), ip[6], 40, 20)
        }
        _ => return None,
    };
    let l4 = &ip[ihl..];
    let (sport, dport, l4hdr, flags) = match proto {
        6 if l4.len() >= 20 => (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
            ((l4[12] >> 4) as u32) * 4,
            l4[13],
        ),
        17 if l4.len() >= 8 => (
            u16::from_be_bytes([l4[0], l4[1]]),
            u16::from_be_bytes([l4[2], l4[3]]),
            8,
            0,
        ),
        _ => return None, // TCP and UDP only for now
    };
    let win = if proto == 6 { u16::from_be_bytes([l4[14], l4[15]]) as u32 } else { 0 };
    // like a real wire: Ethernet frames are at least 60 bytes, padding counts as payload (as in CICIDS2017).
    // The models learned this from IPv4, so an IPv6 packet is measured as the same packet would be over IPv4
    // (20 header bytes fewer, then the 60-byte minimum). Without this, a refused IPv6 connection has no
    // padding "payload" and the model calls IPv6 scan probes benign.
    let frame = (data.len() as u32 - v6_extra).max(60);
    let payload = frame.saturating_sub(14 + ihl as u32 - v6_extra + l4hdr);
    Some(Pkt { src, dst, sport, dport, proto, payload, hdr_len: l4hdr, flags, win, l4hdr, ts_us })
}

type Key = ((IpAddr, u16), (IpAddr, u16), u8);

fn key_of(p: &Pkt) -> Key {
    let a = (p.src, p.sport);
    let b = (p.dst, p.dport);
    if a <= b { (a, b, p.proto) } else { (b, a, p.proto) }
}

/// Running min/max/mean/std (Welford), sample std (n-1)
struct Stat {
    n: u64,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl Default for Stat {
    fn default() -> Self {
        Stat { n: 0, mean: 0.0, m2: 0.0, min: f64::MAX, max: f64::MIN }
    }
}

impl Stat {
    fn add(&mut self, x: f64) {
        self.n += 1;
        let d = x - self.mean;
        self.mean += d / self.n as f64;
        self.m2 += d * (x - self.mean);
        self.min = self.min.min(x);
        self.max = self.max.max(x);
    }
    fn mean(&self) -> f64 { if self.n == 0 { 0.0 } else { self.mean } }
    fn std(&self) -> f64 { if self.n < 2 { 0.0 } else { (self.m2 / (self.n - 1) as f64).sqrt() } }
    fn min(&self) -> f64 { if self.n == 0 { 0.0 } else { self.min } }
    fn max(&self) -> f64 { if self.n == 0 { 0.0 } else { self.max } }
    fn total(&self) -> f64 { self.mean * self.n as f64 }
}

#[derive(Default)]
struct Flow {
    src: Option<(IpAddr, u16)>, // initiator = forward direction
    dst: Option<(IpAddr, u16)>,
    proto: u8,
    start_us: u64,
    last_us: u64,
    fwd_pkts: u32,
    bwd_pkts: u32,
    fwd_bytes: u64,
    bwd_bytes: u64,
    fwd_hdr: u64,
    bwd_hdr: u64,
    fwd_len: Stat,
    bwd_len: Stat,
    all_len: Stat,
    syn: u32,
    fin: u32,
    rst: u32,
    psh: u32,
    ack: u32,
    flow_iat: Stat,
    fwd_iat: Stat,
    last_fwd_us: Option<u64>,
    init_win_fwd: Option<u32>,
    init_win_bwd: Option<u32>,
    act_data_fwd: u32,
    min_seg_fwd: Option<u32>,
}

impl Flow {
    fn new(p: &Pkt) -> Self {
        Flow {
            src: Some((p.src, p.sport)),
            dst: Some((p.dst, p.dport)),
            proto: p.proto,
            start_us: p.ts_us,
            last_us: p.ts_us,
            ..Default::default()
        }
    }

    fn update(&mut self, p: &Pkt) {
        let is_fwd = self.src == Some((p.src, p.sport));
        let len = p.payload as f64;
        if self.fwd_pkts + self.bwd_pkts > 0 {
            self.flow_iat.add(p.ts_us.saturating_sub(self.last_us) as f64);
        }
        if is_fwd {
            if let Some(prev) = self.last_fwd_us {
                self.fwd_iat.add(p.ts_us.saturating_sub(prev) as f64);
            }
            self.last_fwd_us = Some(p.ts_us);
            if p.proto == 6 {
                if self.init_win_fwd.is_none() { self.init_win_fwd = Some(p.win); }
                self.min_seg_fwd = Some(self.min_seg_fwd.map_or(p.l4hdr, |m| m.min(p.l4hdr)));
            }
            if p.payload > 0 { self.act_data_fwd += 1; }
        } else if p.proto == 6 && self.init_win_bwd.is_none() {
            self.init_win_bwd = Some(p.win);
        }
        if is_fwd {
            self.fwd_pkts += 1;
            self.fwd_bytes += p.payload as u64;
            self.fwd_hdr += p.hdr_len as u64;
            self.fwd_len.add(len);
        } else {
            self.bwd_pkts += 1;
            self.bwd_bytes += p.payload as u64;
            self.bwd_hdr += p.hdr_len as u64;
            self.bwd_len.add(len);
        }
        self.all_len.add(len);
        self.last_us = p.ts_us;
        if p.flags & 0x02 != 0 { self.syn += 1; }
        if p.flags & 0x01 != 0 { self.fin += 1; }
        if p.flags & 0x04 != 0 { self.rst += 1; }
        if p.flags & 0x08 != 0 { self.psh += 1; }
        if p.flags & 0x10 != 0 { self.ack += 1; }
    }

    fn features(&self) -> Vec<(&'static str, f64)> {
        let dur_us = (self.last_us - self.start_us) as f64;
        let dur_s = dur_us / 1e6;
        let rate = |x: f64| if dur_s > 0.0 { x / dur_s } else { 0.0 };
        let fp = self.fwd_pkts as f64;
        let bp = self.bwd_pkts as f64;
        vec![
            ("Destination Port", self.dst.unwrap().1 as f64),
            ("Flow Duration", dur_us),
            ("Total Fwd Packets", fp),
            ("Total Backward Packets", bp),
            ("Total Length of Fwd Packets", self.fwd_bytes as f64),
            ("Total Length of Bwd Packets", self.bwd_bytes as f64),
            ("Fwd Packet Length Max", self.fwd_len.max()),
            ("Fwd Packet Length Min", self.fwd_len.min()),
            ("Fwd Packet Length Mean", self.fwd_len.mean()),
            ("Fwd Packet Length Std", self.fwd_len.std()),
            ("Bwd Packet Length Max", self.bwd_len.max()),
            ("Bwd Packet Length Min", self.bwd_len.min()),
            ("Bwd Packet Length Mean", self.bwd_len.mean()),
            ("Bwd Packet Length Std", self.bwd_len.std()),
            ("Flow Bytes/s", rate((self.fwd_bytes + self.bwd_bytes) as f64)),
            ("Flow Packets/s", rate(fp + bp)),
            ("Flow IAT Mean", self.flow_iat.mean()),
            ("Flow IAT Std", self.flow_iat.std()),
            ("Flow IAT Max", self.flow_iat.max()),
            ("Flow IAT Min", self.flow_iat.min()),
            ("Fwd IAT Total", self.fwd_iat.total()),
            ("Fwd IAT Mean", self.fwd_iat.mean()),
            ("Fwd IAT Std", self.fwd_iat.std()),
            ("Fwd IAT Max", self.fwd_iat.max()),
            ("Fwd IAT Min", self.fwd_iat.min()),
            ("Fwd Header Length", self.fwd_hdr as f64),
            ("Bwd Header Length", self.bwd_hdr as f64),
            ("Fwd Packets/s", rate(fp)),
            ("Bwd Packets/s", rate(bp)),
            ("Packet Length Mean", self.all_len.mean()),
            ("Packet Length Std", self.all_len.std()),
            ("Init_Win_bytes_forward", self.init_win_fwd.map_or(-1.0, |v| v as f64)),
            ("Init_Win_bytes_backward", self.init_win_bwd.map_or(-1.0, |v| v as f64)),
            ("act_data_pkt_fwd", self.act_data_fwd as f64),
            ("min_seg_size_forward", self.min_seg_fwd.map_or(0.0, |v| v as f64)),
        ]
    }
}

// Flood protection: every buffer between the network and the database has a cap. What does not fit is
// dropped and counted (logged once a second and reported by /api/health), so a flood of new connections
// cannot exhaust memory.
static FLOWS_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static FLOWS_QUEUE_DROPPED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name).ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0).unwrap_or(default)
}

static TX: std::sync::OnceLock<tokio::sync::mpsc::Sender<pb::FlowFeatures>> =
    std::sync::OnceLock::new();

// Wakes /api/stream listeners whenever a new alert is stored.
static ALERT_BUS: std::sync::OnceLock<tokio::sync::broadcast::Sender<()>> =
    std::sync::OnceLock::new();

fn alert_bus() -> &'static tokio::sync::broadcast::Sender<()> {
    ALERT_BUS.get_or_init(|| tokio::sync::broadcast::channel(16).0)
}

// Minimum confidence for rare, poorly-learned classes (override with NS_RARE_MIN_CONF).
fn rare_min_conf() -> f32 {
    static V: std::sync::OnceLock<f32> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        env::var("NS_RARE_MIN_CONF").ok().and_then(|v| v.parse().ok()).unwrap_or(0.8)
    })
}

fn rare_class_blocked(label: &str, conf: f32, min: f32) -> bool {
    matches!(label, "Heartbleed" | "Infiltration") && conf < min
}

// ---- Optional phone notifications via ntfy (off unless NS_NTFY_TOPIC is set) ----
// Severity rules mirror dashboard/src/lib.ts.
fn severity_rank(label: &str, conf: f32) -> u8 {
    match label {
        "DDoS" | "Bot" | "Infiltration" | "Heartbleed" => 3,
        "DoS Hulk" | "DoS GoldenEye" | "DoS Slowhttptest" | "DoS slowloris" | "SSH-Patator"
        | "Web Attack" | "Web Attack - Brute Force" | "Web Attack - Sql Injection" | "Web Attack - XSS" => 2,
        "Anomaly (unknown)" => {
            if conf < 0.6 {
                0
            } else {
                1
            }
        }
        _ => 1,
    }
}

fn severity_name(rank: u8) -> &'static str {
    match rank {
        0 => "low",
        1 => "medium",
        2 => "high",
        _ => "critical",
    }
}

fn parse_min_severity(s: &str) -> u8 {
    match s.trim().to_ascii_lowercase().as_str() {
        "low" => 0,
        "high" => 2,
        "critical" => 3,
        _ => 1,
    }
}

fn notify_phone(src: &str, label: &str, count: usize, unit: &str, avg: f32) {
    let topic = match env::var("NS_NTFY_TOPIC") {
        Ok(t) if !t.trim().is_empty() => t.trim().to_string(),
        _ => return,
    };
    let min = parse_min_severity(&env::var("NS_NTFY_MIN_SEVERITY").unwrap_or_default());
    let rank = severity_rank(label, avg);
    if rank < min {
        return;
    }
    let server = env::var("NS_NTFY_SERVER").unwrap_or_else(|_| "https://ntfy.sh".to_string());
    let url = format!("{}/{}", server.trim_end_matches('/'), topic);
    let title = format!("NetSpectre: {} ({})", label, severity_name(rank));
    let body = format!("{src} | {count} {unit} in 10s | confidence {:.0}%", avg * 100.0);
    let priority = match rank {
        3 => "urgent",
        2 => "high",
        _ => "default",
    };
    // Separate thread so a slow network never delays flow processing.
    std::thread::spawn(move || {
        let res = ureq::post(url.as_str())
            .header("Title", title.as_str())
            .header("Priority", priority)
            .send(body.as_str());
        if let Err(e) = res {
            eprintln!("ntfy error: {e}");
        }
    });
}

fn emit(f: &Flow) {
    let (s, d) = (f.src.unwrap(), f.dst.unwrap());
    let req = pb::FlowFeatures {
        src_ip: s.0.to_string(),
        src_port: s.1 as u32,
        dst_ip: d.0.to_string(),
        dst_port: d.1 as u32,
        protocol: f.proto as u32,
        timestamp_us: f.last_us,
        features: f.features().iter().map(|x| x.1 as f32).collect(),
    };
    if let Some(tx) = TX.get() {
        enqueue(tx, req);
    }
}

// Hands a finished flow to the classifier without blocking capture; returns false if the queue was full.
fn enqueue(tx: &tokio::sync::mpsc::Sender<pb::FlowFeatures>, req: pb::FlowFeatures) -> bool {
    match tx.try_send(req) {
        Ok(()) => true,
        Err(_) => {
            FLOWS_QUEUE_DROPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        }
    }
}

fn start_worker(addr: String) {
    let (tx, rx) = tokio::sync::mpsc::channel::<pb::FlowFeatures>(env_usize("NS_QUEUE_MAX", 20_000));
    TX.set(tx).ok();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::spawn(run_api());
            run_client(addr, rx).await
        });
    });
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            src_ip TEXT NOT NULL,
            label TEXT NOT NULL,
            flow_count INTEGER NOT NULL,
            avg_confidence REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'new'
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_utc);
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            last_seen TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            flow_count INTEGER NOT NULL DEFAULT 0
        );";

fn open_db() -> rusqlite::Connection {
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    if let Some(dir) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let db = rusqlite::Connection::open(&path).expect("open db");
    let _ = db.pragma_update(None, "journal_mode", "WAL");
    let _ = db.pragma_update(None, "synchronous", "NORMAL");
    db.execute_batch(SCHEMA)
    .expect("create schema");
    let has_col = db
        .prepare("SELECT 1 FROM pragma_table_info('alerts') WHERE name = 'explanation'")
        .and_then(|mut st| st.exists([]))
        .unwrap_or(false);
    if !has_col {
        let _ = db.execute("ALTER TABLE alerts ADD COLUMN explanation TEXT", []);
    }
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)); // owner writes, others may only read
    eprintln!("alert database: {path}");
    db
}

#[derive(serde::Serialize)]
struct Health {
    status: &'static str,
    flows_refused: u64,
    flows_queue_dropped: u64,
}

#[derive(serde::Serialize)]
struct AlertRow {
    id: i64,
    ts_utc: String,
    src_ip: String,
    label: String,
    flow_count: i64,
    avg_confidence: f64,
    status: String,
    explanation: serde_json::Value,
}

async fn api_health() -> axum::Json<Health> {
    use std::sync::atomic::Ordering::Relaxed;
    axum::Json(Health {
        status: "ok",
        flows_refused: FLOWS_REFUSED.load(Relaxed),
        flows_queue_dropped: FLOWS_QUEUE_DROPPED.load(Relaxed),
    })
}

async fn api_alerts(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Result<axum::Json<Vec<AlertRow>>, axum::http::StatusCode> {
    use axum::http::StatusCode;
    let limit: i64 = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50).clamp(1, 500);
    // Optional per-device filter (empty string = all devices); passed as a bound parameter.
    let ip = q.get("src_ip").cloned().unwrap_or_default();
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    let db = rusqlite::Connection::open(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare("SELECT id, ts_utc, src_ip, label, flow_count, avg_confidence, status, explanation FROM alerts WHERE (?2 = '' OR src_ip = ?2) ORDER BY id DESC LIMIT ?1")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map(rusqlite::params![limit, ip], |r| {
            Ok(AlertRow {
                id: r.get(0)?,
                ts_utc: r.get(1)?,
                src_ip: r.get(2)?,
                label: r.get(3)?,
                flow_count: r.get(4)?,
                avg_confidence: r.get(5)?,
                status: r.get(6)?,
                explanation: r
                    .get::<_, Option<String>>(7)?
                    .and_then(|t| serde_json::from_str(&t).ok())
                    .unwrap_or(serde_json::Value::Array(vec![])),
            })
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(axum::Json(rows))
}

#[derive(serde::Deserialize)]
struct StatusUpdate {
    id: i64,
    status: String,
}

async fn api_set_status(axum::Json(u): axum::Json<StatusUpdate>) -> axum::http::StatusCode {
    use axum::http::StatusCode;
    if !["new", "acknowledged", "dismissed"].contains(&u.status.as_str()) {
        return StatusCode::BAD_REQUEST;
    }
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    let Ok(db) = rusqlite::Connection::open(path) else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    match db.execute("UPDATE alerts SET status = ?1 WHERE id = ?2", rusqlite::params![u.status, u.id]) {
        Ok(0) => StatusCode::NOT_FOUND,
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn api_devices() -> Result<axum::Json<Vec<serde_json::Value>>, axum::http::StatusCode> {
    use axum::http::StatusCode;
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    let db = rusqlite::Connection::open(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare(
            "SELECT d.ip, d.first_seen, d.last_seen, d.flow_count, \
             (SELECT COUNT(*) FROM alerts a WHERE a.src_ip = d.ip) \
             FROM devices d ORDER BY d.last_seen DESC",
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "ip": r.get::<_, String>(0)?,
                "first_seen": r.get::<_, String>(1)?,
                "last_seen": r.get::<_, String>(2)?,
                "flow_count": r.get::<_, i64>(3)?,
                "alert_count": r.get::<_, i64>(4)?,
            }))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(rows))
}

async fn api_export() -> Result<impl axum::response::IntoResponse, axum::http::StatusCode> {
    use axum::http::{header, StatusCode};
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    let db = rusqlite::Connection::open(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare("SELECT id, ts_utc, src_ip, label, flow_count, avg_confidence, status, explanation FROM alerts ORDER BY id DESC")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let esc = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut out = String::from("id,time_utc,source_ip,attack,flows,confidence,status,reasons\n");
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, f64>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    for row in rows {
        let (id, ts, ip, label, n, conf, st, ex) = row.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let reasons = ex
            .and_then(|e| serde_json::from_str::<Vec<serde_json::Value>>(&e).ok())
            .map(|v| v.iter().filter_map(|x| x["text"].as_str()).collect::<Vec<_>>().join("; "))
            .unwrap_or_default();
        out.push_str(&format!(
            "{id},{},{},{},{n},{conf:.3},{},{}\n",
            esc(&ts), esc(&ip), esc(&label), esc(&st), esc(&reasons)
        ));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"netspectre_alerts.csv\""),
        ],
        out,
    ))
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// Who may use the API without a token: programs on this machine talking to it directly, and browsers on
// this machine going through the dashboard's nginx proxy (nginx sets X-Forwarded-For to the real client).
// Everyone else (phone, other LAN devices, anyone reaching nginx from the network) needs NS_API_TOKEN,
// sent as the x-api-token header or, for EventSource and download links, as a ?token= query parameter.
fn authorized(peer_loopback: bool, forwarded_for: Option<&str>, header_token: Option<&str>, query: Option<&str>, want: &str) -> bool {
    let local = peer_loopback
        && forwarded_for.map_or(true, |f| {
            f.split(',').next().and_then(|ip| ip.trim().parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback())
        });
    if local {
        return true;
    }
    let query_token = query.and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")));
    let got = header_token.or(query_token).unwrap_or("");
    !want.is_empty() && ct_eq(got, want)
}

async fn require_token(
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let want = env::var("NS_API_TOKEN").unwrap_or_default();
    let h = req.headers();
    let ok = authorized(
        peer.ip().is_loopback(),
        h.get("x-forwarded-for").and_then(|v| v.to_str().ok()),
        h.get("x-api-token").and_then(|v| v.to_str().ok()),
        req.uri().query(),
        &want,
    );
    if !ok {
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

// Counts over ALL stored alerts (the alert list endpoint is capped), for the dashboard overview.
async fn api_stats() -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    use axum::http::StatusCode;
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    let db = rusqlite::Connection::open(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let one = |sql: &str| -> Result<i64, StatusCode> {
        db.query_row(sql, [], |r| r.get(0)).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    };
    let total = one("SELECT COUNT(*) FROM alerts")?;
    let new_alerts = one("SELECT COUNT(*) FROM alerts WHERE status = 'new'")?;
    let last_24h = one(
        "SELECT COUNT(*) FROM alerts WHERE ts_utc >= strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 day')",
    )?;
    let devices = one("SELECT COUNT(*) FROM devices")?;
    let mut stmt = db
        .prepare("SELECT label, COUNT(*) FROM alerts GROUP BY label ORDER BY COUNT(*) DESC, label")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let by_label: Vec<serde_json::Value> = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({ "label": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)? }))
        })
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .filter_map(|r| r.ok())
        .collect();
    Ok(axum::Json(serde_json::json!({
        "total": total,
        "new": new_alerts,
        "last_24h": last_24h,
        "devices": devices,
        "by_label": by_label,
    })))
}

async fn api_stream() -> axum::response::sse::Sse<
    impl tokio_stream::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    use tokio_stream::StreamExt;
    let stream = tokio_stream::wrappers::BroadcastStream::new(alert_bus().subscribe())
        .map(|_| Ok(axum::response::sse::Event::default().event("alert").data("new")));
    axum::response::sse::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

async fn run_api() {
    let _ = open_db(); // make sure the schema exists
    let app = axum::Router::new()
        .route("/api/health", axum::routing::get(api_health))
        .route("/api/alerts", axum::routing::get(api_alerts))
        .route("/api/alerts/status", axum::routing::post(api_set_status))
        .route("/api/devices", axum::routing::get(api_devices))
        .route("/api/alerts/export", axum::routing::get(api_export))
        .route("/api/stream", axum::routing::get(api_stream))
        .route("/api/stats", axum::routing::get(api_stats))
        .layer(axum::middleware::from_fn(require_token))
        .layer(tower_http::cors::CorsLayer::permissive());
    let addr = env::var("NS_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind api address");
    eprintln!("REST API on http://{addr}");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
}

async fn run_client(addr: String, mut rx: tokio::sync::mpsc::Receiver<pb::FlowFeatures>) {
    use std::collections::{HashMap, HashSet};
    let mut client = loop {
        match InferenceClient::connect(addr.clone()).await {
            Ok(c) => break c,
            Err(e) => {
                eprintln!("waiting for ML server at {addr}: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    eprintln!("connected to ML server at {addr}");
    let db = open_db();
    let verbose = env::var("NS_VERBOSE").is_ok();
    let ae_thr: f32 = env::var("NS_AE_THRESHOLD").ok().and_then(|s| s.parse().ok()).unwrap_or(0.2369);
    let ae_ignore: Vec<String> = env::var("NS_ANOMALY_IGNORE")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let mut hist: HashMap<(String, String), Vec<(Instant, u32, f32)>> = HashMap::new();
    let mut last_alert: HashMap<(String, String), Instant> = HashMap::new();

    let mut seen: u64 = 0;
    while let Some(req) = rx.recv().await {
        // keep the per-source history small: drop pairs with no recent flows and expired cooldowns
        seen += 1;
        if seen % 1000 == 0 {
            let now = Instant::now();
            hist.retain(|_, v| v.last().is_some_and(|x| now.duration_since(x.0) <= Duration::from_secs(10)));
            last_alert.retain(|_, t| now.duration_since(*t) <= Duration::from_secs(30));
        }
        let (src, dport) = (req.src_ip.clone(), req.dst_port);
        if let Err(e) = db.execute(
            "INSERT INTO devices (ip, flow_count) VALUES (?1, 1) \
             ON CONFLICT(ip) DO UPDATE SET last_seen = strftime('%Y-%m-%dT%H:%M:%SZ','now'), flow_count = flow_count + 1",
            rusqlite::params![src],
        ) {
            eprintln!("db error (devices): {e}");
        }
        let resp = match client.classify(req).await {
            Ok(r) => r.into_inner(),
            Err(e) => {
                eprintln!("classify error: {e}");
                continue;
            }
        };
        let mut label = resp.label.clone();
        let mut conf = resp.confidence;
        if label == "BENIGN" {
            if ae_thr > 0.0 && resp.anomaly_score > ae_thr && !ae_ignore.iter().any(|ip| *ip == src) {
                label = "Anomaly (unknown)".to_string();
                conf = (resp.anomaly_score / (2.0 * ae_thr)).min(1.0);
            } else {
                if verbose {
                    println!("ok    {src} -> port {dport}  BENIGN ({:.2})", resp.confidence);
                }
                continue;
            }
        }
        // Rare classes (few training flows) need stronger evidence before they may raise an alert.
        if rare_class_blocked(&label, conf, rare_min_conf()) {
            if verbose {
                println!("skip  {src} -> port {dport}  {label} ({conf:.2}) below rare-class minimum");
            }
            continue;
        }
        let key = (src.clone(), label.clone());
        let now = Instant::now();
        let h = hist.entry(key.clone()).or_default();
        h.retain(|x| now.duration_since(x.0) <= Duration::from_secs(10));
        h.push((now, dport, conf));
        let (count, unit, need) = if label == "PortScan" {
            (h.iter().map(|x| x.1).collect::<HashSet<_>>().len(), "ports", 10)
        } else {
            (h.len(), "flows", if label == "Anomaly (unknown)" { 5 } else { 3 })
        };
        let quiet = last_alert.get(&key).map_or(true, |t| now.duration_since(*t) > Duration::from_secs(30));
        if count >= need && quiet {
            last_alert.insert(key, now);
            let avg = h.iter().map(|x| x.2).sum::<f32>() / h.len() as f32;
            println!("ALERT {src} -> {}: {count} {unit} in 10s (avg confidence {avg:.2})", label);
            let reasons_json = serde_json::to_string(
                &resp
                    .reasons
                    .iter()
                    .map(|r| serde_json::json!({"feature": r.feature, "text": r.text, "weight": r.weight}))
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_default();
            let reasons_json = if label == "Anomaly (unknown)" {
                serde_json::json!([{
                    "feature": "anomaly_score",
                    "text": format!(
                        "unusual traffic pattern not matching known attacks (reconstruction error {:.2} vs threshold {:.2})",
                        resp.anomaly_score, ae_thr
                    ),
                    "weight": 100.0
                }])
                .to_string()
            } else {
                reasons_json
            };
            if let Err(e) = db.execute(
                "INSERT INTO alerts (src_ip, label, flow_count, avg_confidence, explanation) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![src, label, count as i64, avg as f64, reasons_json],
            ) {
                eprintln!("db error: {e}");
            } else {
                let _ = alert_bus().send(());
                notify_phone(&src, &label, count, unit, avg);
            }
        }
    }
}

// Privacy policy promises at most NS_RETENTION_DAYS (default 30) of alerts and devices.
fn purge_old(days: u32) -> (usize, usize) {
    purge_in(&open_db(), days)
}

fn purge_in(db: &rusqlite::Connection, days: u32) -> (usize, usize) {
    let cut = format!("-{days} days");
    let a = db
        .execute("DELETE FROM alerts WHERE ts_utc < strftime('%Y-%m-%dT%H:%M:%SZ','now',?1)", [&cut])
        .unwrap_or(0);
    let d = db
        .execute("DELETE FROM devices WHERE last_seen < strftime('%Y-%m-%dT%H:%M:%SZ','now',?1)", [&cut])
        .unwrap_or(0);
    (a, d)
}

fn start_retention() {
    let days: u32 = env::var("NS_RETENTION_DAYS").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
    if days == 0 {
        return;
    }
    std::thread::spawn(move || loop {
        let (a, d) = purge_old(days);
        if a + d > 0 {
            eprintln!("retention: removed {a} alerts and {d} devices older than {days} days");
        }
        std::thread::sleep(std::time::Duration::from_secs(3600));
    });
}

// The flow table. New flows are refused while it holds `max` flows; flows already being tracked
// continue normally and the idle sweep frees room.
struct Tracker {
    flows: HashMap<Key, Flow>,
    closed: HashMap<Key, Instant>, // recently finished flows: late packets of these are ignored
    max: usize,
    refused: u64,
}

impl Tracker {
    fn new(max: usize) -> Self {
        Tracker { flows: HashMap::new(), closed: HashMap::new(), max, refused: 0 }
    }

    // Adds one packet; returns the flow if this packet finished it (second FIN or any RST).
    fn packet(&mut self, p: &Pkt) -> Option<Flow> {
        let k = key_of(p);
        if self.closed.get(&k).is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
            return None;
        }
        if !self.flows.contains_key(&k) && self.flows.len() >= self.max {
            self.refused += 1;
            FLOWS_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        let f = self.flows.entry(k).or_insert_with(|| Flow::new(p));
        f.update(p);
        if f.fin >= 2 || f.rst > 0 {
            let done = self.flows.remove(&k);
            if self.closed.len() < self.max {
                self.closed.insert(k, Instant::now());
            }
            return done;
        }
        None
    }

    // Removes and returns flows idle for longer than idle_us; forgets old closed-flow entries.
    fn expire(&mut self, now_us: u64, idle_us: u64) -> Vec<Flow> {
        self.closed.retain(|_, t| t.elapsed() < Duration::from_secs(10));
        let expired: Vec<Key> = self
            .flows
            .iter()
            .filter(|(_, f)| now_us.saturating_sub(f.last_us) > idle_us)
            .map(|(k, _)| *k)
            .collect();
        expired.into_iter().filter_map(|k| self.flows.remove(&k)).collect()
    }
}

fn main() {
    let iface = env::args().nth(1).unwrap_or_else(|| "eth0".to_string());
    let filter = env::args().nth(2).filter(|f| f != "-");
    let idle_us: u64 = env::args().nth(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(5) * 1_000_000;
    start_retention();
    start_worker(env::var("NS_ML_ADDR").unwrap_or_else(|_| "http://127.0.0.1:50051".to_string()));

    let dev = Device::list()
        .expect("failed to list devices")
        .into_iter()
        .find(|d| d.name == iface)
        .unwrap_or_else(|| panic!("interface {iface} not found"));

    let mut cap = Capture::from_device(dev)
        .expect("device error")
        .promisc(true)
        .snaplen(65535)
        .buffer_size(64 * 1024 * 1024)
        .timeout(500)
        .immediate_mode(true)
        .open()
        .expect("failed to open capture")
        .setnonblock()
        .expect("nonblock");
    if let Some(f) = filter {
        cap.filter(&f, true).expect("bad filter");
    }

    eprintln!("monitoring {iface} (flows close on FIN/RST or after {}s idle)...", idle_us / 1_000_000);
    let max_flows = env_usize("NS_MAX_FLOWS", 100_000);
    let mut tracker = Tracker::new(max_flows);
    let mut last_sweep = Instant::now();
    let mut last_dropped: u32 = 0;
    let (mut warned_refused, mut warned_queue) = (0u64, 0u64);
    loop {
        match cap.next_packet() {
            Ok(pk) => {
                let ts = pk.header.ts.tv_sec as u64 * 1_000_000 + pk.header.ts.tv_usec as u64;
                if let Some(p) = parse(pk.data, ts) {
                    if let Some(f) = tracker.packet(&p) {
                        emit(&f);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => {
                eprintln!("capture error: {e}");
                break;
            }
        }
        if last_sweep.elapsed() >= Duration::from_secs(1) {
            last_sweep = Instant::now();
            if let Ok(st) = cap.stats() {
                if st.dropped > last_dropped {
                    eprintln!("warning: kernel dropped {} packets so far (received {})", st.dropped, st.received);
                    last_dropped = st.dropped;
                }
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
            for f in tracker.expire(now, idle_us) {
                emit(&f);
            }
            use std::sync::atomic::Ordering::Relaxed;
            let (r, q) = (FLOWS_REFUSED.load(Relaxed), FLOWS_QUEUE_DROPPED.load(Relaxed));
            if r > warned_refused || q > warned_queue {
                eprintln!(
                    "warning: flood protection active: {r} new flows refused (table full at {max_flows}), {q} finished flows dropped (classifier queue full)"
                );
                (warned_refused, warned_queue) = (r, q);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn approx(a: f64, b: f64) -> bool { (a - b).abs() < 1e-6 }

    /// Build an Ethernet + IPv4 + TCP/UDP frame by hand.
    fn frame(proto: u8, src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, win: u16, payload: usize) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]); // IPv4
        let l4len = if proto == 6 { 20 } else { 8 };
        let total = (20 + l4len + payload) as u16;
        let mut ip = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, proto, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        if proto == 6 {
            f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // seq + ack
            f.push(0x50); // data offset = 5 words
            f.push(flags);
            f.extend_from_slice(&win.to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 0]); // checksum + urgent
        } else {
            f.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
            f.extend_from_slice(&[0, 0]);
        }
        f.extend(std::iter::repeat(0xAB).take(payload));
        f
    }

    fn pkt(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, win: u32, payload: u32, ts_us: u64) -> Pkt {
        Pkt {
            src: IpAddr::from(src), dst: IpAddr::from(dst), sport, dport,
            proto: 6, payload, hdr_len: 20, flags, win, l4hdr: 20, ts_us,
        }
    }

    fn feat(f: &Flow, name: &str) -> f64 {
        f.features().into_iter().find(|(n, _)| *n == name).unwrap_or_else(|| panic!("no feature {name}")).1
    }

    fn frame6(proto: u8, sport: u16, dport: u16, flags: u8, win: u16, payload: usize) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x86, 0xDD]);
        let l4len = if proto == 6 { 20 } else { 8 };
        let plen = (l4len + payload) as u16;
        f.extend_from_slice(&[0x60, 0, 0, 0, (plen >> 8) as u8, plen as u8, proto, 64]);
        f.extend_from_slice(&"2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        f.extend_from_slice(&"2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap().octets());
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        if proto == 6 {
            f.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0x50, flags]);
            f.extend_from_slice(&win.to_be_bytes());
            f.extend_from_slice(&[0, 0, 0, 0]);
        } else {
            f.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
            f.extend_from_slice(&[0, 0]);
        }
        f.extend(std::iter::repeat(0xAB).take(payload));
        f
    }

    #[test]
    fn parses_ipv6_tcp_and_udp() {
        let p = parse(&frame6(6, 50000, 443, 0x02, 64800, 0), 7).expect("IPv6 TCP should parse");
        assert_eq!(p.src.to_string(), "2001:db8::1");
        assert_eq!(p.dst.to_string(), "2001:db8::2");
        assert_eq!((p.sport, p.dport, p.proto, p.flags, p.win, p.l4hdr), (50000, 443, 6, 0x02, 64800, 20));
        assert_eq!(p.payload, 6); // measured like the IPv4 equivalent: 54 bytes, padded to 60 (as CICIDS2017 counts it)
        let u = parse(&frame6(17, 5353, 53, 0, 0, 30), 0).expect("IPv6 UDP should parse");
        assert_eq!((u.dport, u.proto, u.payload, u.l4hdr), (53, 17, 30, 8)); // real data is unaffected
        let mut bad = frame6(6, 1, 2, 0, 0, 0);
        bad[14] = 0x45; // version nibble says IPv4
        assert!(parse(&bad, 0).is_none());
        let mut icmp6 = frame6(6, 1, 2, 0, 0, 0);
        icmp6[14 + 6] = 58;
        assert!(parse(&icmp6, 0).is_none());
    }

    #[test]
    fn parses_tcp_syn() {
        let d = frame(6, [10, 0, 0, 1], [10, 0, 0, 2], 40000, 80, 0x02, 1024, 100);
        let p = parse(&d, 5).expect("should parse");
        assert_eq!(p.src, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(p.dst, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!((p.sport, p.dport, p.proto), (40000, 80, 6));
        assert_eq!(p.flags, 0x02);
        assert_eq!(p.win, 1024);
        assert_eq!(p.payload, 100);
        assert_eq!(p.l4hdr, 20);
        assert_eq!(p.ts_us, 5);
    }

    #[test]
    fn parses_udp() {
        let d = frame(17, [192, 168, 1, 5], [8, 8, 8, 8], 5353, 53, 0, 0, 40);
        let p = parse(&d, 0).expect("should parse");
        assert_eq!((p.sport, p.dport, p.proto), (5353, 53, 17));
        assert_eq!(p.l4hdr, 8);
        assert_eq!(p.win, 0);
        assert_eq!(p.payload, 40);
    }

    #[test]
    fn rejects_malformed_short_and_other_protocols() {
        let mut v6 = frame(6, [1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0, 0, 0);
        v6[12] = 0x86; v6[13] = 0xDD; // IPv6 ethertype but an IPv4 header inside
        assert!(parse(&v6, 0).is_none());
        let mut arp = frame(6, [1, 1, 1, 1], [2, 2, 2, 2], 1, 2, 0, 0, 0);
        arp[12] = 0x08; arp[13] = 0x06;
        assert!(parse(&arp, 0).is_none());
        assert!(parse(&[0u8; 10], 0).is_none());
        let icmp = frame(1, [1, 1, 1, 1], [2, 2, 2, 2], 0, 0, 0, 0, 8);
        assert!(parse(&icmp, 0).is_none());
    }

    #[test]
    fn short_frames_count_ethernet_padding_as_payload() {
        // 14 + 20 + 20 = 54 bytes on the wire, padded to 60 -> 6 bytes of "payload"
        let d = frame(6, [1, 1, 1, 1], [2, 2, 2, 2], 1000, 22, 0x02, 512, 0);
        assert_eq!(d.len(), 54);
        assert_eq!(parse(&d, 0).unwrap().payload, 6);
    }

    #[test]
    fn flow_key_is_direction_independent() {
        let a = pkt([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80, 0, 0, 0, 0);
        let b = pkt([10, 0, 0, 2], [10, 0, 0, 1], 80, 5000, 0, 0, 0, 0);
        assert_eq!(key_of(&a), key_of(&b));
        let c = pkt([10, 0, 0, 1], [10, 0, 0, 2], 5001, 80, 0, 0, 0, 0);
        assert_ne!(key_of(&a), key_of(&c));
    }

    #[test]
    fn stat_matches_hand_computed_values() {
        let mut s = Stat::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] { s.add(x); }
        assert!(approx(s.mean(), 5.0));
        assert!(approx(s.std(), (32.0f64 / 7.0).sqrt())); // sample std (n-1)
        assert!(approx(s.min(), 2.0));
        assert!(approx(s.max(), 9.0));
        assert!(approx(s.total(), 40.0));
    }

    #[test]
    fn stat_empty_and_single_value_are_zero_not_nan() {
        let s = Stat::default();
        assert_eq!((s.mean(), s.std(), s.min(), s.max()), (0.0, 0.0, 0.0, 0.0));
        let mut one = Stat::default();
        one.add(7.0);
        assert!(approx(one.mean(), 7.0));
        assert_eq!(one.std(), 0.0);
    }

    #[test]
    fn flow_features_for_a_three_packet_handshake() {
        let c = [10, 0, 0, 1];
        let s = [10, 0, 0, 2];
        let mut f = Flow::new(&pkt(c, s, 40000, 80, 0x02, 1000, 100, 0));
        f.update(&pkt(c, s, 40000, 80, 0x02, 1000, 100, 0)); // SYN, 100 B, t=0
        f.update(&pkt(s, c, 80, 40000, 0x12, 2000, 50, 1000)); // SYN+ACK, 50 B, t=1 ms
        f.update(&pkt(c, s, 40000, 80, 0x10, 1000, 0, 3000)); // ACK, 0 B, t=3 ms

        assert_eq!(f.syn, 2);
        assert_eq!(f.ack, 2);
        assert_eq!((f.fin, f.rst, f.psh), (0, 0, 0));

        assert_eq!(feat(&f, "Destination Port"), 80.0);
        assert_eq!(feat(&f, "Total Fwd Packets"), 2.0);
        assert_eq!(feat(&f, "Total Backward Packets"), 1.0);
        assert_eq!(feat(&f, "Total Length of Fwd Packets"), 100.0);
        assert_eq!(feat(&f, "Total Length of Bwd Packets"), 50.0);
        assert!(approx(feat(&f, "Flow Duration"), 3000.0));
        assert_eq!(feat(&f, "Fwd Packet Length Max"), 100.0);
        assert_eq!(feat(&f, "Fwd Packet Length Min"), 0.0);
        assert!(approx(feat(&f, "Fwd Packet Length Mean"), 50.0));
        // inter-arrival times: 1000 us and 2000 us
        assert!(approx(feat(&f, "Flow IAT Mean"), 1500.0));
        assert_eq!(feat(&f, "Flow IAT Min"), 1000.0);
        assert_eq!(feat(&f, "Flow IAT Max"), 2000.0);
        assert!(approx(feat(&f, "Fwd IAT Total"), 3000.0));
        // rates: 3 packets / 3 ms, 150 bytes / 3 ms
        assert!(approx(feat(&f, "Flow Packets/s"), 1000.0));
        assert!(approx(feat(&f, "Flow Bytes/s"), 50000.0));
        assert_eq!(feat(&f, "Fwd Header Length"), 40.0);
        assert_eq!(feat(&f, "Bwd Header Length"), 20.0);
        assert_eq!(feat(&f, "Init_Win_bytes_forward"), 1000.0);
        assert_eq!(feat(&f, "Init_Win_bytes_backward"), 2000.0);
        assert_eq!(feat(&f, "act_data_pkt_fwd"), 1.0);
        assert_eq!(feat(&f, "min_seg_size_forward"), 20.0);
    }

    #[test]
    fn one_way_flow_reports_no_backward_window() {
        let mut f = Flow::new(&pkt([1, 1, 1, 1], [2, 2, 2, 2], 4000, 22, 0x02, 512, 0, 0));
        f.update(&pkt([1, 1, 1, 1], [2, 2, 2, 2], 4000, 22, 0x02, 512, 0, 0));
        assert_eq!(feat(&f, "Init_Win_bytes_backward"), -1.0);
        assert_eq!(feat(&f, "Flow Packets/s"), 0.0); // zero duration must not divide by zero
        assert_eq!(feat(&f, "Total Backward Packets"), 0.0);
    }

    #[test]
    fn flow_table_refuses_new_flows_when_full_but_keeps_existing_ones() {
        let mut t = Tracker::new(2);
        assert!(t.packet(&pkt([10, 0, 0, 1], [10, 0, 0, 9], 1001, 80, 0x02, 0, 0, 1)).is_none());
        assert!(t.packet(&pkt([10, 0, 0, 2], [10, 0, 0, 9], 1002, 80, 0x02, 0, 0, 2)).is_none());
        assert!(t.packet(&pkt([10, 0, 0, 3], [10, 0, 0, 9], 1003, 80, 0x02, 0, 0, 3)).is_none());
        assert_eq!((t.flows.len(), t.refused), (2, 1));
        // a reset on a tracked flow still finishes it and frees a slot
        let done = t.packet(&pkt([10, 0, 0, 9], [10, 0, 0, 1], 80, 1001, 0x04, 0, 0, 4));
        assert!(done.is_some());
        assert_eq!(t.flows.len(), 1);
        assert!(t.packet(&pkt([10, 0, 0, 3], [10, 0, 0, 9], 1003, 80, 0x02, 0, 0, 5)).is_none());
        assert_eq!((t.flows.len(), t.refused), (2, 1));
    }

    #[test]
    fn idle_flows_expire_and_late_packets_of_closed_flows_are_ignored() {
        let mut t = Tracker::new(10);
        t.packet(&pkt([10, 0, 0, 1], [10, 0, 0, 9], 1001, 80, 0x02, 0, 0, 1_000_000));
        assert_eq!(t.expire(3_000_000, 5_000_000).len(), 0);
        assert_eq!(t.expire(7_000_000, 5_000_000).len(), 1);
        assert!(t.packet(&pkt([10, 0, 0, 2], [10, 0, 0, 9], 2002, 80, 0x04, 0, 0, 1)).is_some());
        assert!(t.packet(&pkt([10, 0, 0, 2], [10, 0, 0, 9], 2002, 80, 0x10, 0, 0, 2)).is_none());
        assert!(t.flows.is_empty());
    }

    #[test]
    fn classifier_queue_drops_when_full_instead_of_growing() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<pb::FlowFeatures>(1);
        assert!(enqueue(&tx, pb::FlowFeatures::default()));
        assert!(!enqueue(&tx, pb::FlowFeatures::default()));
    }

    #[test]
    fn local_requests_need_no_token() {
        assert!(authorized(true, None, None, None, "tok"));                 // curl on this machine
        assert!(authorized(true, Some("127.0.0.1"), None, None, "tok"));    // browser on this machine via nginx
        assert!(authorized(true, None, None, None, ""));                    // works even with no token configured
    }

    #[test]
    fn remote_requests_need_the_token() {
        assert!(!authorized(true, Some("192.168.1.20"), None, None, "tok")); // phone via nginx: no bypass any more
        assert!(!authorized(false, None, None, None, "tok"));
        assert!(!authorized(false, None, Some("wrong"), None, "tok"));
        assert!(authorized(false, None, Some("tok"), None, "tok"));
        assert!(authorized(true, Some("192.168.1.20"), None, Some("limit=5&token=tok"), "tok")); // EventSource / download link
        assert!(!authorized(true, Some("192.168.1.20"), None, Some("token=tok2"), "tok"));
        assert!(!authorized(false, None, Some(""), None, ""));               // no token configured: remote access stays closed
        assert!(!authorized(true, Some("not-an-ip"), None, None, "tok"));
    }

    #[test]
    fn retention_deletes_only_old_rows() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch(SCHEMA).unwrap();
        db.execute_batch(
            "ALTER TABLE alerts ADD COLUMN explanation TEXT;
             INSERT INTO alerts (ts_utc, src_ip, label, flow_count, avg_confidence)
               VALUES (strftime('%Y-%m-%dT%H:%M:%SZ','now','-40 days'), '10.0.0.1', 'PortScan', 10, 0.9),
                      (strftime('%Y-%m-%dT%H:%M:%SZ','now','-29 days'), '10.0.0.2', 'PortScan', 10, 0.9),
                      (strftime('%Y-%m-%dT%H:%M:%SZ','now'), '10.0.0.3', 'DDoS', 3, 0.8);
             INSERT INTO devices (ip, first_seen, last_seen, flow_count)
               VALUES ('10.0.0.1', '2020-01-01T00:00:00Z', strftime('%Y-%m-%dT%H:%M:%SZ','now','-31 days'), 1),
                      ('10.0.0.3', '2020-01-01T00:00:00Z', strftime('%Y-%m-%dT%H:%M:%SZ','now'), 5);",
        )
        .unwrap();
        assert_eq!(purge_in(&db, 30), (1, 1));
        let left: i64 = db.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0)).unwrap();
        assert_eq!(left, 2);
        assert_eq!(purge_in(&db, 30), (0, 0));
    }

    #[test]
    fn token_comparison() {
        assert!(ct_eq("secret", "secret"));
        assert!(!ct_eq("secret", "secreT"));
        assert!(!ct_eq("secret", "secret2"));
        assert!(!ct_eq("", "secret"));
    }
}

#[cfg(test)]
mod rare_class_tests {
    use super::rare_class_blocked;

    #[test]
    fn weak_rare_class_is_blocked() {
        assert!(rare_class_blocked("Heartbleed", 0.50, 0.8));
        assert!(rare_class_blocked("Infiltration", 0.79, 0.8));
    }

    #[test]
    fn strong_rare_class_passes() {
        assert!(!rare_class_blocked("Heartbleed", 0.80, 0.8));
        assert!(!rare_class_blocked("Infiltration", 0.99, 0.8));
    }

    #[test]
    fn other_classes_are_never_blocked() {
        assert!(!rare_class_blocked("PortScan", 0.30, 0.8));
        assert!(!rare_class_blocked("DoS Hulk", 0.10, 0.8));
        assert!(!rare_class_blocked("Anomaly (unknown)", 0.50, 0.8));
    }
}

#[cfg(test)]
mod notify_tests {
    use super::{parse_min_severity, severity_name, severity_rank};

    #[test]
    fn ranks_match_dashboard_rules() {
        assert_eq!(severity_rank("Heartbleed", 0.9), 3);
        assert_eq!(severity_rank("DoS Hulk", 0.9), 2);
        assert_eq!(severity_rank("PortScan", 0.9), 1);
        assert_eq!(severity_rank("FTP-Patator", 0.9), 1);
        assert_eq!(severity_rank("SomethingNew", 0.9), 1);
    }

    #[test]
    fn weak_anomaly_is_low_strong_is_medium() {
        assert_eq!(severity_rank("Anomaly (unknown)", 0.5), 0);
        assert_eq!(severity_rank("Anomaly (unknown)", 0.6), 1);
    }

    #[test]
    fn min_severity_parsing() {
        assert_eq!(parse_min_severity("high"), 2);
        assert_eq!(parse_min_severity(" HIGH "), 2);
        assert_eq!(parse_min_severity("critical"), 3);
        assert_eq!(parse_min_severity("low"), 0);
        assert_eq!(parse_min_severity(""), 1);
        assert_eq!(parse_min_severity("garbage"), 1);
    }

    #[test]
    fn names() {
        assert_eq!(severity_name(0), "low");
        assert_eq!(severity_name(3), "critical");
    }
}
