use pcap::{Capture, Device};
use std::collections::HashMap;
use std::env;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[allow(dead_code)]
mod pb {
    tonic::include_proto!("netspectre.v1");
}
#[allow(unused_imports)]
use pb::inference_client::InferenceClient;

struct Pkt {
    src: Ipv4Addr,
    dst: Ipv4Addr,
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
    if data.len() < 14 || u16::from_be_bytes([data[12], data[13]]) != 0x0800 {
        return None;
    }
    let ip = &data[14..];
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as u32;
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    if ip.len() < ihl {
        return None;
    }
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
    let _ = total_len;
    // like a real wire: Ethernet frames are at least 60 bytes, padding counts as payload (as in CICIDS2017)
    let frame = (data.len() as u32).max(60);
    let payload = frame.saturating_sub(14 + ihl as u32 + l4hdr);
    Some(Pkt { src, dst, sport, dport, proto, payload, hdr_len: l4hdr, flags, win, l4hdr, ts_us })
}

type Key = ((Ipv4Addr, u16), (Ipv4Addr, u16), u8);

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
    src: Option<(Ipv4Addr, u16)>, // initiator = forward direction
    dst: Option<(Ipv4Addr, u16)>,
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

static TX: std::sync::OnceLock<tokio::sync::mpsc::UnboundedSender<pb::FlowFeatures>> =
    std::sync::OnceLock::new();

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
        let _ = tx.send(req);
    }
}

fn start_worker(addr: String) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<pb::FlowFeatures>();
    TX.set(tx).ok();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        rt.block_on(async {
            tokio::spawn(run_api());
            run_client(addr, rx).await
        });
    });
}

fn open_db() -> rusqlite::Connection {
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    if let Some(dir) = std::path::Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let db = rusqlite::Connection::open(&path).expect("open db");
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_utc TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
            src_ip TEXT NOT NULL,
            label TEXT NOT NULL,
            flow_count INTEGER NOT NULL,
            avg_confidence REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'new'
        );
        CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts_utc);",
    )
    .expect("create schema");
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
    eprintln!("alert database: {path}");
    db
}

#[derive(serde::Serialize)]
struct Health {
    status: &'static str,
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
}

async fn api_health() -> axum::Json<Health> {
    axum::Json(Health { status: "ok" })
}

async fn api_alerts(
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Result<axum::Json<Vec<AlertRow>>, axum::http::StatusCode> {
    use axum::http::StatusCode;
    let limit: i64 = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50).clamp(1, 500);
    let path = env::var("NS_DB").unwrap_or_else(|_| "../data/netspectre.db".to_string());
    let db = rusqlite::Connection::open(path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut stmt = db
        .prepare("SELECT id, ts_utc, src_ip, label, flow_count, avg_confidence, status FROM alerts ORDER BY id DESC LIMIT ?1")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let rows = stmt
        .query_map([limit], |r| {
            Ok(AlertRow {
                id: r.get(0)?,
                ts_utc: r.get(1)?,
                src_ip: r.get(2)?,
                label: r.get(3)?,
                flow_count: r.get(4)?,
                avg_confidence: r.get(5)?,
                status: r.get(6)?,
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

async fn run_api() {
    let _ = open_db(); // make sure the schema exists
    let app = axum::Router::new()
        .route("/api/health", axum::routing::get(api_health))
        .route("/api/alerts", axum::routing::get(api_alerts))
        .route("/api/alerts/status", axum::routing::post(api_set_status))
        .layer(tower_http::cors::CorsLayer::permissive());
    let addr = env::var("NS_API_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("bind api address");
    eprintln!("REST API on http://{addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn run_client(addr: String, mut rx: tokio::sync::mpsc::UnboundedReceiver<pb::FlowFeatures>) {
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
    let mut hist: HashMap<(String, String), Vec<(Instant, u32, f32)>> = HashMap::new();
    let mut last_alert: HashMap<(String, String), Instant> = HashMap::new();

    while let Some(req) = rx.recv().await {
        let (src, dport) = (req.src_ip.clone(), req.dst_port);
        let resp = match client.classify(req).await {
            Ok(r) => r.into_inner(),
            Err(e) => {
                eprintln!("classify error: {e}");
                continue;
            }
        };
        if resp.label == "BENIGN" {
            if verbose {
                println!("ok    {src} -> port {dport}  BENIGN ({:.2})", resp.confidence);
            }
            continue;
        }
        let key = (src.clone(), resp.label.clone());
        let now = Instant::now();
        let h = hist.entry(key.clone()).or_default();
        h.retain(|x| now.duration_since(x.0) <= Duration::from_secs(10));
        h.push((now, dport, resp.confidence));
        let (count, unit, need) = if resp.label == "PortScan" {
            (h.iter().map(|x| x.1).collect::<HashSet<_>>().len(), "ports", 10)
        } else {
            (h.len(), "flows", 3)
        };
        let quiet = last_alert.get(&key).map_or(true, |t| now.duration_since(*t) > Duration::from_secs(30));
        if count >= need && quiet {
            last_alert.insert(key, now);
            let avg = h.iter().map(|x| x.2).sum::<f32>() / h.len() as f32;
            println!("ALERT {src} -> {}: {count} {unit} in 10s (avg confidence {avg:.2})", resp.label);
            if let Err(e) = db.execute(
                "INSERT INTO alerts (src_ip, label, flow_count, avg_confidence) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![src, resp.label, count as i64, avg as f64],
            ) {
                eprintln!("db error: {e}");
            }
        }
    }
}

fn main() {
    let iface = env::args().nth(1).unwrap_or_else(|| "eth0".to_string());
    let filter = env::args().nth(2).filter(|f| f != "-");
    let idle_us: u64 = env::args().nth(3).and_then(|s| s.parse::<u64>().ok()).unwrap_or(5) * 1_000_000;
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
    let mut flows: HashMap<Key, Flow> = HashMap::new();
    let mut last_sweep = Instant::now();
    let mut closed: HashMap<Key, Instant> = HashMap::new();
    loop {
        match cap.next_packet() {
            Ok(pk) => {
                let ts = pk.header.ts.tv_sec as u64 * 1_000_000 + pk.header.ts.tv_usec as u64;
                if let Some(p) = parse(pk.data, ts) {
                    let k = key_of(&p);
                    if closed.get(&k).map_or(false, |t| t.elapsed() < Duration::from_secs(10)) {
                        continue;
                    }
                    let done = {
                        let f = flows.entry(k).or_insert_with(|| Flow::new(&p));
                        f.update(&p);
                        f.fin >= 2 || f.rst > 0
                    };
                    if done {
                        if let Some(f) = flows.remove(&k) {
                            emit(&f);
                            closed.insert(k, Instant::now());
                        }
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
            closed.retain(|_, t| t.elapsed() < Duration::from_secs(10));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
            let expired: Vec<Key> = flows
                .iter()
                .filter(|(_, f)| now.saturating_sub(f.last_us) > idle_us)
                .map(|(k, _)| *k)
                .collect();
            for k in expired {
                if let Some(f) = flows.remove(&k) {
                    emit(&f);
                }
            }
        }
    }
}
