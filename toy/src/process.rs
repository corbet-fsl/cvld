use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub type Result<T> = std::result::Result<T, String>;
#[derive(Default, Serialize)]
pub struct Metrics {
    pub actions: BTreeMap<String, Vec<Sample>>,
}
#[derive(Serialize)]
pub struct Sample {
    pub milliseconds: f64,
    pub rows_read: u64,
    pub rows_returned: u64,
    pub success: bool,
}
impl Metrics {
    pub fn report(&self) -> Value {
        let mut reports = BTreeMap::new();
        for (action, samples) in &self.actions {
            let mut times: Vec<f64> = samples.iter().map(|s| s.milliseconds).collect();
            times.sort_by(f64::total_cmp);
            let percentile = |p: usize| times[(times.len() * p).div_ceil(100) - 1];
            let read: u64 = samples.iter().map(|s| s.rows_read).sum();
            let returned: u64 = samples.iter().map(|s| s.rows_returned).sum();
            let excess = samples
                .iter()
                .filter(|s| s.rows_read > s.rows_returned)
                .count();
            reports.insert(
                action,
                serde_json::json!({
                    "count":samples.len(), "errors":samples.iter().filter(|s|!s.success).count(),
                    "p50_ms":percentile(50), "p95_ms":percentile(95), "p99_ms":percentile(99),
                    "rows_read":read, "rows_returned":returned, "excess_read_calls":excess,
                    "max_rows_read":samples.iter().map(|s|s.rows_read).max(),
                    "flag":if excess > 0 {"READS_EXCEED_RETURNED"} else {"OK"}
                }),
            );
        }
        serde_json::to_value(reports).unwrap()
    }
}
#[derive(Clone)]
pub struct Cli {
    pub bin: PathBuf,
    pub base: String,
    pub host: String,
    pub dir: PathBuf,
    pub scope: String,
    pub meter: PathBuf,
    pub metrics: Arc<Mutex<Metrics>>,
    counters: Arc<Mutex<(u64, u64, u64, String)>>,
}
impl Cli {
    fn counts(&self) -> (u64, u64) {
        let mut state = self.counters.lock().unwrap();
        if let Ok(mut file) = fs::File::open(&self.meter) {
            file.seek(SeekFrom::Start(state.0)).expect("seek meter");
            let mut tail = String::new();
            let read = file.read_to_string(&mut tail).expect("read meter");
            state.0 += read as u64;
            state.3.push_str(&tail);
            // A sample may race one append; keep an incomplete final record.
            if let Some(end) = state.3.rfind('\n') {
                let complete = state.3[..=end].to_owned();
                state.3.drain(..=end);
                for line in complete.lines() {
                    let (read, returned) = line.split_once(' ').expect("meter record");
                    state.1 += read.parse::<u64>().expect("read count");
                    state.2 += returned.parse::<u64>().expect("returned count");
                }
            }
        }
        (state.1, state.2)
    }
    pub fn call(&self, token: Option<&str>, action: &str, body: Value) -> Result<Value> {
        let before = self.counts();
        let mut command = Command::new(&self.bin);
        command.args(["--url", &self.base, "--host", &self.host]);
        // Never expose session tokens in command arguments or in reports.
        let session = token.map(|token| {
            let path = self.dir.join("client.session");
            fs::write(&path, token).expect("write synthetic session");
            path
        });
        if let Some(path) = &session {
            command.arg("--session-file").arg(path);
        }
        command.args([action, "--request", &body.to_string()]);
        let start = Instant::now();
        let output = command
            .output()
            .map_err(|_| "cannot launch cvld client".to_owned())?;
        let milliseconds = start.elapsed().as_secs_f64() * 1000.0;
        if let Some(path) = session {
            let _ = fs::remove_file(path);
        }
        let after = self.counts();
        self.metrics
            .lock()
            .unwrap()
            .actions
            .entry(format!("{}.{action}", self.scope))
            .or_default()
            .push(Sample {
                milliseconds,
                rows_read: after.0 - before.0,
                rows_returned: after.1 - before.1,
                success: output.status.success(),
            });
        if !output.status.success() {
            // Only the fixed public CLI categories may reach the transcript.
            let message = String::from_utf8_lossy(&output.stderr);
            let category = message.trim();
            if [
                "invalid request",
                "authentication required",
                "action forbidden",
                "wrong host or service",
                "request throttled",
                "operation refused",
                "service unavailable",
            ]
            .contains(&category)
            {
                return Err(category.into());
            }
            return Err("client failed without a public error category".into());
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid CLI JSON".into())
    }
    pub fn host(&self, host: &str) -> Self {
        let mut client = self.clone();
        client.host = host.into();
        client
    }
}
pub struct Service {
    pub cli: Cli,
    child: Child,
    scope: String,
    faketime: PathBuf,
    pub dir: PathBuf,
    pub initial: Value,
}
impl Service {
    pub fn start(
        bin: &Path,
        dir: &Path,
        scope: &str,
        host: String,
        faketime: &Path,
        metrics: Arc<Mutex<Metrics>>,
    ) -> Result<Self> {
        let config: Value =
            serde_json::from_slice(&fs::read(dir.join("config.json")).map_err(|_| "read config")?)
                .map_err(|_| "decode config")?;
        let cli = Cli {
            bin: bin.to_owned(),
            base: format!("http://{}", config["listen"].as_str().ok_or("listen")?),
            host,
            scope: scope.into(),
            dir: dir.to_owned(),
            meter: dir.join("meter"),
            metrics,
            counters: Arc::new(Mutex::new((0, 0, 0, String::new()))),
        };
        let child = Self::spawn(&cli, scope, faketime)?;
        let mut service = Self {
            cli,
            child,
            scope: scope.into(),
            faketime: faketime.to_owned(),
            dir: dir.to_owned(),
            initial: Value::Null,
        };
        service.ready()?;
        Ok(service)
    }
    fn spawn(cli: &Cli, scope: &str, faketime: &Path) -> Result<Child> {
        let library = std::env::var("LIBFAKETIME_PATH")
            .unwrap_or_else(|_| "/usr/lib/x86_64-linux-gnu/faketime/libfaketimeMT.so.1".into());
        if !Path::new(&library).is_file() {
            return Err("set LIBFAKETIME_PATH to libfaketimeMT.so.1".into());
        }
        Command::new(&cli.bin)
            .args(["serve", scope, "--config"])
            .arg(cli.dir.join("config.json"))
            .env("LD_PRELOAD", library)
            .env("FAKETIME_TIMESTAMP_FILE", faketime)
            .env("FAKETIME_NO_CACHE", "1")
            .env("FAKETIME_DONT_FAKE_MONOTONIC", "1")
            .env("FAKETIME_DONT_FAKE_STAT", "1")
            .env("TZ", "UTC")
            .env("CVLD_TOY_METER", &cli.meter)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "cannot start cvld service".into())
    }
    fn ready(&mut self) -> Result<()> {
        let action = if self.scope == "global" {
            "global_public"
        } else {
            "trust_feed"
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.child.try_wait().map_err(|_| "poll service")?.is_some() {
                return Err(format!("{} service exited during startup", self.scope));
            }
            if let Ok(value) = self.cli.call(None, action, serde_json::json!({})) {
                self.initial = value;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err("service readiness deadline".into())
    }
    pub fn restart(&mut self) -> Result<()> {
        self.stop();
        self.child = Self::spawn(&self.cli, &self.scope, &self.faketime)?;
        self.ready()
    }
    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop();
    }
}
pub fn port() -> String {
    // The reservation is short-lived; a collision fails startup, never attaches to an existing process.
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}
pub fn clock(path: &Path, now: u64) {
    let date = chrono::DateTime::from_timestamp(now as i64, 0).unwrap();
    let tmp = path.with_extension("next");
    fs::write(&tmp, date.format("%Y-%m-%d %H:%M:%S").to_string()).unwrap();
    fs::rename(tmp, path).unwrap();
}
