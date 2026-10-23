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
/// The service's own refusal text for a start that crossed a second boundary (cvld `Error::Reconcile`).
const RECONCILE_START: &str = "outcome unknown; reconcile current state before another operation";
const RECONCILE_RESTARTS: u32 = 5;
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
        // The platform launcher reads the composition file beside the global one.
        let file = if scope == "platform" {
            "platform.json"
        } else {
            "config.json"
        };
        Command::new(&cli.bin)
            .args(["serve", scope, "--config"])
            .arg(cli.dir.join(file))
            .env("LD_PRELOAD", library)
            // A harness may run the whole stack under an offset clock (a continued saved state); the
            // services take their time from the clock file the stack keeps, nothing else.
            .env_remove("FAKETIME")
            .env("FAKETIME_TIMESTAMP_FILE", faketime)
            .env("FAKETIME_NO_CACHE", "1")
            .env("FAKETIME_DONT_FAKE_MONOTONIC", "1")
            .env("FAKETIME_DONT_FAKE_STAT", "1")
            .env("TZ", "UTC")
            .env("CVLD_TOY_METER", &cli.meter)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            // Service diagnostics are fixed messages. They go to a file beside the configuration so a
            // startup that exits can be told apart by its exact category; CVLD_TOY_SERVICE_STDERR also
            // shows them on this process's stderr when the service has exited.
            .stderr(match fs::File::create(cli.dir.join("service.stderr")) {
                Ok(file) => Stdio::from(file),
                Err(_) => Stdio::null(),
            })
            .spawn()
            .map_err(|_| "cannot start cvld service".into())
    }
    fn ready(&mut self) -> Result<()> {
        let action = if self.scope == "global" || self.scope == "platform" {
            "global_public"
        } else {
            "trust_feed"
        };
        // Readiness deadline in seconds; the default stays 30. A loaded host may raise it.
        let seconds = std::env::var("CVLD_TOY_READY_SECONDS")
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(30);
        let deadline = Instant::now() + Duration::from_secs(seconds);
        let mut restarts = 0;
        while Instant::now() < deadline {
            if self.child.try_wait().map_err(|_| "poll service")?.is_some() {
                let diagnostic = fs::read_to_string(self.cli.dir.join("service.stderr")).unwrap_or_default();
                if std::env::var_os("CVLD_TOY_SERVICE_STDERR").is_some() {
                    eprint!("{diagnostic}");
                }
                // The service refuses a start whose clock reading moved to another second while it
                // verified its signed documents ("a new second requires retry"); on a loaded host that
                // happens. Only this exact, labelled category is started again; any other exit fails.
                if diagnostic.trim() == RECONCILE_START && restarts < RECONCILE_RESTARTS {
                    restarts += 1;
                    eprintln!(
                        "INFRA: {} service start hit the second-boundary reconcile refusal; start {} of {}",
                        self.scope,
                        restarts + 1,
                        RECONCILE_RESTARTS + 1
                    );
                    self.child = Self::spawn(&self.cli, &self.scope, &self.faketime)?;
                    continue;
                }
                return Err(format!(
                    "{} service exited during startup ({})",
                    self.scope,
                    self.child
                        .try_wait()
                        .ok()
                        .flatten()
                        .map_or("status unknown".to_owned(), |status| status.to_string())
                ));
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
/// Write a libfaketime offset (`+0`, `-120s`, ...) as the services' clock: with
/// `FAKETIME_NO_CACHE` they follow the wall clock plus that offset, to the nanosecond. An empty
/// or absolute (`@...`, a date) value is refused: only a moving clock keeps the services at
/// the devices' time.
pub fn clock_offset(path: &Path, offset: &str) {
    let offset = offset.trim();
    let offset = if offset.is_empty() { "+0" } else { offset };
    assert!(
        offset.starts_with(['+', '-']) && !offset.contains(' '),
        "FAKETIME must be a plain offset for the toy stack, not {offset:?}"
    );
    let tmp = path.with_extension("next");
    fs::write(&tmp, offset).unwrap();
    fs::rename(tmp, path).unwrap();
}
