//! Fixed read-only HTTP/TCP checks on locally opted-in Agent hosts.
use anyhow::{bail, Result};
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    id: String,
    kind: String,
    target: String,
    interval_seconds: u64,
    timeout_seconds: u64,
}
impl Probe {
    fn validate(&self) -> bool {
        if self.id.len() != 32
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !(60..=3600).contains(&self.interval_seconds)
            || !(1..=10).contains(&self.timeout_seconds)
            || self.target.len() > 2048
            || self.target.chars().any(char::is_control)
        {
            return false;
        }
        let raw = if self.kind == "tcp" {
            format!("tcp://{}", self.target)
        } else {
            self.target.clone()
        };
        let Ok(url) = url::Url::parse(&raw) else {
            return false;
        };
        url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && url.query().is_none()
            && match self.kind.as_str() {
                "http" => matches!(url.scheme(), "http" | "https"),
                "tcp" => {
                    url.scheme() == "tcp"
                        && url.port().is_some_and(|port| port > 0)
                        && url.path().is_empty()
                }
                _ => false,
            }
    }
}
pub fn parse(value: &Value) -> Result<Vec<Probe>> {
    let probes: Vec<Probe> = serde_json::from_value(value.clone())?;
    if value.to_string().len() > 32768 || probes.len() > 64 || probes.iter().any(|p| !p.validate())
    {
        bail!("Invalid fixed service probe configuration");
    }
    let mut ids = std::collections::HashSet::new();
    if probes.iter().any(|p| !ids.insert(&p.id)) {
        bail!("Duplicate service probe");
    }
    Ok(probes)
}
#[derive(Default)]
pub struct State {
    pub configuration: Vec<Probe>,
    pub revision: Option<String>,
    results: HashMap<String, (u64, Value)>,
}
impl State {
    pub fn report(&self) -> Value {
        json!({"revision":self.revision,"results":self.results.values().map(|(at,v)|{
            let mut v=v.clone();v["age_seconds"]=json!(if *at==u64::MAX || boot_millis()==u64::MAX {7201} else {boot_millis().saturating_sub(*at)/1000});v
        }).collect::<Vec<_>>()})
    }
    pub fn configure(&mut self, configuration: Vec<Probe>, revision: String) {
        self.results
            .retain(|id, _| configuration.iter().any(|p| &p.id == id));
        self.configuration = configuration;
        self.revision = Some(revision);
    }
}
pub fn start(state: Arc<Mutex<State>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("w-monitor-lite-probe/", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("Probe TLS client");
        let mut due: HashMap<String, Instant> = HashMap::new();
        loop {
            let (mut probes, revision) = {
                let current = state.lock();
                (current.configuration.clone(), current.revision.clone())
            };
            due.retain(|id, _| probes.iter().any(|p| &p.id == id));
            let now = Instant::now();
            probes.sort_by_key(|p| {
                due.get(&p.id)
                    .copied()
                    .unwrap_or(now - Duration::from_secs(3600))
            });
            // Bounded concurrency, no shell, custom headers, redirects, response bodies or retries.
            let mut jobs = tokio::task::JoinSet::new();
            for probe in probes {
                if due.get(&probe.id).is_some_and(|at| *at > Instant::now()) {
                    continue;
                }
                if jobs.len() >= 8 {
                    break;
                }
                due.insert(
                    probe.id.clone(),
                    Instant::now() + Duration::from_secs(probe.interval_seconds),
                );
                let client = client.clone();
                jobs.spawn(async move {
                    let started=Instant::now();
                    let result=tokio::time::timeout(Duration::from_secs(probe.timeout_seconds),async {
                        if probe.kind=="tcp" {
                            tokio::net::TcpStream::connect(&probe.target).await.map(|_|None).map_err(|_|())
                        } else {
                            client.get(&probe.target).send().await.map(|r|Some(r.status().as_u16())).map_err(|_|())
                        }
                    }).await;
                    let (ok,code,error)=match result {
                        Ok(Ok(code))=>(code.is_none_or(|n|(200..400).contains(&n)),code,Value::Null),
                        Ok(Err(()))=>(false,None,json!("connection_or_tls")),
                        Err(_)=>(false,None,json!("timeout")),
                    };
                    (probe.id.clone(),json!({"id":probe.id,"ok":ok,"status_code":code,"latency_ms":started.elapsed().as_millis().min(10000),"error":error}))
                });
            }
            while let Some(Ok((id, value))) = jobs.join_next().await {
                let mut current = state.lock();
                if current.revision == revision {
                    current.results.insert(id, (boot_millis(), value));
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

fn boot_millis() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return u64::MAX;
    }
    (value.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(value.tv_nsec as u64 / 1_000_000)
}
