//! Background thread that samples processes, Clash API connections and sing-box instances,
//! and records connections into the history db.

use crate::clash::{Conn, Tracker};
use crate::history::{self, AppHistory};
use crate::procs::{Proc, Scanner};
use crate::singbox::{self, Instance};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::time::Duration;

#[derive(Default, Clone)]
pub struct Snapshot {
    pub procs: Vec<Proc>,
    pub conns: Vec<Conn>,
    pub api_error: Option<String>,
    pub instances: Vec<Instance>,
    pub history: Vec<AppHistory>,
    pub db_error: Option<String>,
}

pub struct Monitor {
    /// Replaced whole each sample, so readers take a cheap Arc clone instead of copying it.
    pub snapshot: Arc<Mutex<Arc<Snapshot>>>,
    /// (address, secret) of the Clash API; updated when the config changes.
    pub api: Arc<Mutex<(String, String)>>,
    /// History older than this many seconds is deleted (0 = keep the whole session).
    pub retention: Arc<AtomicU64>,
}

impl Monitor {
    pub fn start(
        ctx: eframe::egui::Context,
        api: (String, String),
        db: PathBuf,
        retention: u64,
        interval: Duration,
        on_sample: impl Fn(&[Instance]) + Send + 'static,
    ) -> Self {
        let snapshot = Arc::new(Mutex::new(Arc::new(Snapshot::default())));
        let api = Arc::new(Mutex::new(api));
        let retention = Arc::new(AtomicU64::new(retention));
        let (snap, api2, keep) = (snapshot.clone(), api.clone(), retention.clone());
        std::thread::spawn(move || {
            let mut scanner = Scanner::new();
            let mut tracker = Tracker::default();
            let mut con = history::open_fresh(&db);
            let mut pruned = Instant::now();
            loop {
                let mut procs = scanner.scan();
                let instances = singbox::in_procs(&procs);
                let (addr, secret) = api2.lock().unwrap().clone();
                let (conns, api_error) = if addr.is_empty() {
                    (vec![], Some("clash_api is not enabled in the config".into()))
                } else if instances.is_empty() {
                    (vec![], Some("sing-box is not running".into()))
                } else {
                    match tracker.poll(&addr, &secret) {
                        Ok(c) => (c, None),
                        Err(e) => (vec![], Some(format!("Clash API at {addr}: {e}"))),
                    }
                };
                if let Ok(con) = &con {
                    let secs = keep.load(Ordering::Relaxed);
                    if secs > 0 && pruned.elapsed() > Duration::from_secs(10) {
                        let _ = history::prune(con, secs);
                        pruned = Instant::now();
                    }
                }
                let (history, db_error) = match &mut con {
                    Ok(con) => match history::record(con, &conns).and_then(|_| history::apps(con)) {
                        Ok(h) => (h, None),
                        Err(e) => (vec![], Some(format!("history db: {e}"))),
                    },
                    Err(e) => (vec![], Some(format!("history db {}: {e}", db.display()))),
                };
                // CPU / memory only for the apps the list shows
                let shown: HashSet<&str> =
                    history.iter().map(|h| h.app.as_str()).chain(conns.iter().map(|c| c.app.as_str())).collect();
                scanner.usage(&mut procs, |p| shown.contains(p.exe.as_str()));
                on_sample(&instances);
                let s = Snapshot { procs, conns, api_error, instances, history, db_error };
                *snap.lock().unwrap() = Arc::new(s);
                ctx.request_repaint();
                std::thread::sleep(interval);
            }
        });
        Self { snapshot, api, retention }
    }
}
