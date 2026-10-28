//! The egui front end: process list, per-app details, routing rules and sing-box control.

use crate::clash::{self, Conn};
use crate::config::{Config, APP_KEY, DOMAIN_KEY};
use crate::history::{self, Flow};
use crate::monitor::{Monitor, Snapshot};
use crate::singbox::{self, Instance};
use crate::Paths;
use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

const FILTER_ID: &str = "filter";
const SHORTCUTS: &str = "Space / Enter   route or unroute the selected app
↑ ↓  (j k)       move selection
Home / End       first / last app
Esc              close details / clear filter
/  or  Ctrl+F    filter
Alt+1 2 3        switch tabs
Ctrl+R           reset sing-box
Ctrl + / − / 0   zoom
Double-click     route or unroute
Right-click      more actions / details";

const GREEN: Color32 = Color32::from_rgb(80, 200, 120);
const YELLOW: Color32 = Color32::from_rgb(230, 190, 70);
const RED: Color32 = Color32::from_rgb(235, 90, 90);

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    singbox: String,
    /// Restart sing-box with our config at launch unless our supervised instance is already up.
    reset_on_start: bool,
    /// Reset also stops sing-box instances running other configs (they would fight over TUN routes).
    stop_others: bool,
    /// Only list apps active within this many seconds (0 = all history).
    window_secs: u64,
    /// UI scale (Ctrl +/−/0).
    zoom: f32,
}

impl Default for Settings {
    fn default() -> Self {
        Self { singbox: singbox::default_binary(), reset_on_start: true, stop_others: true, window_secs: 300, zoom: 1.25 }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Apps,
    Routing,
    SingBox,
}

/// Activity windows offered for the app list, in seconds (0 = everything in history).
const WINDOWS: [(u64, &str); 6] =
    [(60, "1 min"), (300, "5 min"), (900, "15 min"), (3600, "1 hour"), (86400, "24 hours"), (0, "since start")];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SortKey {
    Routed,
    Name,
    Live,
    Speed,
    Hits,
    Domains,
    Traffic,
    LastSeen,
    Cpu,
    Memory,
}

impl SortKey {
    const ALL: [SortKey; 10] = [
        SortKey::LastSeen,
        SortKey::Speed,
        SortKey::Live,
        SortKey::Hits,
        SortKey::Domains,
        SortKey::Traffic,
        SortKey::Cpu,
        SortKey::Memory,
        SortKey::Name,
        SortKey::Routed,
    ];

    fn label(self) -> &'static str {
        match self {
            SortKey::Routed => "VPN",
            SortKey::Name => "Name",
            SortKey::Live => "Open connections",
            SortKey::Speed => "Speed",
            SortKey::Hits => "Total connections",
            SortKey::Domains => "Domains",
            SortKey::Traffic => "Traffic",
            SortKey::LastSeen => "Last activity",
            SortKey::Cpu => "CPU",
            SortKey::Memory => "Memory",
        }
    }

    /// Names read best ascending, numbers and recency descending.
    fn default_desc(self) -> bool {
        self != SortKey::Name
    }
}

/// One app = one executable path, i.e. one possible sing-box `process_path` entry.
struct Row {
    /// The process path sing-box reported ("" when it couldn't tell).
    exe: String,
    name: String,
    pids: Vec<u32>,
    user: String,
    cpu: f32,
    rss: u64,
    live: usize,
    rate_up: f64,
    rate_down: f64,
    hits: u64,
    domains: usize,
    traffic: u64,
    last_seen: f64,
    outbounds: BTreeSet<String>,
    routed: bool,
}

enum Action {
    Select(String),
    Details(String),
    Route(String),
    Unroute(String),
    Forget(String),
}

pub struct App {
    paths: Paths,
    cfg: Config,
    settings: Settings,
    monitor: Monitor,
    snap: Snapshot,
    tab: Tab,
    sort: SortKey,
    desc: bool,
    filter: String,
    mine_only: bool,
    selected: Option<String>,
    /// Whether the details panel is shown for `selected`; only opened from the context menu.
    details_open: bool,
    /// Read connection for the details panel (the monitor thread owns the writer).
    db: Option<rusqlite::Connection>,
    flows: (String, Option<Instant>, Vec<Flow>),
    new_app: String,
    new_domain: String,
    busy: Option<String>,
    tx: Sender<Result<String, String>>,
    rx: Receiver<Result<String, String>>,
    messages: Vec<(String, bool)>,
    log_tail: String,
    log_read: Option<Instant>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext, paths: Paths) -> Self {
        install_fallback_fonts(&cc.egui_ctx);
        let (tx, rx) = channel();
        let mut messages = vec![];
        let mut cfg = Config::load(&paths.config).unwrap_or_else(|e| {
            messages.push((format!("{e}; starting from an empty config"), true));
            Config::new(&paths.config, serde_json::json!({}))
        });
        let migrated = cfg.setup();
        if migrated {
            match cfg.save() {
                Ok(()) => messages.push(("set up clash_api, process lookup and the proxy2vpn rule-set in config".into(), false)),
                Err(e) => messages.push((e, true)),
            }
        }
        if migrated || !cfg.rules_path.exists() {
            if let Err(e) = cfg.save_rules() {
                messages.push((e, true));
            }
        }
        let settings: Settings =
            fs::read_to_string(&paths.settings).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let db = paths.state.join("history.db");
        let monitor = Monitor::start(cc.egui_ctx.clone(), cfg.api(), db, settings.window_secs, Duration::from_secs(1));
        let mut app = Self {
            paths,
            cfg,
            settings,
            monitor,
            snap: Snapshot::default(),
            tab: Tab::Apps,
            sort: SortKey::LastSeen,
            desc: true,
            filter: String::new(),
            mine_only: false,
            selected: None,
            details_open: false,
            db: None,
            flows: (String::new(), None, vec![]),
            new_app: String::new(),
            new_domain: String::new(),
            busy: None,
            tx,
            rx,
            messages,
            log_tail: String::new(),
            log_read: None,
        };
        cc.egui_ctx.set_zoom_factor(app.settings.zoom);
        app.save_settings();
        let instances = singbox::find_all();
        if app.settings.reset_on_start && !app.ours_running(&instances) {
            app.reset();
        } else if migrated && instances.iter().any(|i| app.uses_our_config(i)) {
            // the running sing-box has the old config, without the rule-set
            app.snap.instances = instances;
            app.apply();
        }
        app
    }

    fn save_settings(&mut self) {
        let text = serde_json::to_string_pretty(&self.settings).unwrap();
        let res = fs::create_dir_all(self.paths.settings.parent().unwrap())
            .and_then(|_| fs::write(&self.paths.settings, text));
        if let Err(e) = res {
            self.msg(Err(format!("saving settings: {e}")));
        }
    }

    fn msg(&mut self, m: Result<String, String>) {
        let (text, err) = match m {
            Ok(t) => (t, false),
            Err(t) => (t, true),
        };
        self.messages.push((text, err));
        if self.messages.len() > 200 {
            self.messages.remove(0);
        }
    }

    fn uses_our_config(&self, inst: &Instance) -> bool {
        inst.config.as_deref().is_some_and(|c| same_file(c, &self.paths.config))
    }

    /// Our supervised sing-box is up and running this app's config.
    fn ours_running(&self, instances: &[Instance]) -> bool {
        singbox::managed_pid(&self.paths.state)
            .is_some_and(|pid| instances.iter().any(|i| i.pid == pid && self.uses_our_config(i)))
    }

    fn spawn(&mut self, label: &str, f: impl FnOnce() -> Result<String, String> + Send + 'static) {
        if self.busy.is_some() {
            self.msg(Err("another sing-box operation is still running".into()));
            return;
        }
        self.busy = Some(label.into());
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
    }

    fn reset(&mut self) {
        let instances = singbox::find_all();
        let kill: Vec<u32> = instances
            .iter()
            .filter(|i| self.settings.stop_others || self.uses_our_config(i))
            .map(|i| i.pid)
            .collect();
        let (bin, cfg, state) = (self.settings.singbox.clone(), self.paths.config.clone(), self.paths.state.clone());
        self.spawn("Resetting sing-box (authorise in the prompt)…", move || {
            singbox::reset(&bin, &cfg, &state, &kill)?;
            Ok(format!("sing-box restarted with {}", cfg.display()))
        });
    }

    fn stop(&mut self) {
        let pids: Vec<u32> = self.snap.instances.iter().map(|i| i.pid).collect();
        let state = self.paths.state.clone();
        self.spawn("Stopping sing-box…", move || singbox::stop(&state, &pids).map(|_| "sing-box stopped".into()));
    }

    fn check(&mut self) {
        let (bin, cfg) = (self.settings.singbox.clone(), self.paths.config.clone());
        self.spawn("Checking config…", move || singbox::check(&bin, &cfg).map(|_| "config OK".into()));
    }

    /// Validate the saved config and get sing-box running with it.
    fn apply(&mut self) {
        if self.ours_running(&self.snap.instances) {
            let (bin, cfg, state) = (self.settings.singbox.clone(), self.paths.config.clone(), self.paths.state.clone());
            self.spawn("Restarting sing-box…", move || {
                singbox::check(&bin, &cfg)?;
                singbox::reload(&state)
            });
        } else {
            // not ours (or not running): take it over once; later changes won't need a password
            self.reset();
        }
    }

    fn edit_rule(&mut self, key: &str, value: &str, add: bool) {
        let changed = if add {
            match self.cfg.add(key, value) {
                Ok(c) => c,
                Err(e) => return self.msg(Err(e)),
            }
        } else {
            self.cfg.remove(key, value)
        };
        if !changed {
            return self.msg(Ok(format!("{value}: nothing to change")));
        }
        if let Err(e) = self.cfg.save_rules() {
            return self.msg(Err(e));
        }
        if !self.snap.instances.iter().any(|i| self.uses_our_config(i)) {
            self.msg(Ok(format!("{} {key}: {value}", if add { "+" } else { "−" })));
            return self.apply();
        }
        // sing-box picks up the rule-set by itself; only connections opened from now on follow
        // it, so close the affected ones and let the app reconnect
        let ids: Vec<String> = self
            .snap
            .conns
            .iter()
            .filter(|c| match key {
                APP_KEY => c.app == value,
                _ => c.host == value || c.host.ends_with(&format!(".{value}")),
            })
            .map(|c| c.id.clone())
            .collect();
        self.msg(Ok(format!(
            "{} {key}: {value} (applied live, closing {} connection{})",
            if add { "+" } else { "−" },
            ids.len(),
            if ids.len() == 1 { "" } else { "s" }
        )));
        let (addr, secret) = self.cfg.api();
        std::thread::spawn(move || {
            // give sing-box's file watcher a moment to reload the rule-set
            std::thread::sleep(Duration::from_millis(300));
            for id in ids {
                let _ = clash::close(&addr, &secret, &id);
            }
        });
    }

    fn reload_config_from_disk(&mut self) {
        match Config::load(&self.paths.config) {
            Ok(c) => {
                self.cfg = c;
                *self.monitor.api.lock().unwrap() = self.cfg.api();
                self.msg(Ok("config re-read from disk".into()));
            }
            Err(e) => self.msg(Err(e)),
        }
    }

    fn forget(&mut self, exe: &str) {
        if self.db.is_none() {
            self.db = history::open(&self.paths.state.join("history.db")).ok();
        }
        let res = self.db.as_ref().ok_or("history db unavailable".to_string()).and_then(|db| {
            history::forget(db, exe).map_err(|e| e.to_string())
        });
        self.flows.1 = None;
        self.msg(res.map(|_| format!("forgot history of {exe}")));
    }

    // ------------------------------------------------------------ rows

    fn rows(&self) -> Vec<Row> {
        let routed: BTreeSet<String> = self.cfg.items(APP_KEY).into_iter().collect();
        let me = std::env::var("USER").unwrap_or_default();
        let mut rows: Vec<Row> = Vec::new();
        let mut index: HashMap<String, usize> = HashMap::new();
        let mut row = |exe: &str, rows: &mut Vec<Row>| -> usize {
            *index.entry(exe.to_owned()).or_insert_with(|| {
                rows.push(Row {
                    exe: exe.to_owned(),
                    name: if exe.is_empty() { "(unknown process)".into() } else { file_name(exe) },
                    pids: vec![],
                    user: String::new(),
                    cpu: 0.0,
                    rss: 0,
                    live: 0,
                    rate_up: 0.0,
                    rate_down: 0.0,
                    hits: 0,
                    domains: 0,
                    traffic: 0,
                    last_seen: 0.0,
                    outbounds: BTreeSet::new(),
                    routed: routed.contains(exe),
                });
                rows.len() - 1
            })
        };
        // only apps sing-box has seen connecting: the history db, plus whatever is open right now
        for h in &self.snap.history {
            let i = row(&h.app, &mut rows);
            let r = &mut rows[i];
            r.hits = h.hits;
            r.domains = h.domains;
            r.traffic = h.up + h.down;
            r.last_seen = h.last_seen;
            r.outbounds.extend(h.outbounds.split(',').filter(|o| !o.is_empty()).map(str::to_owned));
        }
        let now = history::now();
        for c in self.snap.conns.iter().filter(|c| c.port != 53) {
            let i = row(&c.app, &mut rows);
            let r = &mut rows[i];
            r.live += 1;
            r.rate_up += c.rate_up;
            r.rate_down += c.rate_down;
            r.last_seen = now;
            r.outbounds.insert(c.outbound.clone());
            if r.user.is_empty() {
                r.user = c.user.clone();
            }
        }
        // attach the running processes with that executable path
        for p in &self.snap.procs {
            if let Some(&i) = index.get(&p.exe).filter(|_| !p.exe.is_empty()) {
                let r = &mut rows[i];
                r.pids.push(p.pid);
                r.cpu += p.cpu;
                r.rss += p.rss;
                if r.user.is_empty() {
                    r.user = p.user.clone();
                }
            }
        }
        let window = self.settings.window_secs as f64;
        let f = self.filter.to_lowercase();
        rows.retain(|r| {
            (window == 0.0 || r.live > 0 || now - r.last_seen <= window)
                && (!self.mine_only || r.user == me)
                && (f.is_empty() || r.name.to_lowercase().contains(&f) || r.exe.to_lowercase().contains(&f))
        });
        let key = self.sort;
        rows.sort_by(|a, b| {
            use std::cmp::Ordering;
            let o = match key {
                SortKey::Routed => a.routed.cmp(&b.routed),
                SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                SortKey::Live => a.live.cmp(&b.live),
                SortKey::Speed => (a.rate_up + a.rate_down).total_cmp(&(b.rate_up + b.rate_down)),
                SortKey::Hits => a.hits.cmp(&b.hits),
                SortKey::Domains => a.domains.cmp(&b.domains),
                SortKey::Traffic => a.traffic.cmp(&b.traffic),
                // whole seconds, so apps active in the same tick don't flicker
                SortKey::LastSeen => (a.last_seen as u64).cmp(&(b.last_seen as u64)),
                SortKey::Cpu => a.cpu.partial_cmp(&b.cpu).unwrap_or(Ordering::Equal),
                SortKey::Memory => a.rss.cmp(&b.rss),
            };
            let o = if self.desc { o.reverse() } else { o };
            // stable tie-break so rows don't jump around between refreshes
            o.then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())).then_with(|| a.exe.cmp(&b.exe))
        });
        rows
    }

    // ------------------------------------------------------------ ui

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("proxy2vpn");
            ui.separator();
            ui.selectable_value(&mut self.tab, Tab::Apps, "Apps");
            let n = self.cfg.items(APP_KEY).len() + self.cfg.items(DOMAIN_KEY).len();
            ui.selectable_value(&mut self.tab, Tab::Routing, format!("VPN routes ({n})"));
            ui.selectable_value(&mut self.tab, Tab::SingBox, "sing-box");
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label("⌨").on_hover_text(SHORTCUTS);
                if ui.small_button("A+").on_hover_text("Bigger (Ctrl +)").clicked() {
                    ui.ctx().set_zoom_factor((ui.ctx().zoom_factor() + 0.1).min(3.0));
                }
                if ui.small_button("A−").on_hover_text("Smaller (Ctrl −)").clicked() {
                    ui.ctx().set_zoom_factor((ui.ctx().zoom_factor() - 0.1).max(0.6));
                }
                ui.separator();
                let busy = self.busy.is_some();
                if ui.add_enabled(!busy, egui::Button::new("⟳ Reset sing-box")).on_hover_text(
                    "Stop running sing-box instances and start a fresh one with this app's config",
                ).clicked() {
                    self.reset();
                }
                let (text, color) = self.status();
                ui.label(RichText::new(text).color(color));
            });
        });
    }

    fn status(&self) -> (String, Color32) {
        let inst = &self.snap.instances;
        let managed = singbox::managed_pid(&self.paths.state);
        match inst.iter().find(|i| self.uses_our_config(i)) {
            Some(i) if Some(i.pid) == managed => (format!("● sing-box running (pid {})", i.pid), GREEN),
            Some(i) => (format!("● sing-box running (pid {}, not managed)", i.pid), YELLOW),
            None if inst.is_empty() => ("● sing-box not running".into(), RED),
            None => (format!("● sing-box running with another config (pid {})", inst[0].pid), YELLOW),
        }
    }

    fn bottom_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(b) = &self.busy {
                ui.spinner();
                ui.label(b);
                ui.separator();
            }
            for e in self.snap.api_error.iter().chain(&self.snap.db_error) {
                ui.label(RichText::new(format!("⚠ {e}")).color(YELLOW));
                ui.separator();
            }
            if let Some((m, err)) = self.messages.last() {
                let resp = ui.label(RichText::new(m.lines().next().unwrap_or("")).color(if *err { RED } else { GREEN }));
                if m.contains('\n') {
                    resp.on_hover_text(m);
                }
            }
        });
    }

    fn apps(&mut self, ui: &mut egui::Ui, actions: &mut Vec<Action>) {
        ui.horizontal(|ui| {
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .id(egui::Id::new(FILTER_ID))
                    .hint_text("🔍 filter  ( / )")
                    .desired_width(220.0),
            );
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                self.filter.clear();
                r.surrender_focus();
            }
            ui.label("Active in last");
            let label = WINDOWS.iter().find(|w| w.0 == self.settings.window_secs).map_or("custom", |w| w.1);
            let before = self.settings.window_secs;
            egui::ComboBox::from_id_salt("window").selected_text(label).show_ui(ui, |ui| {
                for (secs, text) in WINDOWS {
                    ui.selectable_value(&mut self.settings.window_secs, secs, text);
                }
            });
            if self.settings.window_secs != before {
                self.monitor.retention.store(self.settings.window_secs, std::sync::atomic::Ordering::Relaxed);
                self.save_settings();
            }
            ui.separator();
            ui.label("Sort by");
            let before = self.sort;
            egui::ComboBox::from_id_salt("sort").selected_text(self.sort.label()).show_ui(ui, |ui| {
                for k in SortKey::ALL {
                    ui.selectable_value(&mut self.sort, k, k.label());
                }
            });
            if self.sort != before {
                self.desc = self.sort.default_desc();
            }
            if ui.button(if self.desc { "⬇ desc" } else { "⬆ asc" }).clicked() {
                self.desc = !self.desc;
            }
            ui.separator();
            ui.checkbox(&mut self.mine_only, "Only my apps");
        });
        ui.add_space(4.0);

        let rows = self.rows();
        let scroll_to = self.list_keys(ui.ctx(), &rows, actions);
        if rows.is_empty() {
            ui.add_space(20.0);
            ui.vertical_centered(|ui| {
                ui.weak("No app has made connections through sing-box in this time window.");
                if let Some(e) = &self.snap.api_error {
                    ui.label(RichText::new(e).color(YELLOW));
                }
            });
            return;
        }
        let header = |ui: &mut egui::Ui, app: &mut App, key: SortKey, text: &str| {
            let arrow = if app.sort == key { if app.desc { " ⬇" } else { " ⬆" } } else { "" };
            if ui.selectable_label(app.sort == key, RichText::new(format!("{text}{arrow}")).strong()).clicked() {
                if app.sort == key {
                    app.desc = !app.desc;
                } else {
                    app.sort = key;
                    app.desc = key.default_desc();
                }
            }
        };
        let now = history::now();
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        let mut table = TableBuilder::new(ui);
        if let Some(i) = scroll_to {
            table = table.scroll_to_row(i, None);
        }
        table
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::exact(44.0))
            .column(Column::initial(170.0).at_least(80.0).clip(true))
            .column(Column::initial(60.0))
            .column(Column::initial(50.0))
            .column(Column::initial(70.0))
            .column(Column::initial(70.0))
            .column(Column::initial(55.0))
            .column(Column::initial(65.0))
            .column(Column::initial(70.0))
            .column(Column::initial(65.0))
            .column(Column::initial(55.0))
            .column(Column::initial(65.0))
            .column(Column::initial(90.0).clip(true))
            .column(Column::remainder().clip(true))
            .header(row_h + 2.0, |mut h| {
                h.col(|ui| header(ui, self, SortKey::Routed, "VPN"));
                h.col(|ui| header(ui, self, SortKey::Name, "App"));
                h.col(|ui| header(ui, self, SortKey::LastSeen, "Active"));
                h.col(|ui| header(ui, self, SortKey::Live, "Open"));
                h.col(|ui| header(ui, self, SortKey::Speed, "↓/s"));
                h.col(|ui| header(ui, self, SortKey::Speed, "↑/s"));
                h.col(|ui| header(ui, self, SortKey::Hits, "Conns"));
                h.col(|ui| header(ui, self, SortKey::Domains, "Domains"));
                h.col(|ui| header(ui, self, SortKey::Traffic, "Traffic"));
                h.col(|ui| {
                    ui.strong("Procs");
                });
                h.col(|ui| header(ui, self, SortKey::Cpu, "CPU%"));
                h.col(|ui| header(ui, self, SortKey::Memory, "Memory"));
                h.col(|ui| {
                    ui.strong("Outbound");
                });
                h.col(|ui| {
                    ui.strong("Process path");
                });
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut row| {
                    let r = &rows[row.index()];
                    row.set_selected(self.selected.as_deref() == Some(r.exe.as_str()));
                    row.col(|ui| {
                        if r.routed {
                            ui.label(RichText::new("● VPN").color(GREEN).small());
                        }
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&r.name).strong());
                    });
                    row.col(|ui| {
                        if r.live > 0 {
                            ui.label(RichText::new("now").color(GREEN));
                        } else {
                            ui.label(format!("{} ago", ago(now - r.last_seen)));
                        }
                    });
                    row.col(|ui| {
                        if r.live > 0 {
                            ui.label(r.live.to_string());
                        }
                    });
                    row.col(|ui| {
                        ui.label(rate(r.rate_down));
                    });
                    row.col(|ui| {
                        ui.label(rate(r.rate_up));
                    });
                    row.col(|ui| {
                        ui.label(r.hits.to_string());
                    });
                    row.col(|ui| {
                        ui.label(r.domains.to_string());
                    });
                    row.col(|ui| {
                        ui.label(human(r.traffic as f64));
                    });
                    row.col(|ui| {
                        ui.label(if r.pids.is_empty() { "—".into() } else { r.pids.len().to_string() });
                    });
                    row.col(|ui| {
                        if !r.pids.is_empty() {
                            ui.label(format!("{:.1}", r.cpu));
                        }
                    });
                    row.col(|ui| {
                        if !r.pids.is_empty() {
                            ui.label(human(r.rss as f64));
                        }
                    });
                    row.col(|ui| {
                        let obs: Vec<&str> = r.outbounds.iter().map(String::as_str).collect();
                        let color = if obs.iter().any(|o| *o != "direct") { GREEN } else { ui.visuals().weak_text_color() };
                        ui.label(RichText::new(obs.join(",")).color(color));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(&r.exe).weak().monospace());
                    });
                    let resp = row.response();
                    if resp.clicked() {
                        actions.push(Action::Select(r.exe.clone()));
                    }
                    if resp.double_clicked() && !r.exe.is_empty() {
                        actions.push(if r.routed { Action::Unroute(r.exe.clone()) } else { Action::Route(r.exe.clone()) });
                    }
                    resp.context_menu(|ui| {
                        if ui.button("More details").clicked() {
                            actions.push(Action::Details(r.exe.clone()));
                            ui.close_menu();
                        }
                        ui.separator();
                        if r.exe.is_empty() {
                            ui.label("sing-box couldn't identify the process — can't route");
                        } else if r.routed {
                            if ui.button("Remove from VPN").clicked() {
                                actions.push(Action::Unroute(r.exe.clone()));
                                ui.close_menu();
                            }
                        } else if ui.button("Route via VPN").clicked() {
                            actions.push(Action::Route(r.exe.clone()));
                            ui.close_menu();
                        }
                        if ui.button("Copy path").clicked() {
                            ui.output_mut(|o| o.copied_text = r.exe.clone());
                            ui.close_menu();
                        }
                        if ui.button("Forget history").clicked() {
                            actions.push(Action::Forget(r.exe.clone()));
                            ui.close_menu();
                        }
                    });
                });
            });
    }

    /// Keyboard control of the app list. Returns a row to scroll to.
    fn list_keys(&mut self, ctx: &egui::Context, rows: &[Row], actions: &mut Vec<Action>) -> Option<usize> {
        use egui::{Key, Modifiers};
        if ctx.wants_keyboard_input() || rows.is_empty() {
            return None;
        }
        let pos = self.selected.as_ref().and_then(|s| rows.iter().position(|r| &r.exe == s));
        let (down, up, home, end, space, esc) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::NONE, Key::ArrowDown) || i.consume_key(Modifiers::NONE, Key::J),
                i.consume_key(Modifiers::NONE, Key::ArrowUp) || i.consume_key(Modifiers::NONE, Key::K),
                i.consume_key(Modifiers::NONE, Key::Home),
                i.consume_key(Modifiers::NONE, Key::End),
                i.consume_key(Modifiers::NONE, Key::Space) || i.consume_key(Modifiers::NONE, Key::Enter),
                i.consume_key(Modifiers::NONE, Key::Escape),
            )
        });
        if esc {
            if self.details_open {
                self.details_open = false;
            } else {
                self.selected = None;
            }
            return None;
        }
        if space {
            if let Some(r) = pos.map(|i| &rows[i]).filter(|r| !r.exe.is_empty()) {
                actions.push(if r.routed { Action::Unroute(r.exe.clone()) } else { Action::Route(r.exe.clone()) });
            }
        }
        let last = rows.len() - 1;
        let target = match pos {
            _ if home => 0,
            _ if end => last,
            Some(i) if down => (i + 1).min(last),
            Some(i) if up => i.saturating_sub(1),
            None if down || up => 0,
            _ => return None,
        };
        self.selected = Some(rows[target].exe.clone());
        Some(target)
    }

    fn details(&mut self, ui: &mut egui::Ui, exe: &str, actions: &mut Vec<Action>) {
        let procs: Vec<_> = self.snap.procs.iter().filter(|p| !exe.is_empty() && p.exe == exe).cloned().collect();
        let routed = !exe.is_empty() && self.cfg.items(APP_KEY).iter().any(|a| a == exe);
        let name = if exe.is_empty() { "(unknown process)".into() } else { file_name(exe) };

        ui.horizontal(|ui| {
            ui.heading(name);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("✖").clicked() {
                    self.details_open = false;
                }
            });
        });
        ui.label(RichText::new(exe).monospace().weak());
        ui.add_space(6.0);
        if exe.is_empty() {
            ui.label(
                RichText::new("sing-box couldn't identify the process for these connections, so they can't be routed by path.")
                    .color(YELLOW),
            );
        } else if routed {
            ui.label(RichText::new("● Routed via VPN").color(GREEN).strong());
            if ui.add(egui::Button::new("➖ Remove from VPN routes").min_size([220.0, 28.0].into())).clicked() {
                actions.push(Action::Unroute(exe.to_owned()));
            }
        } else {
            ui.label(format!("Not routed (goes to “{}”)", self.cfg.final_outbound()));
            if ui.add(egui::Button::new(RichText::new("➕ Route via VPN").strong()).min_size([220.0, 28.0].into())).clicked() {
                actions.push(Action::Route(exe.to_owned()));
            }
        }
        ui.separator();

        // history for this app, re-queried every couple of seconds
        if self.flows.0 != exe || self.flows.1.is_none_or(|t| t.elapsed() > Duration::from_secs(2)) {
            if self.db.is_none() {
                self.db = history::open(&self.paths.state.join("history.db")).ok();
            }
            let flows = self.db.as_ref().and_then(|db| history::flows(db, exe).ok()).unwrap_or_default();
            self.flows = (exe.to_owned(), Some(Instant::now()), flows);
        }

        let mut conns: Vec<&Conn> = self.snap.conns.iter().filter(|c| c.app == exe && c.port != 53).collect();
        conns.sort_by(|a, b| (b.rate_down + b.rate_up).total_cmp(&(a.rate_down + a.rate_up)).then(b.down.cmp(&a.down)));
        let now = history::now();
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            egui::CollapsingHeader::new(format!("Open connections ({})", conns.len())).default_open(true).show(ui, |ui| {
                if conns.is_empty() {
                    ui.weak("none right now");
                }
                egui::Grid::new("conns").striped(true).num_columns(4).show(ui, |ui| {
                    for c in conns.iter().take(200) {
                        ui.label(RichText::new(format!("{}:{}", c.host, c.port)).monospace())
                            .on_hover_text(format!("{} {} · rule: {}", c.network, c.ip, c.rule));
                        let col = if c.outbound == "direct" { ui.visuals().weak_text_color() } else { GREEN };
                        ui.label(RichText::new(&c.outbound).color(col));
                        ui.label(format!("↓{} ↑{}", rate(c.rate_down), rate(c.rate_up)));
                        ui.label(human((c.up + c.down) as f64));
                        ui.end_row();
                    }
                });
            });
            let flows = &self.flows.2;
            egui::CollapsingHeader::new(format!("Domains seen ({})", flows.len())).default_open(true).show(ui, |ui| {
                egui::Grid::new("flows").striped(true).num_columns(5).show(ui, |ui| {
                    for f in flows {
                        ui.label(RichText::new(format!("{}:{}", f.target, f.port)).monospace());
                        let col = if f.outbound == "direct" { ui.visuals().weak_text_color() } else { GREEN };
                        ui.label(RichText::new(&f.outbound).color(col));
                        ui.label(format!("{}×", f.hits));
                        ui.label(human(f.traffic as f64));
                        ui.label(format!("{} ago", ago(now - f.last_seen)));
                        ui.end_row();
                    }
                });
                if !flows.is_empty() && ui.small_button("Forget this app's history").clicked() {
                    actions.push(Action::Forget(exe.to_owned()));
                }
            });
            egui::CollapsingHeader::new(format!("Running processes ({})", procs.len())).default_open(false).show(ui, |ui| {
                egui::Grid::new("procs").striped(true).num_columns(5).show(ui, |ui| {
                    for p in &procs {
                        ui.label(p.pid.to_string());
                        ui.label(&p.user);
                        ui.label(format!("{:.1}%", p.cpu));
                        ui.label(human(p.rss as f64));
                        let cmd: String = p.cmdline.chars().take(80).collect();
                        ui.label(RichText::new(cmd).monospace().small()).on_hover_text(&p.cmdline);
                        ui.end_row();
                    }
                });
            });
        });
    }

    fn routing(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("VPN outbound:");
            ui.label(RichText::new(self.cfg.vpn_tag().unwrap_or_else(|| "(none!)".into())).color(GREEN).strong());
            ui.separator();
            ui.label(format!("everything else → {}", self.cfg.final_outbound()));
            ui.separator();
            if ui.button("Re-read config").clicked() {
                self.reload_config_from_disk();
            }
            if ui.button("Apply / reload").clicked() {
                self.apply();
            }
        });
        ui.label(RichText::new(self.paths.config.display().to_string()).monospace().weak());
        ui.separator();

        let running: BTreeSet<&str> = self.snap.procs.iter().map(|p| p.exe.as_str()).collect();
        let mut remove: Option<(&str, String)> = None;
        let mut add: Option<(&str, String)> = None;
        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            ui.heading("Apps (process_path)");
            for a in self.cfg.items(APP_KEY) {
                ui.horizontal(|ui| {
                    if ui.small_button("✖").on_hover_text("remove from VPN").clicked() {
                        remove = Some((APP_KEY, a.clone()));
                    }
                    let (dot, col) = if running.contains(a.as_str()) { ("●", GREEN) } else { ("○", Color32::GRAY) };
                    ui.label(RichText::new(dot).color(col)).on_hover_text("running now?");
                    ui.label(RichText::new(&a).monospace());
                });
            }
            ui.horizontal(|ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut self.new_app).hint_text("/path/to/executable").desired_width(360.0));
                if (ui.button("Add app").clicked() || r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    && !self.new_app.trim().is_empty()
                {
                    add = Some((APP_KEY, std::mem::take(&mut self.new_app).trim().to_owned()));
                }
            });
            ui.add_space(12.0);
            ui.heading("Domains (domain_suffix)");
            for d in self.cfg.items(DOMAIN_KEY) {
                ui.horizontal(|ui| {
                    if ui.small_button("✖").on_hover_text("remove from VPN").clicked() {
                        remove = Some((DOMAIN_KEY, d.clone()));
                    }
                    ui.label(RichText::new(&d).monospace());
                });
            }
            ui.horizontal(|ui| {
                let r = ui.add(egui::TextEdit::singleline(&mut self.new_domain).hint_text("example.com").desired_width(360.0));
                if (ui.button("Add domain").clicked() || r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                    && !self.new_domain.trim().is_empty()
                {
                    add = Some((DOMAIN_KEY, std::mem::take(&mut self.new_domain).trim().to_lowercase()));
                }
            });
        });
        if let Some((k, v)) = remove {
            self.edit_rule(k, &v, false);
        }
        if let Some((k, v)) = add {
            self.edit_rule(k, &v, true);
        }
    }

    fn singbox_tab(&mut self, ui: &mut egui::Ui) {
        let busy = self.busy.is_some();
        egui::Grid::new("sb").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            ui.label("Status");
            let (t, c) = self.status();
            ui.label(RichText::new(t).color(c));
            ui.end_row();
            ui.label("Binary");
            ui.horizontal(|ui| {
                if ui.add(egui::TextEdit::singleline(&mut self.settings.singbox).desired_width(480.0)).lost_focus() {
                    self.save_settings();
                }
                if ui.button("Detect").clicked() {
                    self.settings.singbox = singbox::default_binary();
                    self.save_settings();
                }
            });
            ui.end_row();
            ui.label("Config");
            ui.label(RichText::new(self.paths.config.display().to_string()).monospace());
            ui.end_row();
            ui.label("Log");
            ui.label(RichText::new(self.paths.state.join("sing-box.log").display().to_string()).monospace());
            ui.end_row();
            ui.label("Options");
            ui.vertical(|ui| {
                if ui.checkbox(&mut self.settings.reset_on_start, "Reset sing-box when proxy2vpn starts").changed() {
                    self.save_settings();
                }
                if ui
                    .checkbox(&mut self.settings.stop_others, "Reset also stops sing-box instances using other configs")
                    .changed()
                {
                    self.save_settings();
                }
            });
            ui.end_row();
        });
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("⟳ Reset (restart with this config)")).clicked() {
                self.reset();
            }
            if ui.add_enabled(!busy, egui::Button::new("Reload")).clicked() {
                self.apply();
            }
            if ui.add_enabled(!busy && !self.snap.instances.is_empty(), egui::Button::new("Stop")).clicked() {
                self.stop();
            }
            if ui.add_enabled(!busy, egui::Button::new("Check config")).clicked() {
                self.check();
            }
        });
        ui.separator();
        ui.strong("Running instances");
        let managed = singbox::managed_pid(&self.paths.state);
        egui::Grid::new("inst").striped(true).num_columns(4).show(ui, |ui| {
            for i in &self.snap.instances {
                ui.label(i.pid.to_string());
                ui.label(if Some(i.pid) == managed { "managed" } else { "external" });
                ui.label(RichText::new(&i.binary).monospace());
                let cfg = i.config.as_ref().map(|c| c.display().to_string()).unwrap_or("?".into());
                let col = if self.uses_our_config(i) { GREEN } else { YELLOW };
                ui.label(RichText::new(cfg).monospace().color(col));
                ui.end_row();
            }
        });
        if self.snap.instances.is_empty() {
            ui.weak("none");
        }
        ui.separator();

        if self.log_read.is_none_or(|t| t.elapsed() > Duration::from_secs(2)) {
            self.log_tail = tail(&self.paths.state.join("sing-box.log"), 300);
            self.log_read = Some(Instant::now());
        }
        ui.strong("sing-box log");
        egui::ScrollArea::vertical().auto_shrink(false).stick_to_bottom(true).show(ui, |ui| {
            ui.label(RichText::new(&self.log_tail).monospace().small());
        });
    }

    fn global_keys(&mut self, ctx: &egui::Context) {
        use egui::{Key, Modifiers};
        let typing = ctx.wants_keyboard_input();
        let (tab, reset, focus_filter) = ctx.input_mut(|i| {
            let tab = [(Key::Num1, Tab::Apps), (Key::Num2, Tab::Routing), (Key::Num3, Tab::SingBox)]
                .into_iter()
                .find(|(k, _)| i.consume_key(Modifiers::ALT, *k))
                .map(|(_, t)| t);
            let reset = i.consume_key(Modifiers::CTRL, Key::R);
            let focus = i.consume_key(Modifiers::CTRL, Key::F) || (!typing && i.consume_key(Modifiers::NONE, Key::Slash));
            (tab, reset, focus)
        });
        if let Some(t) = tab {
            self.tab = t;
        }
        if reset && self.busy.is_none() {
            self.reset();
        }
        if focus_filter {
            self.tab = Tab::Apps;
            ctx.memory_mut(|m| m.request_focus(egui::Id::new(FILTER_ID)));
        }
        // eframe handles Ctrl +/−/0 itself; remember the result
        let zoom = ctx.zoom_factor();
        if (zoom - self.settings.zoom).abs() > 0.001 {
            self.settings.zoom = zoom;
            self.save_settings();
        }
    }

    fn messages_window(&self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().stick_to_bottom(true).max_height(90.0).auto_shrink([false, true]).show(ui, |ui| {
            for (m, err) in &self.messages {
                ui.label(RichText::new(m).small().color(if *err { RED } else { ui.visuals().text_color() }));
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        while let Ok(r) = self.rx.try_recv() {
            self.busy = None;
            self.msg(r);
        }
        self.snap = self.monitor.snapshot.lock().unwrap().clone();
        self.global_keys(ctx);

        let mut actions = Vec::new();
        egui::TopBottomPanel::top("top").show(ctx, |ui| self.top_bar(ui));
        egui::TopBottomPanel::bottom("bottom").show(ctx, |ui| self.bottom_bar(ui));
        if self.tab == Tab::SingBox {
            egui::TopBottomPanel::bottom("messages").resizable(true).show(ctx, |ui| self.messages_window(ui));
        }
        if self.tab == Tab::Apps {
            if let Some(key) = self.selected.clone().filter(|_| self.details_open) {
                egui::SidePanel::right("details")
                    .resizable(true)
                    .default_width(420.0)
                    .show(ctx, |ui| self.details(ui, &key, &mut actions));
            }
        }
        egui::CentralPanel::default().show(ctx, |ui| match self.tab {
            Tab::Apps => self.apps(ui, &mut actions),
            Tab::Routing => self.routing(ui),
            Tab::SingBox => self.singbox_tab(ui),
        });

        for a in actions {
            match a {
                Action::Select(k) => self.selected = Some(k),
                Action::Details(k) => {
                    self.selected = Some(k);
                    self.details_open = true;
                }
                Action::Route(exe) => self.edit_rule(APP_KEY, &exe, true),
                Action::Unroute(exe) => self.edit_rule(APP_KEY, &exe, false),
                Action::Forget(exe) => self.forget(&exe),
            }
        }
    }
}

// ------------------------------------------------------------ helpers

/// egui's bundled fonts lack arrows, ● and most non-Latin scripts; borrow system fonts for those.
fn install_fallback_fonts(ctx: &egui::Context) {
    const CANDIDATES: [&str; 5] = [
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf",
        "/usr/share/fonts/google-noto/NotoSans-Regular.ttf",
    ];
    let mut fonts = egui::FontDefinitions::default();
    for path in CANDIDATES {
        let Ok(bytes) = fs::read(path) else { continue };
        fonts.font_data.insert(path.into(), egui::FontData::from_owned(bytes));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts.families.entry(family).or_default().push(path.into());
        }
    }
    ctx.set_fonts(fonts);
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.to_owned())
}

fn same_file(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
    canon(a) == canon(b)
}

fn human(n: f64) -> String {
    let mut n = n;
    for unit in ["B", "K", "M", "G"] {
        if n < 1024.0 {
            return format!("{n:.0}{unit}");
        }
        n /= 1024.0;
    }
    format!("{n:.1}T")
}

fn ago(secs: f64) -> String {
    let s = secs.max(0.0) as u64;
    for (unit, n) in [("d", 86400), ("h", 3600), ("m", 60)] {
        if s >= n {
            return format!("{}{unit}", s / n);
        }
    }
    format!("{s}s")
}

fn rate(n: f64) -> String {
    if n < 1.0 {
        String::new()
    } else {
        format!("{}/s", human(n))
    }
}

fn tail(path: &Path, lines: usize) -> String {
    let text = fs::read(path).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let text = strip_ansi(&text);
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
