//! Process list from /proc, with CPU usage computed between scans. Used to attach PIDs, CPU and
//! memory to the apps sing-box reports.
//!
//! Scanning every process each second is most of this app's CPU cost, so it is kept cheap: a
//! process's exe, command line and owner are cached and re-read only when its /proc/PID/exe link
//! changes (one syscall per process per scan), and CPU / memory are read only for the processes
//! the caller asks about.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct Proc {
    pub pid: u32,
    /// Executable path as sing-box sees it (/proc/PID/exe); guessed from argv[0] when unreadable.
    pub exe: String,
    pub args: Vec<String>,
    pub cmdline: String,
    pub user: String,
    /// Only measured for the processes passed to `Scanner::usage`; 0 otherwise.
    pub cpu: f32,
    pub rss: u64,
}

pub struct Scanner {
    /// pid -> (exe link when read, the process; None for kernel threads)
    cache: HashMap<u32, (Option<PathBuf>, Option<Proc>)>,
    prev_ticks: HashMap<u32, u64>,
    last: Option<Instant>,
    users: HashMap<u32, String>,
    clk_tck: f64,
    page: u64,
}

impl Scanner {
    pub fn new() -> Self {
        let users = fs::read_to_string("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                Some((f.get(2)?.parse().ok()?, f[0].to_owned()))
            })
            .collect();
        // SAFETY: sysconf has no preconditions
        let (clk, page) = unsafe { (libc::sysconf(libc::_SC_CLK_TCK), libc::sysconf(libc::_SC_PAGESIZE)) };
        Self {
            cache: HashMap::new(),
            prev_ticks: HashMap::new(),
            last: None,
            users,
            clk_tck: if clk > 0 { clk as f64 } else { 100.0 },
            page: if page > 0 { page as u64 } else { 4096 },
        }
    }

    /// All user processes, without CPU / memory.
    pub fn scan(&mut self) -> Vec<Proc> {
        let mut cache = HashMap::with_capacity(self.cache.len());
        let mut out = Vec::new();
        let Ok(dir) = fs::read_dir("/proc") else { return out };
        for entry in dir.flatten() {
            let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
            let link = fs::read_link(format!("/proc/{pid}/exe")).ok();
            let cached = match self.cache.remove(&pid) {
                Some((l, p)) if l == link => p,
                // new process, or it exec'd something else
                _ => match self.read(pid, &link) {
                    Some(p) => p,
                    None => continue, // gone
                },
            };
            out.extend(cached.clone());
            cache.insert(pid, (link, cached));
        }
        self.cache = cache;
        out
    }

    /// Fill in CPU and memory for the processes `wanted` picks.
    pub fn usage(&mut self, procs: &mut [Proc], wanted: impl Fn(&Proc) -> bool) {
        let now = Instant::now();
        let dt = self.last.map(|l| (now - l).as_secs_f64()).unwrap_or(0.0);
        self.last = Some(now);
        let mut ticks = HashMap::new();
        for p in procs.iter_mut().filter(|p| wanted(p)) {
            let Some((t, rss)) = self.stat(p.pid) else { continue };
            p.rss = rss;
            if let Some(&prev) = self.prev_ticks.get(&p.pid).filter(|_| dt > 0.0) {
                p.cpu = (t.saturating_sub(prev) as f64 / self.clk_tck / dt * 100.0) as f32;
            }
            ticks.insert(p.pid, t);
        }
        self.prev_ticks = ticks;
    }

    /// (utime + stime ticks, rss bytes)
    fn stat(&self, pid: u32) -> Option<(u64, u64)> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // comm is in parens and may contain spaces; fields after it are space separated
        let (_, rest) = stat.rsplit_once(')')?;
        let f: Vec<&str> = rest.split_whitespace().collect();
        let ticks = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
        let rss = f.get(21).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) * self.page;
        Some((ticks, rss))
    }

    /// None if the process is gone; Some(None) for a kernel thread or zombie.
    fn read(&self, pid: u32, link: &Option<PathBuf>) -> Option<Option<Proc>> {
        let base = format!("/proc/{pid}");
        let raw = fs::read(format!("{base}/cmdline")).ok()?;
        if raw.is_empty() {
            return Some(None);
        }
        let args: Vec<String> =
            raw.split(|&b| b == 0).filter(|a| !a.is_empty()).map(|a| String::from_utf8_lossy(a).into_owned()).collect();
        let exe = match link {
            Some(p) => p.to_string_lossy().trim_end_matches(" (deleted)").to_owned(),
            None => args.first().map(|a| guess_exe(a)).unwrap_or_default(),
        };
        let uid = fs::metadata(&base).ok()?.uid();
        let user = self.users.get(&uid).cloned().unwrap_or_else(|| uid.to_string());
        let cmdline = args.join(" ");
        Some(Some(Proc { pid, exe, args, cmdline, user, cpu: 0.0, rss: 0 }))
    }
}

/// Best guess at an executable from argv[0] when /proc/PID/exe is unreadable.
fn guess_exe(argv0: &str) -> String {
    if argv0.starts_with('/') {
        return argv0.to_owned();
    }
    if argv0.contains('/') || argv0.contains(' ') || argv0.contains(':') {
        return String::new(); // relative path or a rewritten title ("sshd: user@pts/0")
    }
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .map(|d| std::path::Path::new(d).join(argv0))
        .find(|p| p.is_file())
        .and_then(|p| fs::canonicalize(p).ok())
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}
