//! Finding, (re)starting and reloading sing-box.
//!
//! Routing changes don't come through here: they go to the rule-set file, which sing-box reloads
//! by itself. This is for the rest of the config.
//!
//! sing-box needs root for TUN, and only reloads on SIGHUP (the Clash API's PUT /configs is a
//! no-op) — and that SIGHUP reload breaks with TUN. So "reset" starts sing-box under a tiny root
//! shell supervisor, authorised once via sudo/pkexec. The supervisor listens on a user-owned FIFO
//! for `reload` (a clean restart) / `stop`, restarts sing-box if it crashes, and so later reloads
//! need no password.

use crate::procs::Proc;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_BINARY: &str = "Application/v2rayN-linux-64/bin/sing_box/sing-box";

#[derive(Clone, Debug)]
pub struct Instance {
    pub pid: u32,
    pub binary: String,
    pub config: Option<PathBuf>,
}

/// All running `sing-box run` processes (sudo/pkexec wrappers excluded).
pub fn find_all() -> Vec<Instance> {
    let Ok(dir) = fs::read_dir("/proc") else { return vec![] };
    dir.flatten()
        .filter_map(|e| {
            let pid = e.file_name().to_str()?.parse::<u32>().ok()?;
            let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
            let argv: Vec<String> = raw
                .split(|&b| b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            instance(pid, &argv)
        })
        .collect()
}

/// The sing-box instances among already-scanned processes.
pub fn in_procs(procs: &[Proc]) -> Vec<Instance> {
    procs.iter().filter_map(|p| instance(p.pid, &p.args)).collect()
}

fn instance(pid: u32, argv: &[String]) -> Option<Instance> {
    if !argv.first().is_some_and(|a| a.ends_with("sing-box")) || !argv.iter().any(|a| a == "run") {
        return None;
    }
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
    if matches!(comm.trim(), "sudo" | "pkexec" | "doas") {
        return None;
    }
    let config = argv.windows(2).find(|w| w[0] == "-c" || w[0] == "--config").map(|w| {
        let p = PathBuf::from(&w[1]);
        if p.is_absolute() {
            p
        } else {
            fs::read_link(format!("/proc/{pid}/cwd")).map(|cwd| cwd.join(&p)).unwrap_or(p)
        }
    });
    Some(Instance { pid, binary: argv[0].clone(), config })
}

/// Best guess at the sing-box binary: a running one, the v2rayN bundle, or PATH.
pub fn default_binary() -> String {
    if let Some(i) = find_all().into_iter().next() {
        return i.binary;
    }
    let bundled = home().join(DEFAULT_BINARY);
    if bundled.exists() {
        return bundled.to_string_lossy().into_owned();
    }
    "sing-box".into()
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/root".into())
}

pub fn check(binary: &str, config: &Path) -> Result<(), String> {
    let out = Command::new(binary)
        .args(["check", "-c"])
        .arg(config)
        .output()
        .map_err(|e| format!("cannot run {binary}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        let msg = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr });
        Err(format!("sing-box check failed:\n{}", msg.trim()))
    }
}

/// Bumped whenever the supervisor script changes, so an old one gets replaced on the next reset.
const SUPERVISOR_VERSION: &str = "2";

/// pid of the sing-box our (current) supervisor runs, if it is alive.
pub fn managed_pid(state: &Path) -> Option<u32> {
    if fs::read_to_string(state.join("supervisor.version")).ok()?.trim() != SUPERVISOR_VERSION {
        return None;
    }
    let pid: u32 = fs::read_to_string(state.join("sing-box.pid")).ok()?.trim().parse().ok()?;
    Path::new(&format!("/proc/{pid}")).exists().then_some(pid)
}

fn send_ctl(state: &Path, cmd: &str) -> std::io::Result<()> {
    // non-blocking so a FIFO with no supervisor behind it fails (ENXIO) instead of hanging
    let mut f = OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(state.join("ctl"))?;
    f.write_all(format!("{cmd}\n").as_bytes())
}

const SUPERVISOR: &str = r#"
set -u
bin=$1; cfg=$2; dir=$3; owner=$4; shift 4
[ -f "$dir/supervisor.pid" ] && kill "$(cat "$dir/supervisor.pid")" 2>/dev/null
for p in "$@"; do kill "$p" 2>/dev/null; done
i=0
while [ $i -lt 50 ]; do
  alive=
  for p in "$@"; do kill -0 "$p" 2>/dev/null && alive=1; done
  [ -z "$alive" ] && break
  sleep 0.1; i=$((i+1))
done
for p in "$@"; do kill -9 "$p" 2>/dev/null; done
rm -f "$dir/ctl" "$dir/sing-box.pid" "$dir/supervisor.pid" "$dir/supervisor.version"
mkfifo -m 600 "$dir/ctl" && chown "$owner" "$dir/ctl" || exit 1
setsid -f /bin/sh -c '
  bin=$1; cfg=$2; dir=$3
  echo $$ > "$dir/supervisor.pid"
  echo SUPERVISOR_VERSION > "$dir/supervisor.version"
  exec 3<>"$dir/ctl"
  log() { echo "--- $(date "+%F %T") oxito: $*" >>"$dir/sing-box.log"; }
  # kill -0 succeeds on an unreaped zombie, so look at the process state instead
  alive() { [ -r /proc/$1/stat ] && [ "$(sed "s/.*) //; s/ .*//" /proc/$1/stat 2>/dev/null)" != Z ]; }
  start() {
    log "starting $bin run -c $cfg"
    "$bin" run -c "$cfg" 3>&- >>"$dir/sing-box.log" 2>&1 &
    sb=$!
    started=$(date +%s)
    echo $sb > "$dir/sing-box.pid"
    ( while alive $sb; do sleep 0.5; done; echo "exited $sb" >&3 ) &
  }
  halt() {
    kill $sb 2>/dev/null
    i=0
    while alive $sb && [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done
    kill -9 $sb 2>/dev/null
    wait $sb 2>/dev/null
  }
  fails=0
  start
  while read -r cmd arg <&3; do
    case $cmd in
      # SIGHUP reload re-opens the TUN device while the old one is still held and dies with
      # "TUNSETIFF: device or resource busy", so a reload is a clean restart instead
      reload) log "restarting to apply config"; halt; sleep 0.3; fails=0; start ;;
      stop) log "stopping"; halt; break ;;
      exited)
        [ "$arg" = "$sb" ] || continue
        wait $sb 2>/dev/null
        if [ $(( $(date +%s) - started )) -lt 10 ]; then fails=$((fails+1)); else fails=1; fi
        if [ $fails -ge 3 ]; then log "sing-box keeps exiting; giving up"; break; fi
        log "sing-box exited; restarting"; sleep 1; start ;;
    esac
  done
  if [ "$(cat "$dir/sing-box.pid" 2>/dev/null)" = "$sb" ]; then
    rm -f "$dir/ctl" "$dir/sing-box.pid" "$dir/supervisor.pid" "$dir/supervisor.version"
  fi
' oxito-supervisor "$bin" "$cfg" "$dir" </dev/null >/dev/null 2>&1
"#;

/// Run a command as root: directly if we are root, via cached sudo if possible, else pkexec.
fn run_root(args: &[&str]) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions
    let mut cmd = if unsafe { libc::geteuid() } == 0 {
        let mut c = Command::new(args[0]);
        c.args(&args[1..]);
        c
    } else if Command::new("sudo").args(["-n", "true"]).output().is_ok_and(|o| o.status.success()) {
        let mut c = Command::new("sudo");
        c.arg("-n").args(args);
        c
    } else {
        let mut c = Command::new("pkexec");
        c.args(args);
        c
    };
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(match out.status.code() {
            Some(126) | Some(127) if err.trim().is_empty() => "authorisation cancelled".into(),
            _ => format!("privileged command failed ({}): {}", out.status, err.trim()),
        })
    }
}

/// Stop every given sing-box instance and start a fresh supervised one with `config`.
pub fn reset(binary: &str, config: &Path, state: &Path, kill: &[u32]) -> Result<(), String> {
    check(binary, config)?;
    fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let binary = fs::canonicalize(binary)
        .or_else(|_| which(binary).ok_or(()))
        .map_err(|_| format!("sing-box binary not found: {binary}"))?;
    let config = fs::canonicalize(config).map_err(|e| e.to_string())?;
    // SAFETY: getuid has no preconditions
    let uid = unsafe { libc::getuid() }.to_string();
    let pids: Vec<String> = kill.iter().map(u32::to_string).collect();
    let mut args = vec!["/bin/sh", "-c", SUPERVISOR, "oxito-reset"];
    let (b, c, s) = (binary.to_string_lossy(), config.to_string_lossy(), state.to_string_lossy());
    args.extend([b.as_ref(), c.as_ref(), s.as_ref(), uid.as_str()]);
    args.extend(pids.iter().map(String::as_str));
    let script = SUPERVISOR.replace("SUPERVISOR_VERSION", SUPERVISOR_VERSION);
    args[2] = &script;
    run_root(&args)?;
    // give sing-box a moment to come up (or die on a bad config)
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if managed_pid(state).is_some() {
            return Ok(());
        }
    }
    Err(format!("sing-box did not start; see {}", state.join("sing-box.log").display()))
}

/// Restart our supervised sing-box so it picks up the config, and wait until it's back up.
pub fn reload(state: &Path) -> Result<String, String> {
    let old = managed_pid(state).ok_or("sing-box was not started by oxito")?;
    send_ctl(state, "reload").map_err(|e| format!("supervisor unreachable: {e}"))?;
    for _ in 0..80 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        if let Some(pid) = managed_pid(state).filter(|&p| p != old) {
            // a bad config makes sing-box exit right away; give it a moment to prove itself
            std::thread::sleep(std::time::Duration::from_millis(700));
            if Path::new(&format!("/proc/{pid}")).exists() {
                return Ok(format!("sing-box restarted with the new config (pid {pid})"));
            }
        }
    }
    Err(format!("sing-box did not come back up; see {}", state.join("sing-box.log").display()))
}

pub fn stop(state: &Path, pids: &[u32]) -> Result<(), String> {
    let managed = managed_pid(state).filter(|_| send_ctl(state, "stop").is_ok());
    let rest: Vec<String> = pids.iter().filter(|&&p| Some(p) != managed).map(u32::to_string).collect();
    if rest.is_empty() {
        return Ok(());
    }
    let mut args = vec!["kill"];
    args.extend(rest.iter().map(String::as_str));
    run_root(&args)
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")?.to_str()?.split(':').map(|d| Path::new(d).join(name)).find(|p| p.is_file())
}
