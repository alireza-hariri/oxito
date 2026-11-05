#!/usr/bin/env python3
"""p2v - see which apps connect to which domains through sing-box, and route them via the VPN.

Connections are read live from sing-box's Clash API (process path, sniffed domain,
matched rule, outbound) and stored in a local SQLite history. Rules are written into
the sing-box config, which is then validated and hot-reloaded with SIGHUP.
"""

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "sing-box-hf.json"
DEFAULT_SINGBOX = Path.home() / "Application/v2rayN-linux-64/bin/sing_box/sing-box"
STATE_DIR = Path.home() / ".local/state/oxito"
DB_PATH = STATE_DIR / "history.db"
API_ADDR = "127.0.0.1:9090"

TTY = sys.stdout.isatty()


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if TTY else str(text)


def die(msg):
    print(c("error: ", 31) + msg, file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- config

class Config:
    def __init__(self, path):
        self.path = Path(path)
        self.data = json.loads(self.path.read_text())

    def save(self):
        shutil.copy2(self.path, self.path.with_suffix(".json.bak"))
        self.path.write_text(json.dumps(self.data, indent=2) + "\n")

    @property
    def rules(self):
        return self.data.setdefault("route", {}).setdefault("rules", [])

    @property
    def vpn_tag(self):
        for ob in self.data.get("outbounds", []):
            if ob.get("type") not in ("direct", "block", "dns"):
                return ob["tag"]
        die("no proxy outbound found in config")

    @property
    def api(self):
        api = self.data.get("experimental", {}).get("clash_api", {})
        return api.get("external_controller"), api.get("secret", "")

    def _rule(self, key, create):
        """The VPN rule matching only on `key` (process_path / domain_suffix)."""
        for r in self.rules:
            if r.get("outbound") == self.vpn_tag and key in r and len(r) == 2:
                return r
        if not create:
            return None
        rule = {key: [], "outbound": self.vpn_tag}
        # keep sniff / hijack-dns first
        idx = 0
        for i, r in enumerate(self.rules):
            if r.get("action") in ("sniff", "hijack-dns", "resolve"):
                idx = i + 1
        self.rules.insert(idx, rule)
        return rule

    def items(self, key):
        r = self._rule(key, False)
        return list(r[key]) if r else []

    def add(self, key, value):
        r = self._rule(key, True)
        if value in r[key]:
            return False
        r[key].append(value)
        return True

    def remove(self, key, value):
        r = self._rule(key, False)
        if not r or value not in r[key]:
            return False
        r[key].remove(value)
        if not r[key]:
            self.rules.remove(r)
        return True

    def setup(self):
        """Enable Clash API + DNS reverse mapping. Returns True if changed."""
        changed = False
        api = self.data.setdefault("experimental", {}).setdefault("clash_api", {})
        if not api.get("external_controller"):
            api["external_controller"] = API_ADDR
            changed = True
        if not api.get("secret"):
            api["secret"] = secrets.token_hex(16)
            changed = True
        dns = self.data.setdefault("dns", {})
        if not dns.get("reverse_mapping"):
            # map IPs back to the domain that was resolved, for non-sniffable traffic
            dns["reverse_mapping"] = True
            changed = True
        return changed


# ---------------------------------------------------------------- sing-box process

def find_singbox(config_path):
    """(pid, binary) of the running sing-box that uses config_path."""
    target = str(Path(config_path).resolve())
    for p in Path("/proc").iterdir():
        if not p.name.isdigit():
            continue
        try:
            argv = (p / "cmdline").read_bytes().split(b"\0")
            comm = (p / "comm").read_text().strip()
        except OSError:
            continue
        argv = [a.decode(errors="replace") for a in argv if a]
        if comm == "sudo" or not argv or not argv[0].endswith("sing-box") or "run" not in argv:
            continue
        for i, a in enumerate(argv):
            if a in ("-c", "--config") and i + 1 < len(argv):
                if str(Path(argv[i + 1]).resolve()) == target:
                    return int(p.name), argv[0]
    return None, None


def check_config(binary, config_path):
    r = subprocess.run([binary, "check", "-c", str(config_path)], capture_output=True, text=True)
    if r.returncode != 0:
        die("sing-box check failed:\n" + (r.stderr or r.stdout))


def apply(cfg, args):
    pid, binary = find_singbox(cfg.path)
    binary = binary or str(args.singbox)
    check_config(binary, cfg.path)
    print(c("config OK", 32))
    if not pid:
        print(c("sing-box is not running with this config. Start it with:", 33))
        print(f"  sudo {binary} run -c {cfg.path}")
        return
    try:
        os.kill(pid, signal.SIGHUP)
    except PermissionError:
        print(f"reloading sing-box (pid {pid}) via sudo...")
        if subprocess.run(["sudo", "kill", "-HUP", str(pid)]).returncode != 0:
            die("could not signal sing-box")
    print(c(f"sing-box (pid {pid}) reloaded", 32))


# ---------------------------------------------------------------- history db

def db():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""CREATE TABLE IF NOT EXISTS flows (
        app TEXT, target TEXT, port INTEGER, network TEXT, outbound TEXT,
        first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 0,
        up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
        PRIMARY KEY (app, target, port))""")
    # one row per connection, for time-window / duration / per-connection queries
    con.execute("""CREATE TABLE IF NOT EXISTS conns (
        id TEXT PRIMARY KEY, app TEXT, user TEXT, target TEXT, ip TEXT, port INTEGER,
        network TEXT, outbound TEXT, rule TEXT, start REAL, end REAL,
        up INTEGER DEFAULT 0, down INTEGER DEFAULT 0)""")
    con.execute("CREATE INDEX IF NOT EXISTS conns_app ON conns(app, start)")
    return con


def record(con, app, target, port, network, outbound, ts, hit=1, up=0, down=0):
    con.execute("""INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(app, target, port) DO UPDATE SET
          last_seen=max(last_seen, excluded.last_seen),
          first_seen=min(first_seen, excluded.first_seen),
          outbound=excluded.outbound, network=excluded.network,
          hits=hits+excluded.hits, up=up+excluded.up, down=down+excluded.down""",
                (app, target, port, network, outbound, ts, ts, hit, up, down))


# ---------------------------------------------------------------- clash api

def fetch_connections(addr, secret):
    req = urllib.request.Request(f"http://{addr}/connections",
                                 headers={"Authorization": f"Bearer {secret}"})
    with urllib.request.urlopen(req, timeout=3) as r:
        return json.load(r).get("connections") or []


def parse_conn(conn):
    m = conn.get("metadata", {})
    proc = m.get("processPath") or ""
    user = re.search(r" \((.*)\)$", proc)
    start = conn.get("start", "")
    try:
        # Go timestamps carry nanoseconds; trim to micro for fromisoformat
        start = datetime.fromisoformat(re.sub(r"(\.\d{6})\d*", r"\1", start)).timestamp()
    except ValueError:
        start = time.time()
    return {
        "id": conn["id"],
        "app": re.sub(r" \(.*\)$", "", proc) or "?",
        "user": user.group(1) if user else "",
        "target": m.get("host") or m.get("destinationIP") or "?",
        "ip": m.get("destinationIP", ""),
        "port": int(m.get("destinationPort") or 0),
        "network": m.get("network", ""),
        "outbound": (conn.get("chains") or ["?"])[0],
        "rule": conn.get("rule", ""),
        "start": start,
        "up": conn.get("upload", 0),
        "down": conn.get("download", 0),
    }


class Recorder:
    """Feeds API snapshots into the history db; tracks open connections and their speed."""

    def __init__(self, con):
        self.con = con
        self.open = {}  # id -> parsed conn, plus "rate_up"/"rate_down" in B/s
        self.last = None

    def update(self, conns, now):
        """Returns the connections that appeared since the last snapshot."""
        dt = now - self.last if self.last else 0
        self.last = now
        fresh, live = [], {}
        for raw in conns:
            x = parse_conn(raw)
            prev = self.open.get(x["id"])
            if prev is None:
                fresh.append(x)
                d_up, d_down = x["up"], x["down"]
                self.con.execute("INSERT OR IGNORE INTO conns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                 (x["id"], x["app"], x["user"], x["target"], x["ip"], x["port"],
                                  x["network"], x["outbound"], x["rule"], x["start"], now, x["up"], x["down"]))
            else:
                d_up, d_down = max(0, x["up"] - prev["up"]), max(0, x["down"] - prev["down"])
                self.con.execute("UPDATE conns SET end=?, up=?, down=? WHERE id=?",
                                 (now, x["up"], x["down"], x["id"]))
            x["rate_up"] = d_up / dt if dt and prev else 0
            x["rate_down"] = d_down / dt if dt and prev else 0
            record(self.con, x["app"], x["target"], x["port"], x["network"], x["outbound"],
                   now, 0 if prev else 1, d_up, d_down)
            live[x["id"]] = x
        self.open = live
        self.con.commit()
        return fresh


def poll(cfg, interval, on_update):
    addr, secret = cfg.api
    if not addr:
        die("clash_api not enabled; run: p2v setup")
    rec = Recorder(db())
    while True:
        try:
            conns = fetch_connections(addr, secret)
        except (urllib.error.URLError, OSError) as e:
            print(c(f"api unreachable ({e}); retrying...", 31))
            time.sleep(3)
            continue
        on_update(rec, rec.update(conns, time.time()))
        time.sleep(interval)


def short_app(app):
    return Path(app).name if "/" in app else app


def human(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n:.0f}{unit}"
        n /= 1024
    return f"{n:.1f}T"


def ago(ts):
    s = time.time() - ts
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if s >= n:
            return f"{int(s // n)}{unit}"
    return f"{int(s)}s"


# ---------------------------------------------------------------- commands

def cmd_setup(cfg, args):
    if cfg.setup():
        cfg.save()
        print(c("enabled clash_api and dns.reverse_mapping in ", 32) + str(cfg.path))
    else:
        print("config already set up")
    apply(cfg, args)


def cmd_watch(cfg, args):
    known = {(a, t) for a, t in db().execute("SELECT app, target FROM flows")}
    print(c(f"watching (Ctrl+C to stop) — {c('NEW', 33)} = never seen before", 2))

    def show(rec, fresh):
        for x in fresh:
            if (x["port"] == 53 and not args.dns) or (args.app and args.app not in x["app"]):
                continue
            key = (x["app"], x["target"])
            new = key not in known
            known.add(key)
            if new or not args.new:
                col = 32 if x["outbound"] != "direct" else 2
                print(f"{time.strftime('%H:%M:%S')} {c('NEW', 33) if new else '   '} "
                      f"{short_app(x['app']):<18} {x['target']}:{x['port']} {c('→ ' + x['outbound'], col)}"
                      + (c(f"  [{x['rule']}]", 2) if args.verbose else ""), flush=True)

    poll(cfg, args.interval, show)


def cmd_top(cfg, args):
    """Live per-app view of currently open connections, like nethogs."""
    vpn = set(cfg.items("process_path"))
    sort = {"speed": lambda a: -(a["rate_up"] + a["rate_down"]), "conns": lambda a: -a["n"],
            "traffic": lambda a: -(a["up"] + a["down"])}[args.sort]

    def show(rec, fresh):
        apps = {}
        for x in rec.open.values():
            if x["port"] == 53 and not args.dns:
                continue
            a = apps.setdefault(x["app"], {"app": x["app"], "n": 0, "up": 0, "down": 0,
                                           "rate_up": 0, "rate_down": 0, "targets": {}, "obs": set()})
            a["n"] += 1
            for k in ("up", "down", "rate_up", "rate_down"):
                a[k] += x[k]
            t = a["targets"].setdefault(x["target"], 0)
            a["targets"][x["target"]] = t + x["rate_up"] + x["rate_down"]
            a["obs"].add(x["outbound"])
        out = ["\033[H\033[J" if TTY else "",
               c(f"p2v top — {len(rec.open)} open connections, sorted by {args.sort}   "
                 f"{time.strftime('%H:%M:%S')}  (Ctrl+C)", 2),
               f"{'':2}{'APP':<22} {'OPEN':>4} {'↓/s':>7} {'↑/s':>7} {'↓ TOTAL':>8} {'↑ TOTAL':>8}  "
               f"{'OUT':<10} BUSIEST DOMAINS"]
        for a in sorted(apps.values(), key=sort)[:args.limit]:
            busy = sorted(a["targets"], key=a["targets"].get, reverse=True)[:3]
            mark = c("● ", 32) if a["app"] in vpn else "  "
            out.append(f"{mark}{short_app(a['app'])[:22]:<22} {a['n']:>4} {human(a['rate_down']):>7} "
                       f"{human(a['rate_up']):>7} {human(a['down']):>8} {human(a['up']):>8}  "
                       f"{','.join(sorted(a['obs']))[:10]:<10} {', '.join(busy)}")
        print("\n".join(out), flush=True)

    poll(cfg, args.interval, show)


def cmd_apps(cfg, args):
    con = db()
    vpn = set(cfg.items("process_path"))
    order = {"last": "max(last_seen)", "conns": "sum(hits)", "traffic": "sum(up+down)",
             "domains": "count(DISTINCT target)"}[args.sort]
    rows = con.execute(f"""SELECT app, count(DISTINCT target), sum(hits), sum(down), sum(up),
        min(first_seen), max(last_seen), group_concat(DISTINCT outbound) FROM flows WHERE port != 53
        GROUP BY app ORDER BY {order} DESC LIMIT ?""", (args.limit,)).fetchall()
    print(f"{'':2}{'APP':<45} {'DOMAINS':>7} {'CONNS':>6} {'↓':>7} {'↑':>7} {'FIRST':>5} {'LAST':>5}  OUTBOUND")
    for app, n, hits, down, up, first, last, obs in rows:
        mark = c("● ", 32) if app in vpn else "  "
        print(f"{mark}{app:<45} {n:>7} {hits:>6} {human(down or 0):>7} {human(up or 0):>7} "
              f"{ago(first):>5} {ago(last):>5}  {obs}")
    print(c(f"\nsorted by {args.sort} (--sort last|conns|traffic|domains)", 2), end="")
    print(c("\n● = routed via VPN by process_path", 2))


def cmd_domains(cfg, args):
    con = db()
    q = "SELECT app, target, port, outbound, hits, up+down, last_seen FROM flows WHERE 1"
    p = []
    if not args.dns:
        q += " AND port != 53"
    if args.app:
        q += " AND app LIKE ?"
        p.append(f"%{args.app}%")
    if args.direct:
        q += " AND outbound = 'direct'"
    order = {"last": "last_seen", "conns": "hits", "traffic": "up+down", "domains": "last_seen"}[args.sort]
    q += f" ORDER BY app, {order} DESC"
    vpn_domains = cfg.items("domain_suffix")
    cur = None
    for app, target, port, ob, hits, traffic, last in con.execute(q, p):
        if app != cur:
            cur = app
            print(c(f"\n{app}", 1))
        via = any(target == d or target.endswith("." + d) for d in vpn_domains)
        col = 32 if ob != "direct" else 2
        print(f"  {'●' if via else ' '} {target + ':' + str(port):<55} {c(ob, col):<10} "
              f"{hits:>5}x {human(traffic or 0):>7} {ago(last):>5} ago")


def resolve_app(con, name):
    """Match a name against known app paths; exact paths pass through."""
    if name.startswith("/"):
        return name
    apps = [a for (a,) in con.execute("SELECT DISTINCT app FROM flows") if name in a]
    exact = [a for a in apps if Path(a).name == name]
    if len(exact) == 1:
        return exact[0]
    if len(apps) == 1:
        return apps[0]
    if not apps:
        die(f"no app matching '{name}' in history; pass the full path")
    die(f"'{name}' is ambiguous:\n  " + "\n  ".join(apps))


def cmd_add(cfg, args):
    con = db()
    changed = False
    for v in args.values:
        key, val = ("domain_suffix", v.lower()) if args.kind == "domain" else ("process_path", resolve_app(con, v))
        if cfg.add(key, val):
            print(c("+ ", 32) + f"{key}: {val}")
            changed = True
        else:
            print(f"  already present: {val}")
    if changed:
        cfg.save()
        if not args.no_apply:
            apply(cfg, args)


def cmd_rm(cfg, args):
    changed = False
    key = "domain_suffix" if args.kind == "domain" else "process_path"
    for v in args.values:
        matches = [x for x in cfg.items(key) if x == v or (key == "process_path" and Path(x).name == v)]
        if not matches:
            print(f"  not in rules: {v}")
        for m in matches:
            cfg.remove(key, m)
            print(c("- ", 31) + f"{key}: {m}")
            changed = True
    if changed:
        cfg.save()
        if not args.no_apply:
            apply(cfg, args)


def cmd_rules(cfg, args):
    print(f"VPN outbound: {c(cfg.vpn_tag, 32)}    final: {cfg.data.get('route', {}).get('final')}")
    print(c("\napps (process_path):", 1))
    for a in cfg.items("process_path") or ["(none)"]:
        print(f"  {a}")
    print(c("\ndomains (domain_suffix):", 1))
    for d in cfg.items("domain_suffix") or ["(none)"]:
        print(f"  {d}")


LOG_ID = re.compile(r"\[(\d+) \d+m?s\] (.*)")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def cmd_import_log(cfg, args):
    """Best-effort history import from a sing-box log (correlates lines by connection id)."""
    conns = {}
    for line in Path(args.file).read_text(errors="replace").splitlines():
        m = LOG_ID.search(ANSI.sub("", line))
        if not m:
            continue
        info = conns.setdefault(m.group(1), {})
        msg = m.group(2)
        if r := re.search(r"inbound (?:packet )?connection to (\S+):(\d+)$", msg):
            info["target"], info["port"] = r.group(1), int(r.group(2))
        elif r := re.search(r"found process path: ([^,]+)", msg):
            info["app"] = r.group(1)
        elif r := re.search(r"sniffed (?:packet )?protocol: \w+, domain: ([^,\s]+)", msg):
            info["domain"] = r.group(1)
        elif r := re.search(r"outbound/\w+\[([^\]]+)\]", msg):
            info["outbound"] = r.group(1)
    con = db()
    mtime = Path(args.file).stat().st_mtime
    n = 0
    for info in conns.values():
        if "app" not in info or "target" not in info:
            continue
        record(con, info["app"], info.get("domain") or info["target"], info["port"], "",
               info.get("outbound", "?"), mtime)
        n += 1
    con.commit()
    print(f"imported {n} connections from {args.file}")


def main():
    ap = argparse.ArgumentParser(prog="p2v", description=__doc__.split("\n")[0])
    ap.add_argument("-c", "--config", default=os.environ.get("P2V_CONFIG", DEFAULT_CONFIG), type=Path)
    ap.add_argument("--singbox", default=DEFAULT_SINGBOX, type=Path, help="sing-box binary (if not running)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup", help="enable clash_api + dns reverse mapping, then reload")

    w = sub.add_parser("watch", help="live connections (records history)")
    w.add_argument("-a", "--app", help="only apps whose path contains this")
    w.add_argument("-n", "--new", action="store_true", help="only print never-seen app→domain pairs")
    w.add_argument("--dns", action="store_true", help="include DNS (port 53) flows")
    w.add_argument("-v", "--verbose", action="store_true", help="show matched rule")
    w.add_argument("-i", "--interval", type=float, default=0.5)

    t = sub.add_parser("top", help="live per-app speed / open connections")
    t.add_argument("-s", "--sort", choices=["speed", "conns", "traffic"], default="speed")
    t.add_argument("-l", "--limit", type=int, default=30)
    t.add_argument("--dns", action="store_true")
    t.add_argument("-i", "--interval", type=float, default=1)

    sorts = ["last", "conns", "traffic", "domains"]
    a = sub.add_parser("apps", help="apps seen so far")
    a.add_argument("-s", "--sort", choices=sorts, default="last")
    a.add_argument("-l", "--limit", type=int, default=50)

    d = sub.add_parser("domains", help="domains per app from history")
    d.add_argument("app", nargs="?", help="filter by app path substring")
    d.add_argument("--direct", action="store_true", help="only flows that went direct")
    d.add_argument("-s", "--sort", choices=sorts, default="last")
    d.add_argument("--dns", action="store_true")

    for name, fn in (("add", cmd_add), ("rm", cmd_rm)):
        p = sub.add_parser(name, help=f"{name} app/domain {'to' if name == 'add' else 'from'} VPN route, then reload")
        p.add_argument("kind", choices=["app", "domain"])
        p.add_argument("values", nargs="+", help="app name/path, or domain suffix")
        p.add_argument("--no-apply", action="store_true", help="edit config only, don't reload")

    sub.add_parser("rules", help="show current VPN rules")
    sub.add_parser("apply", help="check config and reload sing-box")
    il = sub.add_parser("import-log", help="import history from a sing-box log file")
    il.add_argument("file", nargs="?", default=STATE_DIR / "sing-box.log")

    args = ap.parse_args()
    cfg = Config(args.config)
    {"setup": cmd_setup, "watch": cmd_watch, "top": cmd_top, "apps": cmd_apps, "domains": cmd_domains,
     "add": cmd_add, "rm": cmd_rm, "rules": cmd_rules, "apply": apply,
     "import-log": cmd_import_log}[args.cmd](cfg, args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
