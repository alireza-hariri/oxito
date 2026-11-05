//! SQLite history of what each app connected to through sing-box (same schema as the old oxito.py).
//! It only covers the current session: recreated at startup and pruned to the activity window.

use crate::clash::Conn;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default)]
pub struct AppHistory {
    pub app: String,
    pub domains: usize,
    pub hits: u64,
    pub up: u64,
    pub down: u64,
    pub last_seen: f64,
    pub outbounds: String,
}

#[derive(Clone, Debug)]
pub struct Flow {
    pub target: String,
    pub port: u16,
    pub outbound: String,
    pub hits: u64,
    pub traffic: u64,
    pub last_seen: f64,
}

pub fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Delete the db (and its WAL files) and open an empty one.
pub fn open_fresh(path: &Path) -> rusqlite::Result<Connection> {
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
    open(path)
}

/// Drop everything not seen within the last `secs` seconds.
pub fn prune(con: &Connection, secs: u64) -> rusqlite::Result<()> {
    let cutoff = now() - secs as f64;
    con.execute("DELETE FROM flows WHERE last_seen < ?", [cutoff])?;
    con.execute("DELETE FROM conns WHERE end < ?", [cutoff])?;
    Ok(())
}

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let con = Connection::open(path)?;
    con.busy_timeout(std::time::Duration::from_secs(2))?;
    con.execute_batch(
        "PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS flows (
            app TEXT, target TEXT, port INTEGER, network TEXT, outbound TEXT,
            first_seen REAL, last_seen REAL, hits INTEGER DEFAULT 0,
            up INTEGER DEFAULT 0, down INTEGER DEFAULT 0,
            PRIMARY KEY (app, target, port));
        CREATE TABLE IF NOT EXISTS conns (
            id TEXT PRIMARY KEY, app TEXT, user TEXT, target TEXT, ip TEXT, port INTEGER,
            network TEXT, outbound TEXT, rule TEXT, start REAL, end REAL,
            up INTEGER DEFAULT 0, down INTEGER DEFAULT 0);
        CREATE INDEX IF NOT EXISTS conns_app ON conns(app, start);",
    )?;
    Ok(con)
}

/// Store one Clash API snapshot. A connection already in the db (e.g. after an app restart)
/// isn't counted twice: its byte deltas are taken against what was stored.
pub fn record(con: &mut Connection, conns: &[Conn]) -> rusqlite::Result<()> {
    let ts = now();
    let tx = con.transaction()?;
    for c in conns {
        let (mut hit, mut d_up, mut d_down) = (0u64, c.d_up, c.d_down);
        if c.new {
            let stored: Option<(u64, u64)> = tx
                .query_row("SELECT up, down FROM conns WHERE id=?", [&c.id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            match stored {
                Some((u, d)) => (d_up, d_down) = (c.up.saturating_sub(u), c.down.saturating_sub(d)),
                None => {
                    hit = 1;
                    tx.execute(
                        "INSERT INTO conns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        params![c.id, c.app, c.user, c.host, c.ip, c.port, c.network, c.outbound, c.rule, ts, ts, c.up, c.down],
                    )?;
                }
            }
        }
        tx.execute("UPDATE conns SET end=?, up=?, down=? WHERE id=?", params![ts, c.up, c.down, c.id])?;
        tx.execute(
            "INSERT INTO flows VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(app, target, port) DO UPDATE SET
              last_seen=max(last_seen, excluded.last_seen),
              first_seen=min(first_seen, excluded.first_seen),
              outbound=excluded.outbound, network=excluded.network,
              hits=hits+excluded.hits, up=up+excluded.up, down=down+excluded.down",
            params![c.app, c.host, c.port, c.network, c.outbound, ts, ts, hit, d_up, d_down],
        )?;
    }
    tx.commit()
}

/// Per-app totals, DNS (port 53) excluded.
pub fn apps(con: &Connection) -> rusqlite::Result<Vec<AppHistory>> {
    let mut st = con.prepare_cached(
        "SELECT app, count(DISTINCT target), sum(hits), sum(up), sum(down), max(last_seen),
                group_concat(DISTINCT outbound)
         FROM flows WHERE port != 53 GROUP BY app",
    )?;
    let rows = st.query_map([], |r| {
        Ok(AppHistory {
            app: r.get(0)?,
            domains: r.get::<_, i64>(1)? as usize,
            hits: r.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
            up: r.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
            down: r.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64,
            last_seen: r.get::<_, Option<f64>>(5)?.unwrap_or(0.0),
            outbounds: r.get::<_, Option<String>>(6)?.unwrap_or_default(),
        })
    })?;
    rows.collect()
}

/// Everything one app has connected to, most recent first.
pub fn flows(con: &Connection, app: &str) -> rusqlite::Result<Vec<Flow>> {
    let mut st = con.prepare_cached(
        "SELECT target, port, outbound, hits, up+down, last_seen FROM flows
         WHERE app = ? AND port != 53 ORDER BY last_seen DESC LIMIT 500",
    )?;
    let rows = st.query_map([app], |r| {
        Ok(Flow {
            target: r.get(0)?,
            port: r.get::<_, i64>(1)? as u16,
            outbound: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            hits: r.get::<_, i64>(3)? as u64,
            traffic: r.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64,
            last_seen: r.get(5)?,
        })
    })?;
    rows.collect()
}

pub fn forget(con: &Connection, app: &str) -> rusqlite::Result<()> {
    con.execute("DELETE FROM flows WHERE app = ?", [app])?;
    con.execute("DELETE FROM conns WHERE app = ?", [app])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: &str, app: &str, host: &str, up: u64, new: bool) -> Conn {
        Conn {
            id: id.into(),
            app: app.into(),
            user: "me".into(),
            host: host.into(),
            ip: String::new(),
            port: 443,
            network: "tcp".into(),
            outbound: "direct".into(),
            rule: String::new(),
            up,
            down: 0,
            rate_up: 0.0,
            rate_down: 0.0,
            d_up: if new { up } else { 0 },
            d_down: 0,
            new,
        }
    }

    #[test]
    fn record_counts_once_and_prunes() {
        let path = std::env::temp_dir().join(format!("oxito-test-{}.db", std::process::id()));
        let mut con = open_fresh(&path).unwrap();
        record(&mut con, &[conn("1", "/usr/bin/a", "x.com", 10, true)]).unwrap();
        record(&mut con, &[conn("1", "/usr/bin/a", "x.com", 10, false)]).unwrap();
        // the same connection seen as "new" again (app restart) must not count twice
        record(&mut con, &[conn("1", "/usr/bin/a", "x.com", 25, true), conn("2", "/usr/bin/b", "y.com", 5, true)])
            .unwrap();
        let mut apps = apps(&con).unwrap();
        apps.sort_by(|a, b| a.app.cmp(&b.app));
        assert_eq!((apps[0].hits, apps[0].up), (1, 25));
        assert_eq!(apps[1].app, "/usr/bin/b");
        con.execute("UPDATE flows SET last_seen = last_seen - 600 WHERE app = '/usr/bin/b'", []).unwrap();
        prune(&con, 300).unwrap();
        assert_eq!(super::apps(&con).unwrap().len(), 1);
        drop(con);
        assert!(open_fresh(&path).map(|c| super::apps(&c).unwrap().is_empty()).unwrap());
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }
}
