//! Live connections from sing-box's Clash API, with per-connection transfer rates.

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct Conn {
    pub id: String,
    /// Process path without sing-box's " (user)" suffix.
    pub app: String,
    /// Owner of the process, from sing-box's " (user)" suffix.
    pub user: String,
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub network: String,
    pub outbound: String,
    pub rule: String,
    pub up: u64,
    pub down: u64,
    pub rate_up: f64,
    pub rate_down: f64,
    /// Bytes since the previous poll (the whole total for a new connection).
    pub d_up: u64,
    pub d_down: u64,
    /// First time this connection showed up.
    pub new: bool,
}

#[derive(Deserialize)]
struct Resp {
    connections: Option<Vec<RawConn>>,
}

#[derive(Deserialize)]
struct RawConn {
    id: String,
    #[serde(default)]
    metadata: HashMap<String, Value>,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    rule: String,
}

/// Plain HTTP/1.0 request; the controller is always local, so no client crate is needed.
fn request(method: &str, addr: &str, path: &str, secret: &str) -> Result<String, String> {
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("bad api address")?;
    let mut s =
        TcpStream::connect_timeout(&sock, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok();
    write!(
        s,
        "{method} {path} HTTP/1.0\r\nHost: {addr}\r\nAuthorization: Bearer {secret}\r\n\r\n"
    )
    .map_err(|e| e.to_string())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    let (head, body) = buf.split_once("\r\n\r\n").ok_or("malformed response")?;
    let status = head.lines().next().unwrap_or("");
    if !status.contains(" 200") && !status.contains(" 204") {
        return Err(format!("api: {status}"));
    }
    Ok(body.to_owned())
}

/// Close one connection, so the app reconnects and gets routed by the current rules.
pub fn close(addr: &str, secret: &str, id: &str) -> Result<(), String> {
    request("DELETE", addr, &format!("/connections/{id}"), secret).map(drop)
}

#[derive(Default)]
pub struct Tracker {
    prev: HashMap<String, (u64, u64)>,
    last: Option<Instant>,
}

impl Tracker {
    pub fn poll(&mut self, addr: &str, secret: &str) -> Result<Vec<Conn>, String> {
        let body = request("GET", addr, "/connections", secret)?;
        let resp: Resp = serde_json::from_str(&body).map_err(|e| e.to_string())?;
        let now = Instant::now();
        let dt = self.last.map(|l| (now - l).as_secs_f64()).unwrap_or(0.0);
        self.last = Some(now);
        let mut seen = HashMap::new();
        let conns = resp
            .connections
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                let m = |k: &str| match c.metadata.get(k) {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Number(n)) => n.to_string(),
                    _ => String::new(),
                };
                let proc_path = m("processPath");
                let (app, user) = match proc_path.rfind(" (") {
                    Some(i) if proc_path.ends_with(')') => (
                        proc_path[..i].to_owned(),
                        proc_path[i + 2..proc_path.len() - 1].to_owned(),
                    ),
                    _ => (proc_path, String::new()),
                };
                let prev = self.prev.get(&c.id).copied();
                let (d_up, d_down) = match prev {
                    Some((u, d)) => (c.upload.saturating_sub(u), c.download.saturating_sub(d)),
                    None => (c.upload, c.download),
                };
                let (rate_up, rate_down) = if prev.is_some() && dt > 0.0 {
                    (d_up as f64 / dt, d_down as f64 / dt)
                } else {
                    (0.0, 0.0)
                };
                seen.insert(c.id.clone(), (c.upload, c.download));
                let host = Some(m("host"))
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| m("destinationIP"));
                Conn {
                    id: c.id,
                    app,
                    user,
                    host,
                    ip: m("destinationIP"),
                    port: m("destinationPort").parse().unwrap_or(0),
                    network: m("network"),
                    outbound: c.chains.first().cloned().unwrap_or_default(),
                    rule: c.rule,
                    up: c.upload,
                    down: c.download,
                    rate_up,
                    rate_down,
                    d_up,
                    d_down,
                    new: prev.is_none(),
                }
            })
            .collect();
        self.prev = seen;
        Ok(conns)
    }
}
