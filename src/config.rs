//! The sing-box config: VPN routing rules plus the Clash API settings the app relies on.

use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const APP_KEY: &str = "process_path";
pub const DOMAIN_KEY: &str = "domain_suffix";
const DEFAULT_API: &str = "127.0.0.1:9090";

pub struct Config {
    pub path: PathBuf,
    pub data: Value,
}

fn obj(v: &mut Value) -> &mut Map<String, Value> {
    if !v.is_object() {
        *v = json!({});
    }
    v.as_object_mut().unwrap()
}

fn child<'a>(v: &'a mut Value, key: &str) -> &'a mut Value {
    obj(v).entry(key).or_insert_with(|| json!({}))
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let data = serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        Ok(Self { path: path.to_owned(), data })
    }

    pub fn save(&self) -> Result<(), String> {
        let _ = fs::copy(&self.path, self.path.with_extension("json.bak"));
        let text = serde_json::to_string_pretty(&self.data).unwrap() + "\n";
        fs::write(&self.path, text).map_err(|e| format!("write {}: {e}", self.path.display()))
    }

    /// First outbound that isn't direct/block/dns.
    pub fn vpn_tag(&self) -> Option<String> {
        self.data["outbounds"].as_array()?.iter().find_map(|ob| {
            let t = ob["type"].as_str().unwrap_or("");
            if matches!(t, "direct" | "block" | "dns") {
                None
            } else {
                ob["tag"].as_str().map(str::to_owned)
            }
        })
    }

    /// (external_controller, secret) of the Clash API.
    pub fn api(&self) -> (String, String) {
        let api = &self.data["experimental"]["clash_api"];
        let s = |k: &str| api[k].as_str().unwrap_or("").to_owned();
        (s("external_controller"), s("secret"))
    }

    pub fn final_outbound(&self) -> String {
        self.data["route"]["final"].as_str().unwrap_or("?").to_owned()
    }

    fn rules(&self) -> &[Value] {
        self.data["route"]["rules"].as_array().map(Vec::as_slice).unwrap_or(&[])
    }

    fn rules_mut(&mut self) -> &mut Vec<Value> {
        let rules = obj(child(&mut self.data, "route")).entry("rules").or_insert_with(|| json!([]));
        if !rules.is_array() {
            *rules = json!([]);
        }
        rules.as_array_mut().unwrap()
    }

    /// Index of the VPN rule that matches only on `key`.
    fn rule_index(&self, key: &str, vpn: &str) -> Option<usize> {
        self.rules().iter().position(|r| {
            r["outbound"].as_str() == Some(vpn) && r.get(key).is_some() && r.as_object().map(Map::len) == Some(2)
        })
    }

    pub fn items(&self, key: &str) -> Vec<String> {
        let Some(vpn) = self.vpn_tag() else { return vec![] };
        let Some(i) = self.rule_index(key, &vpn) else { return vec![] };
        match &self.rules()[i][key] {
            Value::Array(a) => a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect(),
            Value::String(s) => vec![s.clone()],
            _ => vec![],
        }
    }

    pub fn add(&mut self, key: &str, value: &str) -> Result<bool, String> {
        let vpn = self.vpn_tag().ok_or("no proxy outbound found in config")?;
        let i = match self.rule_index(key, &vpn) {
            Some(i) => i,
            None => {
                // keep sniff / hijack-dns / resolve rules in front
                let rules = self.rules_mut();
                let idx = rules
                    .iter()
                    .rposition(|r| matches!(r["action"].as_str(), Some("sniff" | "hijack-dns" | "resolve")))
                    .map_or(0, |i| i + 1);
                let mut rule = Map::new();
                rule.insert(key.into(), json!([]));
                rule.insert("outbound".into(), json!(vpn));
                rules.insert(idx, Value::Object(rule));
                idx
            }
        };
        let list = &mut self.rules_mut()[i][key];
        if let Value::String(s) = list {
            *list = json!([s.clone()]);
        }
        let list = list.as_array_mut().ok_or("rule list is not an array")?;
        if list.iter().any(|v| v.as_str() == Some(value)) {
            return Ok(false);
        }
        list.push(json!(value));
        Ok(true)
    }

    pub fn remove(&mut self, key: &str, value: &str) -> bool {
        let Some(vpn) = self.vpn_tag() else { return false };
        let Some(i) = self.rule_index(key, &vpn) else { return false };
        let rules = self.rules_mut();
        let removed = match &mut rules[i][key] {
            Value::Array(a) => {
                let n = a.len();
                a.retain(|v| v.as_str() != Some(value));
                a.len() != n
            }
            Value::String(s) if s == value => {
                rules[i][key] = json!([]);
                true
            }
            _ => false,
        };
        if rules[i][key].as_array().is_some_and(Vec::is_empty) {
            rules.remove(i);
        }
        removed
    }

    /// Enable the Clash API and DNS reverse mapping. Returns true if anything changed.
    pub fn setup(&mut self) -> bool {
        let mut changed = false;
        let api = obj(child(child(&mut self.data, "experimental"), "clash_api"));
        if api.get("external_controller").and_then(Value::as_str).unwrap_or("").is_empty() {
            api.insert("external_controller".into(), json!(DEFAULT_API));
            changed = true;
        }
        if api.get("secret").and_then(Value::as_str).unwrap_or("").is_empty() {
            api.insert("secret".into(), json!(random_hex(16)));
            changed = true;
        }
        let dns = obj(child(&mut self.data, "dns"));
        if dns.get("reverse_mapping").and_then(Value::as_bool) != Some(true) {
            // map IPs back to the resolved domain, for traffic that can't be sniffed
            dns.insert("reverse_mapping".into(), json!(true));
            changed = true;
        }
        changed
    }
}

fn random_hex(n: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; n];
    let _ = fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf));
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        Config { path: "/dev/null".into(), data: serde_json::from_str(crate::EXAMPLE_CONFIG).unwrap() }
    }

    #[test]
    fn add_and_remove_apps() {
        let mut c = cfg();
        assert_eq!(c.vpn_tag().as_deref(), Some("xray-proxy"));
        let before = c.items(APP_KEY);
        assert!(c.add(APP_KEY, "/usr/bin/curl").unwrap());
        assert!(!c.add(APP_KEY, "/usr/bin/curl").unwrap());
        assert_eq!(c.items(APP_KEY).len(), before.len() + 1);
        assert!(c.remove(APP_KEY, "/usr/bin/curl"));
        assert_eq!(c.items(APP_KEY), before);
    }

    #[test]
    fn domain_rule_created_after_sniff_and_dropped_when_empty() {
        let mut c = cfg();
        let n = c.rules().len();
        assert!(c.add(DOMAIN_KEY, "example.com").unwrap());
        assert_eq!(c.rules()[2][DOMAIN_KEY][0], "example.com");
        assert!(c.remove(DOMAIN_KEY, "example.com"));
        assert_eq!(c.rules().len(), n);
    }

    #[test]
    fn setup_fills_secret() {
        let mut c = cfg();
        assert!(c.setup());
        assert_eq!(c.api().1.len(), 32);
        assert!(!c.setup());
    }
}
