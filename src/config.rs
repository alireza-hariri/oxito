//! The sing-box config plus the rule-set file holding the VPN routing rules.
//!
//! The routed apps/domains live in a local source rule-set next to the config. sing-box watches
//! that file and swaps the rules in place when it changes, so routing edits need no restart (a
//! restart would re-create the TUN and drop every connection). The config itself only has to
//! reference the rule-set once.

use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const APP_KEY: &str = "process_path";
pub const DOMAIN_KEY: &str = "domain_suffix";
pub const RULE_SET_TAG: &str = "oxito";
const DEFAULT_API: &str = "127.0.0.1:9090";

pub struct Config {
    pub path: PathBuf,
    pub data: Value,
    /// The rule-set file sing-box watches.
    pub rules_path: PathBuf,
    /// Its contents: `{"version": 2, "rules": [{"process_path": [..]}, {"domain_suffix": [..]}]}`.
    pub rules: Value,
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

fn array<'a>(m: &'a mut Map<String, Value>, key: &str) -> &'a mut Vec<Value> {
    let v = m.entry(key).or_insert_with(|| json!([]));
    if !v.is_array() {
        *v = json!([]);
    }
    v.as_array_mut().unwrap()
}

fn list_items(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

fn empty_rules() -> Value {
    json!({ "version": 2, "rules": [] })
}

/// `config.json` -> `config.rules.json`
pub fn rules_path(config: &Path) -> PathBuf {
    config.with_extension("rules.json")
}

impl Config {
    pub fn new(path: &Path, data: Value) -> Self {
        Self {
            path: path.to_owned(),
            data,
            rules_path: rules_path(path),
            rules: empty_rules(),
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let data =
            serde_json::from_str(&text).map_err(|e| format!("parse {}: {e}", path.display()))?;
        let mut cfg = Self::new(path, data);
        if let Ok(text) = fs::read_to_string(&cfg.rules_path) {
            cfg.rules = serde_json::from_str(&text)
                .map_err(|e| format!("parse {}: {e}", cfg.rules_path.display()))?;
        }
        Ok(cfg)
    }

    pub fn save(&self) -> Result<(), String> {
        let _ = fs::copy(&self.path, self.path.with_extension("json.bak"));
        let text = serde_json::to_string_pretty(&self.data).unwrap() + "\n";
        fs::write(&self.path, text).map_err(|e| format!("write {}: {e}", self.path.display()))
    }

    /// Write the rule-set atomically, so sing-box never reloads a half-written file.
    pub fn save_rules(&self) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&self.rules).unwrap() + "\n";
        let tmp = self.rules_path.with_extension("json.tmp");
        fs::write(&tmp, text)
            .and_then(|_| fs::rename(&tmp, &self.rules_path))
            .map_err(|e| format!("write {}: {e}", self.rules_path.display()))
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
        self.data["route"]["final"]
            .as_str()
            .unwrap_or("?")
            .to_owned()
    }

    fn route_rules(&self) -> &[Value] {
        self.data["route"]["rules"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    fn route_rules_mut(&mut self) -> &mut Vec<Value> {
        array(obj(child(&mut self.data, "route")), "rules")
    }

    /// Index of the old-style VPN rule in the config that matches only on `key`.
    fn route_rule_index(&self, key: &str, vpn: &str) -> Option<usize> {
        self.route_rules().iter().position(|r| {
            r["outbound"].as_str() == Some(vpn)
                && r.get(key).is_some()
                && r.as_object().map(Map::len) == Some(2)
        })
    }

    fn set_rules_mut(&mut self) -> &mut Vec<Value> {
        array(obj(&mut self.rules), "rules")
    }

    /// Index of the rule-set rule that matches only on `key`.
    fn rule_index(&self, key: &str) -> Option<usize> {
        self.rules["rules"]
            .as_array()?
            .iter()
            .position(|r| r.get(key).is_some() && r.as_object().map(Map::len) == Some(1))
    }

    pub fn items(&self, key: &str) -> Vec<String> {
        let Some(i) = self.rule_index(key) else {
            return vec![];
        };
        list_items(&self.rules["rules"][i][key])
    }

    pub fn add(&mut self, key: &str, value: &str) -> Result<bool, String> {
        let i = match self.rule_index(key) {
            Some(i) => i,
            None => {
                let rules = self.set_rules_mut();
                rules.push(json!({ key: [] }));
                rules.len() - 1
            }
        };
        let list = &mut self.set_rules_mut()[i][key];
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
        let Some(i) = self.rule_index(key) else {
            return false;
        };
        let rules = self.set_rules_mut();
        let n = list_items(&rules[i][key]).len();
        let rest: Vec<String> = list_items(&rules[i][key])
            .into_iter()
            .filter(|v| v != value)
            .collect();
        if rest.len() == n {
            return false;
        }
        if rest.is_empty() {
            rules.remove(i);
        } else {
            rules[i][key] = json!(rest);
        }
        true
    }

    /// Enable the Clash API, DNS reverse mapping and process lookup, and route through our
    /// rule-set, moving any old in-config app/domain rules into it. Returns true if the config
    /// changed (the rule-set may change too; save both).
    pub fn setup(&mut self) -> bool {
        let mut changed = self.setup_rule_set();
        let api = obj(child(child(&mut self.data, "experimental"), "clash_api"));
        if api
            .get("external_controller")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            api.insert("external_controller".into(), json!(DEFAULT_API));
            changed = true;
        }
        if api
            .get("secret")
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            api.insert("secret".into(), json!(random_hex(16)));
            changed = true;
        }
        let dns = obj(child(&mut self.data, "dns"));
        if dns.get("reverse_mapping").and_then(Value::as_bool) != Some(true) {
            // map IPs back to the resolved domain, for traffic that can't be sniffed
            dns.insert("reverse_mapping".into(), json!(true));
            changed = true;
        }
        let route = obj(child(&mut self.data, "route"));
        if route.get("find_process").and_then(Value::as_bool) != Some(true) {
            // sing-box decides at startup whether to look up processes, from the rules it has
            // then; the rule-set may start out empty, so ask for it explicitly
            route.insert("find_process".into(), json!(true));
            changed = true;
        }
        changed
    }

    fn setup_rule_set(&mut self) -> bool {
        let Some(vpn) = self.vpn_tag() else {
            return false;
        };
        let mut changed = false;
        for key in [APP_KEY, DOMAIN_KEY] {
            if let Some(i) = self.route_rule_index(key, &vpn) {
                let rule = self.route_rules_mut().remove(i);
                for v in list_items(&rule[key]) {
                    let _ = self.add(key, &v);
                }
                changed = true;
            }
        }
        let path = self.rules_path.to_string_lossy().into_owned();
        let entry =
            json!({ "tag": RULE_SET_TAG, "type": "local", "format": "source", "path": path });
        let sets = array(obj(child(&mut self.data, "route")), "rule_set");
        match sets
            .iter_mut()
            .find(|s| s["tag"].as_str() == Some(RULE_SET_TAG))
        {
            Some(s) if *s == entry => {}
            Some(s) => {
                *s = entry;
                changed = true;
            }
            None => {
                sets.push(entry);
                changed = true;
            }
        }
        let rule = json!({ "rule_set": RULE_SET_TAG, "outbound": vpn });
        if !self.route_rules().contains(&rule) {
            let rules = self.route_rules_mut();
            rules.retain(|r| r["rule_set"].as_str() != Some(RULE_SET_TAG));
            // keep sniff / hijack-dns / resolve rules in front
            let idx = rules
                .iter()
                .rposition(|r| {
                    matches!(
                        r["action"].as_str(),
                        Some("sniff" | "hijack-dns" | "resolve")
                    )
                })
                .map_or(0, |i| i + 1);
            rules.insert(idx, rule);
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
        Config::new(
            Path::new("/tmp/oxito/config.json"),
            serde_json::from_str(crate::EXAMPLE_CONFIG).unwrap(),
        )
    }

    #[test]
    fn setup_moves_rules_into_rule_set() {
        let mut c = cfg();
        assert!(c.setup());
        assert_eq!(c.items(APP_KEY).len(), 2);
        let route = &c.data["route"];
        assert_eq!(
            route["rules"][2],
            json!({ "rule_set": RULE_SET_TAG, "outbound": "xray-proxy" })
        );
        assert!(route["rules"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get(APP_KEY).is_none()));
        assert_eq!(route["rule_set"][0]["path"], "/tmp/oxito/config.rules.json");
        assert_eq!(route["find_process"], true);
        assert!(!c.setup());
    }

    #[test]
    fn add_and_remove_apps() {
        let mut c = cfg();
        c.setup();
        let before = c.items(APP_KEY);
        assert!(c.add(APP_KEY, "/usr/bin/curl").unwrap());
        assert!(!c.add(APP_KEY, "/usr/bin/curl").unwrap());
        assert_eq!(c.items(APP_KEY).len(), before.len() + 1);
        assert!(c.remove(APP_KEY, "/usr/bin/curl"));
        assert_eq!(c.items(APP_KEY), before);
    }

    #[test]
    fn domain_rule_dropped_when_empty() {
        let mut c = cfg();
        c.setup();
        assert!(c.add(DOMAIN_KEY, "example.com").unwrap());
        assert_eq!(c.rules["rules"][1], json!({ DOMAIN_KEY: ["example.com"] }));
        assert!(c.remove(DOMAIN_KEY, "example.com"));
        assert_eq!(c.rules["rules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn setup_fills_secret() {
        let mut c = cfg();
        assert!(c.setup());
        assert_eq!(c.api().1.len(), 32);
        assert!(!c.setup());
    }
}
