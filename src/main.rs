//! proxy2vpn - see running apps and their traffic through sing-box, and pick which ones go via the VPN.

mod app;
mod clash;
mod config;
mod history;
mod icon;
mod monitor;
mod procs;
mod singbox;

use std::fs;
use std::path::PathBuf;

const EXAMPLE_CONFIG: &str = include_str!("../example_config.json");

pub struct Paths {
    pub config: PathBuf,
    pub settings: PathBuf,
    pub state: PathBuf,
}

fn paths() -> Result<Paths, String> {
    let home = singbox::home();
    let conf_dir = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or(home.join(".config"));
    let conf_dir = conf_dir.join("proxy2vpn");
    let mut config = conf_dir.join("config.json");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config = args.next().ok_or("--config needs a path")?.into(),
            "-h" | "--help" => {
                println!("usage: proxy2vpn [-c CONFIG]\n\nCONFIG defaults to {}", config.display());
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {a}")),
        }
    }
    if !config.exists() {
        // first run: seed the working config from the bundled example
        fs::create_dir_all(config.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(&config, EXAMPLE_CONFIG).map_err(|e| format!("write {}: {e}", config.display()))?;
    }
    Ok(Paths {
        config,
        settings: conf_dir.join("settings.json"),
        state: home.join(".local/state/proxy2vpn"),
    })
}

fn main() -> eframe::Result {
    let paths = match paths() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let opts = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("proxy2vpn")
            .with_app_id("proxy2vpn")
            .with_inner_size(app::saved_window_size(&paths))
            .with_icon(icon::icon_data(false)),
        // X11 (XWayland on Wayland): native Wayland can't hide the window to the tray or bring it
        // back, and ignores the window icon
        event_loop_builder: Some(Box::new(|b| {
            use winit::platform::x11::EventLoopBuilderExtX11;
            b.with_x11();
        })),
        ..Default::default()
    };
    eframe::run_native("proxy2vpn", opts, Box::new(|cc| Ok(Box::new(app::App::new(cc, paths)))))
}
