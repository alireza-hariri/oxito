//! oxito - see running apps and their traffic through sing-box, and pick which ones go via the VPN.

mod app;
mod appicon;
mod clash;
mod config;
mod history;
mod icon;
mod monitor;
mod procs;
mod singbox;
mod single;

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const EXAMPLE_CONFIG: &str = include_str!("../example_config.json");

pub struct Paths {
    pub config: PathBuf,
    pub settings: PathBuf,
    pub state: PathBuf,
}

fn paths() -> Result<Paths, String> {
    let home = singbox::home();
    let conf_dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or(home.join(".config"));
    let conf_dir = conf_dir.join("oxito");
    let mut config = conf_dir.join("config.json");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => config = args.next().ok_or("--config needs a path")?.into(),
            "-h" | "--help" => {
                println!(
                    "usage: oxito [-c CONFIG]\n\nCONFIG defaults to {}",
                    config.display()
                );
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument: {a}")),
        }
    }
    if !config.exists() {
        // first run: seed the working config from the bundled example
        fs::create_dir_all(config.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(&config, EXAMPLE_CONFIG)
            .map_err(|e| format!("write {}: {e}", config.display()))?;
    }
    Ok(Paths {
        config,
        settings: conf_dir.join("settings.json"),
        state: home.join(".local/state/oxito"),
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
    if let Err(e) = fs::create_dir_all(&paths.state) {
        eprintln!("error: creating {}: {e}", paths.state.display());
        std::process::exit(1);
    }
    let socket = paths.state.join("ui.sock");
    // the UI's egui context, filled in once the app is created; a second instance's "show"
    // request needs it to bring the (maybe hidden) window back
    let ctx_slot: Arc<Mutex<Option<eframe::egui::Context>>> = Arc::default();
    if let Err(e) = single::primary_or_notify(&socket, {
        let slot = ctx_slot.clone();
        move || {
            if let Some(ctx) = slot.lock().unwrap().clone() {
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Visible(true));
                ctx.send_viewport_cmd(eframe::egui::ViewportCommand::Focus);
                ctx.request_repaint();
            }
        }
    }) {
        eprintln!("{e}");
        std::process::exit(0);
    }
    let opts = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("oxito")
            .with_app_id("oxito")
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
    let res = eframe::run_native(
        "oxito",
        opts,
        Box::new(|cc| Ok(Box::new(app::App::new(cc, paths, ctx_slot)))),
    );
    single::cleanup(&socket);
    res
}
