//! The app icon (`assets/oxito.svg`): green while sing-box runs this app's config, blue
//! otherwise. Shown as the window icon and as a tray icon; the tray brings back a window hidden
//! with Esc.

use eframe::egui::{self, IconData, ViewportCommand};
use std::sync::{Arc, Mutex};

const SVG: &str = include_str!("../assets/oxito.svg");
/// (blue as in the svg, green replacement): gradient top, gradient bottom / arrow.
const RECOLOR: [(&str, &str); 2] = [("#4a90e2", "#3fbf74"), ("#2a5fae", "#23874c")];

/// RGBA pixels, `size` x `size`.
pub fn render(on: bool, size: u32) -> Vec<u8> {
    let mut svg = SVG.to_owned();
    if on {
        for (blue, green) in RECOLOR {
            svg = svg.replace(blue, green);
        }
    }
    let tree = resvg::usvg::Tree::from_str(&svg, &Default::default()).expect("bundled svg is valid");
    let mut pixmap = resvg::tiny_skia::Pixmap::new(size, size).unwrap();
    let scale = size as f32 / tree.size().width();
    resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(scale, scale), &mut pixmap.as_mut());
    pixmap.pixels().iter().flat_map(|p| {
        let c = p.demultiply();
        [c.red(), c.green(), c.blue(), c.alpha()]
    }).collect()
}

pub fn icon_data(on: bool) -> IconData {
    IconData { rgba: render(on, 64), width: 64, height: 64 }
}

// ------------------------------------------------------------ tray

struct Tray {
    on: bool,
    ctx: egui::Context,
}

impl Tray {
    fn show(&self) {
        self.ctx.send_viewport_cmd(ViewportCommand::Visible(true));
        self.ctx.send_viewport_cmd(ViewportCommand::Minimized(false));
        self.ctx.send_viewport_cmd(ViewportCommand::Focus);
        self.ctx.request_repaint();
    }
}

impl ksni::Tray for Tray {
    fn id(&self) -> String {
        "oxito".into()
    }

    fn title(&self) -> String {
        "oxito".into()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        [32, 64, 128]
            .into_iter()
            .map(|size| {
                // RGBA -> ARGB
                let mut data = render(self.on, size as u32);
                for p in data.chunks_exact_mut(4) {
                    p.rotate_right(1);
                }
                ksni::Icon { width: size, height: size, data }
            })
            .collect()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let description = if self.on { "sing-box running" } else { "sing-box not running" }.into();
        ksni::ToolTip { title: "oxito".into(), description, ..Default::default() }
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        self.show();
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem { label: "Show".into(), activate: Box::new(|t: &mut Self| t.show()), ..Default::default() }
                .into(),
            StandardItem {
                label: "Quit".into(),
                activate: Box::new(|t: &mut Self| {
                    t.ctx.send_viewport_cmd(ViewportCommand::Close);
                    t.ctx.request_repaint();
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

/// Keeps the window and tray icons in step with whether sing-box is on. Cheap to clone, so the
/// monitor thread can update it while the window is hidden.
#[derive(Clone)]
pub struct Indicator {
    on: Arc<Mutex<Option<bool>>>,
    tray: Option<ksni::blocking::Handle<Tray>>,
    ctx: egui::Context,
}

impl Indicator {
    /// Also returns why the tray icon couldn't be shown, if it couldn't (no tray host running).
    pub fn new(ctx: &egui::Context) -> (Self, Option<String>) {
        use ksni::blocking::TrayMethods;
        let (tray, err) = match (Tray { on: false, ctx: ctx.clone() }).spawn() {
            Ok(h) => (Some(h), None),
            Err(e) => (None, Some(format!("tray icon unavailable: {e}"))),
        };
        (Self { on: Arc::new(Mutex::new(None)), tray, ctx: ctx.clone() }, err)
    }

    /// Whether there's a tray icon to bring the window back from.
    pub fn has_tray(&self) -> bool {
        self.tray.as_ref().is_some_and(|t| !t.is_closed())
    }

    pub fn set(&self, on: bool) {
        if self.on.lock().unwrap().replace(on) == Some(on) {
            return;
        }
        self.ctx.send_viewport_cmd(ViewportCommand::Icon(Some(Arc::new(icon_data(on)))));
        if let Some(t) = &self.tray {
            t.update(|t| t.on = on);
        }
    }
}
