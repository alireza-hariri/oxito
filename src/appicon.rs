//! Per-app icons for the Apps table. An executable's icon is resolved the freedesktop way:
//! match its basename against `.desktop` files (`Exec` path, `Exec` command or
//! `StartupWMClass`), take their `Icon=` name, then look that name up in the icon theme
//! (the user's current theme first, `hicolor` as fallback, then legacy `/usr/share/pixmaps`).
//! PNG is decoded with `image`, SVG with `resvg`. Resolved icons are cached as egui textures;
//! failures are cached too, so lookups happen once per app.

use eframe::egui::{self, Color32, Context, TextureHandle, TextureOptions};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::singbox;

/// Icon size we want from the theme; bigger files are downscaled by egui.
const WANT: u32 = 32;

/// `exe basename | window class` (lowercase) -> `Icon=` name. Later dirs win so
/// `~/.local/share/applications` can override `/usr/share/applications`.
fn desktop_icons() -> &'static HashMap<String, String> {
    static DESKTOPS: OnceLock<HashMap<String, String>> = OnceLock::new();
    DESKTOPS.get_or_init(|| {
        let mut map = HashMap::new();
        let home = singbox::home();
        for (dir, overwrite) in [
            (PathBuf::from("/usr/share/applications"), false),
            (PathBuf::from("/usr/local/share/applications"), false),
            (
                home.join(".local/share/flatpak/exports/share/applications"),
                true,
            ),
            (home.join(".local/share/applications"), true),
        ] {
            let Ok(read) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in read.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                    continue;
                }
                if let Some(desktop) = DesktopFile::parse(&path) {
                    desktop.register(&mut map, overwrite);
                }
            }
        }
        map
    })
}

struct DesktopFile {
    /// Keys to match the exe against: full-exec path, its basename, command name, WM class.
    keys: Vec<String>,
    icon: String,
}

impl DesktopFile {
    fn parse(path: &Path) -> Option<Self> {
        let text = std::fs::read_to_string(path).ok()?;
        let mut exec = None;
        let mut icon = None;
        let mut class = None;
        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "Exec" => exec = Some(value.trim().to_owned()),
                "Icon" => icon = Some(value.trim().to_owned()),
                "StartupWMClass" => class = Some(value.trim().to_owned()),
                _ => {}
            }
        }
        // skip lines-before-[Desktop Entry] false positives: only headers can appear there
        if let Some(head) = text.find("[Desktop Entry]") {
            let head = &text[..head];
            if head
                .lines()
                .any(|l| l.starts_with("Exec=") || l.starts_with("Icon="))
            {
                return None;
            }
        }
        let icon = icon?;
        let mut keys = vec![];
        let exe = exec.unwrap_or_default();
        if let Some(first) = exe.split_whitespace().next() {
            let first = first.trim_matches('"');
            if first.contains('/') {
                let path = Path::new(first);
                keys.push(first.to_owned());
                keys.push(path.file_name()?.to_string_lossy().into_owned());
            } else if !first.starts_with('-') && !first.starts_with('%') {
                keys.push(first.to_owned());
            }
        }
        if let Some(c) = class {
            keys.push(c);
        }
        if keys.is_empty() {
            return None;
        }
        Some(Self { keys, icon })
    }

    fn register(self, map: &mut HashMap<String, String>, overwrite: bool) {
        for key in self.keys {
            let key = key.to_lowercase();
            if overwrite || !map.contains_key(&key) {
                map.insert(key, self.icon.clone());
            }
        }
    }
}

/// Best file for an icon name: scalable beats any raster, otherwise the raster size closest to
/// `WANT` from above (larger is better than smaller). Returns svg/pixmap content, not a path,
/// so the caller never has to re-read.
fn theme_icons() -> &'static HashMap<String, Vec<PathBuf>> {
    static THEMES: OnceLock<HashMap<String, Vec<PathBuf>>> = OnceLock::new();
    THEMES.get_or_init(|| {
        let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
        let home = singbox::home();
        let mut roots = vec![
            PathBuf::from("/usr/share/icons"),
            home.join(".local/share/icons"),
            home.join(".icons"),
        ];
        roots.dedup();
        let mut theme_dirs: Vec<PathBuf> = vec![];
        for root in &roots {
            let Ok(read) = std::fs::read_dir(root) else {
                continue;
            };
            let mut themes: Vec<PathBuf> = read.flatten().map(|e| e.path()).collect();
            theme_dirs.append(&mut themes);
        }
        // fallbacks last; the user's current theme first (KDE records it in kdeglobals)
        let current = std::fs::read_to_string(home.join(".config/kdeglobals"))
            .ok()
            .and_then(|t| {
                t.lines()
                    .find(|l| l.starts_with("Theme="))
                    .and_then(|l| l.split_once('='))
                    .map(|(_, v)| v.trim().to_owned())
            });
        theme_dirs.sort_by_key(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            // prefer the current theme, then hicolor, then the rest
            (
                name != current.as_deref().unwrap_or("hicolor"),
                name != "hicolor",
            )
        });
        for theme in &theme_dirs {
            let Ok(sizes) = std::fs::read_dir(theme) else {
                continue;
            };
            for size in sizes.flatten() {
                // <theme>/<size>/apps/<file> and the legacy flat layout <theme>/apps/<file>
                for apps in [size.path().join("apps"), size.path()] {
                    let Ok(read) = std::fs::read_dir(&apps) else {
                        continue;
                    };
                    for file in read.flatten() {
                        let path = file.path();
                        if matches!(
                            path.extension().and_then(|e| e.to_str()),
                            Some("png") | Some("svg")
                        ) {
                            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                            map.entry(stem.to_lowercase()).or_default().push(path);
                        }
                    }
                }
            }
        }
        // legacy pixmaps: <name>.png
        let Ok(read) = std::fs::read_dir("/usr/share/pixmaps") else {
            return map;
        };
        for file in read.flatten() {
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) == Some("png") {
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                map.entry(stem.to_lowercase()).or_default().push(path);
            }
        }
        map
    })
}

/// Rank icon candidates: scalable first, then closest raster size to `WANT` (over is better
/// than under).
fn best(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .filter_map(|path| {
            // path is <theme>/<size>/apps/<file>; the flat layout has <theme>/<file> instead
            let size_dir = path.parent().and_then(|p| p.file_name())?.to_str()?;
            let size_dir = if size_dir == "apps" {
                path.parent()?.parent()?.file_name()?.to_str()?
            } else {
                size_dir
            };
            let score = if size_dir == "scalable" {
                0
            } else {
                let px: u32 = size_dir.split('x').next()?.parse().ok()?;
                1 + px.abs_diff(WANT).min(px) // under-size is worse than over-size
            };
            Some((score, path))
        })
        .min_by_key(|(score, _)| *score)
        .map(|(_, p)| p.clone())
}

/// Icon file for an app: the `.desktop` `Icon=` name first, then theme/pixmaps lookups of the
/// exe basename and the display name (some apps ship theme icons without a desktop file).
pub fn icon_file(exe: &str, name: &str) -> Option<PathBuf> {
    let base = Path::new(exe).file_name()?.to_string_lossy().into_owned();
    let mut wanted = vec![];
    if let Some(icon) = desktop_icons().get(&base.to_lowercase()) {
        wanted.push(icon.clone());
    }
    wanted.push(base);
    wanted.push(name.to_owned());
    for w in wanted {
        let none: Vec<PathBuf> = vec![];
        if let Some(p) = best(theme_icons().get(&w.to_lowercase()).unwrap_or(&none)) {
            return Some(p);
        }
    }
    None
}

/// Decode a png/svg icon file to RGBA pixels.
pub fn decode(path: &Path) -> Option<egui::ColorImage> {
    let bytes = std::fs::read(path).ok()?;
    let (rgba, w, h) = match path.extension().and_then(|e| e.to_str())? {
        "svg" => {
            let tree = resvg::usvg::Tree::from_data(&bytes, &Default::default()).ok()?;
            let scale = WANT as f32 / tree.size().width().max(1.0);
            let mut pixmap = resvg::tiny_skia::Pixmap::new(WANT, WANT)?;
            resvg::render(
                &tree,
                resvg::tiny_skia::Transform::from_scale(scale, scale),
                &mut pixmap.as_mut(),
            );
            (pixmap.take(), WANT as usize, WANT as usize)
        }
        "png" => {
            let img = image::load_from_memory(&bytes).ok()?;
            let img = img.to_rgba8();
            let (w, h) = (img.width() as usize, img.height() as usize);
            (img.into_raw(), w, h)
        }
        _ => return None,
    };
    let pixels: Vec<Color32> = rgba
        .chunks_exact(4)
        .map(|c| Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3]))
        .collect();
    Some(egui::ColorImage {
        size: [w, h],
        pixels,
    })
}

/// Cache of resolved app icons, keyed by exe path. `None` = no icon found (also cached).
#[derive(Default)]
pub struct Icons {
    map: HashMap<String, Option<TextureHandle>>,
}

impl Icons {
    /// Texture for `exe` (displayed as `name`), decoded and cached on first call.
    pub fn get(&mut self, ctx: &Context, exe: &str, name: &str) -> Option<TextureHandle> {
        if !self.map.contains_key(exe) {
            let tex = icon_file(exe, name)
                .and_then(|p| decode(&p))
                .map(|img| ctx.load_texture(format!("app:{exe}"), img, TextureOptions::default()));
            self.map.insert(exe.to_owned(), tex);
        }
        self.map.get(exe).and_then(|t| t.as_ref().cloned())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn resolves_installed_apps() {
        for (exe, name) in [
            ("/usr/lib/chromium/chromium", "chromium"),
            ("/usr/bin/firefox", "Firefox"),
            ("/usr/bin/does-not-exist-xyz", "nothing"),
        ] {
            let icon = super::icon_file(exe, name);
            let found = icon
                .as_ref()
                .map_or_else(|| "".to_owned(), |p| p.display().to_string());
            if exe.contains("does-not-exist") {
                assert!(icon.is_none(), "unexpected icon for ghost app: {found}");
                continue;
            }
            assert!(
                found.contains("icons") || found.contains("pixmaps"),
                "no icon for {exe}: {found:?}"
            );
            assert!(
                super::decode(std::path::Path::new(&found)).is_some(),
                "decode failed: {found}"
            );
        }
    }
}
