//! Making sure only one oxito UI is running.
//!
//! The first instance binds a Unix-domain socket in the state dir; a second one connects, asks it
//! to show its (possibly hidden) window, and exits. The socket doubles as the lock, and a reply
//! distinguishes a live instance from a stale socket left over by a crash.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

/// Try to become the one oxito instance. `Err(())` means another instance is already running (and
/// has been asked to show its window), so the caller should exit.
pub fn primary_or_notify(
    socket: &Path,
    show: impl Fn() + Send + 'static,
) -> Result<(), String> {
    // someone already listening?
    if let Ok(mut s) = UnixStream::connect(socket) {
        let ok = s
            .write_all(b"show\n")
            .and_then(|_| s.flush())
            .is_ok()
            && BufReader::new(s.try_clone().map_err(|e| e.to_string())?)
                .lines()
                .next()
                .map_or(false, |l| l.as_deref().is_ok_and(|l| l == "ok"));
        if ok {
            return Err("oxito is already running; showing its window".into());
        }
        // no reply: stale socket left by a dead instance
        let _ = fs::remove_file(socket);
    }
    let listener = UnixListener::bind(socket)
        .map_err(|e| format!("oxito already running (socket in use: {e})"))?;
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let mut conn = conn;
            let mut line = String::new();
            if std::io::BufReader::new(
                match conn.try_clone() {
                    Ok(c) => c,
                    Err(_) => continue,
                },
            )
            .read_line(&mut line)
            .ok()
            != Some(0)
                && line.trim() == "show"
            {
                show();
            }
            let _ = conn.write_all(b"ok\n");
        }
    });
    Ok(())
}

/// Remove the socket on shutdown, so the next instance binds a fresh one.
pub fn cleanup(socket: &Path) {
    let _ = fs::remove_file(socket);
}
