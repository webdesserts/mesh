//! The 2-tab "Pair Device…" webview window.

use tauri::{AppHandle, Manager, TitleBarStyle, WebviewUrl, WebviewWindowBuilder};

/// Window label used by the capability and by `emit_to`.
pub const PAIR_LABEL: &str = "pair";

/// Open (or focus) the pairing window.
pub fn open(app: &AppHandle) -> tauri::Result<()> {
    if let Some(window) = app.get_webview_window(PAIR_LABEL) {
        window.set_focus()?;
        return Ok(());
    }
    WebviewWindowBuilder::new(app, PAIR_LABEL, WebviewUrl::App("pair.html".into()))
        .title("Pair Device")
        .inner_size(440.0, 460.0)
        .resizable(false)
        .title_bar_style(TitleBarStyle::Overlay)
        .build()?;
    Ok(())
}
