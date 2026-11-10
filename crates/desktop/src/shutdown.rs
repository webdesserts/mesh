//! Clean shutdown for `Quit Mesh`, `ExitRequested`, `SIGINT` and `SIGTERM`.

use tauri::{AppHandle, Manager};

/// Shut the daemon down, then exit the process.
pub fn quit(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        shutdown_host(&app).await;
        app.exit(0);
    });
}

/// Best-effort daemon shutdown without exiting (used by `ExitRequested`).
pub async fn shutdown_host(app: &AppHandle) {
    let state = app.state::<crate::state::AppState>();
    let host = {
        let mut guard = state.host.lock().await;
        guard.take()
    };
    if let Some(host) = host {
        host.shutdown().await;
    }
}
