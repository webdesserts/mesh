//! Tray menu event dispatch.

use tauri::AppHandle;

pub fn handle(app: &AppHandle, id: &str) {
    match id {
        "quit" => crate::shutdown::quit(app),
        "pair" => {
            if let Err(e) = crate::pair_window::open(app) {
                tracing::warn!(error = %e, "open pair window failed");
            }
        }
        "copy_node_id" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let state = tauri::Manager::state::<crate::state::AppState>(&app);
                match crate::commands::copy_node_id(&state).await {
                    Ok(id) => tracing::info!(node_id = %id, "copied node id to clipboard"),
                    Err(e) => tracing::warn!(error = %e, "copy node id failed"),
                }
            });
        }
        "toggle_relay" => {
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                match crate::commands::toggle_relay(&app).await {
                    Ok(hosting) => tracing::info!(hosting, "relay toggle applied"),
                    Err(e) => tracing::warn!(error = %e, "relay toggle failed"),
                }
                crate::tray::refresh(&app).await;
            });
        }
        _ => {}
    }
}
