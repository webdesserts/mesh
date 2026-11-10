//! Desktop-only control routes merged onto the daemon'"'"'s `:4620` TCP API.
//!
//! These routes need the Tauri `AppHandle`, so they live in the desktop crate
//! and are merged by `webdesserts_mesh::api::serve_with_extra` *before*
//! `admin_guard` is layered: every mutating route still requires the admin
//! bearer token over loopback TCP.

use crate::commands;
use crate::shutdown;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

/// Build the desktop control router bound to `app`.
pub fn router(app: AppHandle) -> Router {
    Router::new()
        .route("/daemon/restart", post(daemon_restart))
        .route("/app/restart", post(app_restart))
        .route("/update/check", get(update_check))
        .route("/app/update", post(app_update))
        .with_state(app)
}

fn error(status: StatusCode, message: String) -> Response {
    (status, Json(json!({ "ok": false, "error": message }))).into_response()
}

async fn daemon_restart(State(app): State<AppHandle>) -> Response {
    match commands::restart_daemon(&app).await {
        Ok(()) => Json(json!({ "ok": true, "restarting": true })).into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "daemon restart failed");
            error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

async fn app_restart(State(app): State<AppHandle>) -> Response {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Let the HTTP response flush before the process restarts.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        shutdown::shutdown_host(&app).await;
        app.restart();
    });
    Json(json!({ "ok": true, "restarting": true })).into_response()
}

async fn update_check(State(app): State<AppHandle>) -> Response {
    let current = app.package_info().version.to_string();
    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(e) => {
            tracing::warn!(error = %e, "updater unavailable");
            return error(StatusCode::SERVICE_UNAVAILABLE, e.to_string());
        }
    };
    match updater.check().await {
        Ok(Some(update)) => Json(json!({
            "current_version": current,
            "update_available": true,
            "latest_version": update.version,
        }))
        .into_response(),
        Ok(None) => Json(json!({
            "current_version": current,
            "update_available": false,
            "latest_version": current,
        }))
        .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "update check failed");
            error(StatusCode::BAD_GATEWAY, e.to_string())
        }
    }
}

async fn app_update(State(app): State<AppHandle>) -> Response {
    let updater = match app.updater() {
        Ok(updater) => updater,
        Err(e) => {
            tracing::warn!(error = %e, "updater unavailable");
            return error(StatusCode::SERVICE_UNAVAILABLE, e.to_string());
        }
    };
    let update = match updater.check().await {
        Ok(Some(update)) => update,
        Ok(None) => {
            return Json(json!({ "ok": true, "updating": false, "reason": "up to date" }))
                .into_response()
        }
        Err(e) => {
            tracing::warn!(error = %e, "update check failed");
            return error(StatusCode::BAD_GATEWAY, e.to_string());
        }
    };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(e) = update
            .download_and_install(|_chunk, _total| {}, || {})
            .await
        {
            tracing::warn!(error = %e, "update download failed");
            return;
        }
        shutdown::shutdown_host(&app).await;
        app.restart();
    });
    Json(json!({ "ok": true, "updating": true })).into_response()
}
