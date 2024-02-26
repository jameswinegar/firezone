//! Everything related to the Settings window, including
//! advanced settings and code for manipulating diagnostic logs.

use crate::client::{
    gui::{ControllerRequest, Managed},
    known_dirs,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, time::Duration};
use tokio::sync::oneshot;
use url::Url;

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AdvancedSettings {
    pub auth_base_url: Url,
    pub api_url: Url,
    pub log_filter: String,
}

#[cfg(debug_assertions)]
impl Default for AdvancedSettings {
    fn default() -> Self {
        Self {
            auth_base_url: Url::parse("https://app.firez.one").unwrap(),
            api_url: Url::parse("wss://api.firez.one").unwrap(),
            log_filter: "firezone_gui_client=debug,firezone_tunnel=trace,phoenix_channel=debug,connlib_shared=debug,connlib_client_shared=debug,snownet=debug,str0m=info,warn".to_string(),
        }
    }
}

#[cfg(not(debug_assertions))]
impl Default for AdvancedSettings {
    fn default() -> Self {
        Self {
            auth_base_url: Url::parse("https://app.firezone.dev").unwrap(),
            api_url: Url::parse("wss://api.firezone.dev").unwrap(),
            log_filter: "firezone_gui_client=info,firezone_tunnel=trace,phoenix_channel=info,connlib_shared=info,connlib_client_shared=info,snownet=debug,str0m=info,warn".to_string(),
        }
    }
}

fn advanced_settings_path() -> Result<PathBuf> {
    Ok(known_dirs::settings()
        .context("`known_dirs::settings` failed")?
        .join("advanced_settings.json"))
}

#[tauri::command]
pub(crate) async fn apply_advanced_settings(
    managed: tauri::State<'_, Managed>,
    settings: AdvancedSettings,
) -> Result<(), String> {
    if managed.inner().inject_faults {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    apply_advanced_settings_inner(&settings)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub(crate) async fn reset_advanced_settings(
    managed: tauri::State<'_, Managed>,
) -> Result<AdvancedSettings, String> {
    let settings = AdvancedSettings::default();
    if managed.inner().inject_faults {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    apply_advanced_settings_inner(&settings)
        .await
        .map_err(|e| e.to_string())?;

    Ok(settings)
}

#[tauri::command]
pub(crate) async fn get_advanced_settings(
    managed: tauri::State<'_, Managed>,
) -> Result<AdvancedSettings, String> {
    let (tx, rx) = oneshot::channel();
    if let Err(e) = managed
        .ctlr_tx
        .send(ControllerRequest::GetAdvancedSettings(tx))
        .await
    {
        tracing::error!("couldn't request advanced settings from controller task: {e}");
    }
    Ok(rx.await.unwrap())
}

pub(crate) async fn apply_advanced_settings_inner(settings: &AdvancedSettings) -> Result<()> {
    let path = advanced_settings_path()?;
    let dir = path
        .parent()
        .context("settings path should have a parent")?;
    tokio::fs::create_dir_all(dir).await?;
    tokio::fs::write(path, serde_json::to_string(&settings)?).await?;
    Ok(())
}

/// Return advanced settings if they're stored on disk
///
/// Uses std::fs, so stick it in `spawn_blocking` for async contexts
pub(crate) fn load_advanced_settings() -> Result<AdvancedSettings> {
    let path = advanced_settings_path()?;
    let text = std::fs::read_to_string(path)?;
    let settings = serde_json::from_str(&text)?;
    Ok(settings)
}
