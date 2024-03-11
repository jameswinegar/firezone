//! TODO: Not implemented for Linux yet

use super::Error;
use anyhow::{bail, Context, Result};
use secrecy::SecretString;

pub(crate) struct Server {}

impl Server {
    pub(crate) fn new() -> Result<Self, Error> {
        tracing::error!("`deep_link::Server::new` not implemented yet");
        Ok(Self {})
    }

    pub(crate) async fn accept(self) -> Result<SecretString, Error> {
        tracing::error!("Deep links not implemented yet on Linux");
        futures::future::pending().await
    }
}

pub(crate) async fn open(_url: &url::Url) -> Result<()> {
    crate::client::logging::debug_command_setup()?;
    tracing::error!("Deep link callback handling not implemented yet for Linux");
    Ok(())
}

/// Register a URI scheme so that browser can deep link into our app for auth
///
/// Performs blocking I/O (Waits on `xdg-desktop-menu` subprocess)
pub(crate) fn register() -> Result<()> {
    // Write `$HOME/.local/share/applications/firezone-client.desktop`
    // According to <https://wiki.archlinux.org/title/Desktop_entries>, that's the place to put
    // per-user desktop entries.
    let dir = dirs::data_local_dir()
        .context("can't figure out where to put our desktop entry")?
        .join("applications");
    std::fs::create_dir_all(&dir)?;

    // Don't use atomic writes here - If we lose power, we'll just rewrite this file on
    // the next boot anyway.
    let path = dir.join("firezone-client.desktop");
    let exe = std::env::current_exe().context("failed to find our own exe path")?;
    let content = format!(
        "[Desktop Entry]
Version=1.0
Name=Firezone
Comment=Firezone GUI Client
Exec={} open-deep-link %U
Terminal=false
Type=Application
MimeType=x-scheme-handler/{}
Categories=Network;
",
        exe.display(),
        super::FZ_SCHEME
    );
    std::fs::write(&path, content).context("failed to write desktop entry file")?;

    // Run `xdg-desktop-menu install` with that desktop file
    let xdg_desktop_menu = "xdg-desktop-menu";
    let status = std::process::Command::new(xdg_desktop_menu)
        .arg("install")
        .arg(&path)
        .status()
        .with_context(|| format!("failed to run `{xdg_desktop_menu}`"))?;
    if !status.success() {
        bail!("failed to register our deep link scheme")
    }
    Ok(())
}
