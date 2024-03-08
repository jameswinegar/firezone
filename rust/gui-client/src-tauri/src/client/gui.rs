//! The Tauri GUI for Windows
//! This is not checked or compiled on other platforms.

// TODO: `git grep` for unwraps before 1.0, especially this gui module <https://github.com/firezone/firezone/issues/3521>

use crate::client::{
    self, about, deep_link, logging, network_changes,
    settings::{self, AdvancedSettings},
    Failure,
};
use anyhow::{anyhow, bail, Context, Result};
use arc_swap::ArcSwap;
use connlib_client_shared::SecureUrl;
use connlib_client_shared::{file_logger, ResourceDescription};
use connlib_shared::{messages::ResourceId, BUNDLE_ID};
use secrecy::{ExposeSecret, Secret, SecretString};
use std::{net::IpAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use system_tray_menu::Event as TrayMenuEvent;
use tauri::{Manager, SystemTray, SystemTrayEvent};
use tokio::sync::{mpsc, oneshot, Notify};
use ControllerRequest as Req;

mod system_tray_menu;

#[cfg(target_os = "linux")]
#[path = "gui/os_linux.rs"]
mod os;

// Stub only
#[cfg(target_os = "macos")]
#[path = "gui/os_macos.rs"]
mod os;

#[cfg(target_os = "windows")]
#[path = "gui/os_windows.rs"]
mod os;

/// The Windows client doesn't use platform APIs to detect network connectivity changes,
/// so we rely on connlib to do so. We have valid use cases for headless Windows clients
/// (IoT devices, point-of-sale devices, etc), so try to reconnect for 30 days if there's
/// been a partition.
const MAX_PARTITION_TIME: Duration = Duration::from_secs(60 * 60 * 24 * 30);

pub(crate) type CtlrTx = mpsc::Sender<ControllerRequest>;

/// All managed state that we might need to access from odd places like Tauri commands.
///
/// Note that this never gets Dropped because of
/// <https://github.com/tauri-apps/tauri/issues/8631>
pub(crate) struct Managed {
    pub ctlr_tx: CtlrTx,
    pub inject_faults: bool,
}

impl Managed {
    #[cfg(debug_assertions)]
    /// In debug mode, if `--inject-faults` is passed, sleep for `millis` milliseconds
    pub async fn fault_msleep(&self, millis: u64) {
        if self.inject_faults {
            tokio::time::sleep(std::time::Duration::from_millis(millis)).await;
        }
    }

    #[cfg(not(debug_assertions))]
    /// Does nothing in release mode
    pub async fn fault_msleep(&self, _millis: u64) {}
}

// TODO: Replace with `anyhow` gradually per <https://github.com/firezone/firezone/pull/3546#discussion_r1477114789>
#[cfg_attr(target_os = "linux", allow(dead_code))]
#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error(r#"Couldn't show clickable notification titled "{0}""#)]
    ClickableNotification(String),
    #[error("Deep-link module error: {0}")]
    DeepLink(#[from] deep_link::Error),
    #[error("Can't show log filter error dialog: {0}")]
    LogFilterErrorDialog(native_dialog::Error),
    #[error("Logging module error: {0}")]
    Logging(#[from] logging::Error),
    #[error(r#"Couldn't show notification titled "{0}""#)]
    Notification(String),
    #[error(transparent)]
    Tauri(#[from] tauri::Error),
    #[error("tokio::runtime::Runtime::new failed: {0}")]
    TokioRuntimeNew(std::io::Error),

    // `client.rs` provides a more user-friendly message when showing the error dialog box
    #[error("WebViewNotInstalled")]
    WebViewNotInstalled,
}

/// Runs the Tauri GUI and returns on exit or unrecoverable error
pub(crate) fn run(cli: &client::Cli) -> Result<(), Error> {
    let advanced_settings = settings::load_advanced_settings().unwrap_or_default();

    // If the log filter is unparsable, show an error and use the default
    // Fixes <https://github.com/firezone/firezone/issues/3452>
    let advanced_settings =
        match tracing_subscriber::EnvFilter::from_str(&advanced_settings.log_filter) {
            Ok(_) => advanced_settings,
            Err(_) => {
                native_dialog::MessageDialog::new()
                    .set_title("Log filter error")
                    .set_text(
                        "The custom log filter is not parsable. Using the default log filter.",
                    )
                    .set_type(native_dialog::MessageType::Error)
                    .show_alert()
                    .map_err(Error::LogFilterErrorDialog)?;

                AdvancedSettings {
                    log_filter: AdvancedSettings::default().log_filter,
                    ..advanced_settings
                }
            }
        };

    // Start logging
    // TODO: Try using an Arc to keep the file logger alive even if Tauri bails out
    // That may fix <https://github.com/firezone/firezone/issues/3567>
    let logging_handles = client::logging::setup(&advanced_settings.log_filter)?;
    tracing::info!("started log");
    tracing::info!("GIT_VERSION = {}", crate::client::GIT_VERSION);

    // Need to keep this alive so crashes will be handled. Dropping detaches it.
    let _crash_handler = match client::crash_handling::attach_handler() {
        Ok(x) => Some(x),
        Err(error) => {
            // TODO: None of these logs are actually written yet
            // <https://github.com/firezone/firezone/issues/3211>
            tracing::warn!(?error, "Did not set up crash handler");
            None
        }
    };

    // Needed for the deep link server
    let rt = tokio::runtime::Runtime::new().map_err(Error::TokioRuntimeNew)?;
    let _guard = rt.enter();

    let (ctlr_tx, ctlr_rx) = mpsc::channel(5);
    let notify_controller = Arc::new(Notify::new());

    // Check for updates
    let ctlr_tx_clone = ctlr_tx.clone();
    let always_show_update_notification = cli.always_show_update_notification;
    tokio::spawn(async move {
        if let Err(error) = check_for_updates(ctlr_tx_clone, always_show_update_notification).await
        {
            tracing::error!(?error, "Error in check_for_updates");
        }
    });

    if let Some(client::Cmd::SmokeTest) = &cli.command {
        let ctlr_tx = ctlr_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = smoke_test(ctlr_tx).await {
                tracing::error!(?error, "Error during smoke test");
                std::process::exit(1);
            }
        });
    }

    // Make sure we're single-instance
    // We register our deep links to call the `open-deep-link` subcommand,
    // so if we're at this point, we know we've been launched manually
    let server = deep_link::Server::new()?;

    // We know now we're the only instance on the computer, so register our exe
    // to handle deep links
    deep_link::register()?;
    tokio::spawn(accept_deep_links(server, ctlr_tx.clone()));

    let managed = Managed {
        ctlr_tx: ctlr_tx.clone(),
        inject_faults: cli.inject_faults,
    };

    let tray = SystemTray::new().with_menu(system_tray_menu::signed_out());

    if let Some(failure) = cli.fail_on_purpose() {
        let ctlr_tx = ctlr_tx.clone();
        tokio::spawn(async move {
            let delay = 5;
            tracing::info!(
                "Will crash / error / panic on purpose in {delay} seconds to test error handling."
            );
            tokio::time::sleep(Duration::from_secs(delay)).await;
            tracing::info!("Crashing / erroring / panicking on purpose");
            ctlr_tx.send(ControllerRequest::Fail(failure)).await?;
            Ok::<_, anyhow::Error>(())
        });
    }

    let app = tauri::Builder::default()
        .manage(managed)
        .on_window_event(|event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event.event() {
                // Keep the frontend running but just hide this webview
                // Per https://tauri.app/v1/guides/features/system-tray/#preventing-the-app-from-closing
                // Closing the window fully seems to deallocate it or something.

                event.window().hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            about::get_cargo_version,
            about::get_git_version,
            logging::clear_logs,
            logging::count_logs,
            logging::export_logs,
            settings::apply_advanced_settings,
            settings::reset_advanced_settings,
            settings::get_advanced_settings,
        ])
        .system_tray(tray)
        .on_system_tray_event(|app, event| {
            if let SystemTrayEvent::MenuItemClick { id, .. } = event {
                tracing::debug!(?id, "SystemTrayEvent::MenuItemClick");
                let event = match TrayMenuEvent::from_str(&id) {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::error!("{e}");
                        return;
                    }
                };
                match handle_system_tray_event(app, event) {
                    Ok(_) => {}
                    Err(e) => tracing::error!("{e}"),
                }
            }
        })
        .setup(move |app| {
            assert_eq!(
                BUNDLE_ID,
                app.handle().config().tauri.bundle.identifier,
                "BUNDLE_ID should match bundle ID in tauri.conf.json"
            );

            let app_handle = app.handle();
            let _ctlr_task = tokio::spawn(async move {
                let app_handle_2 = app_handle.clone();
                // Spawn two nested Tasks so the outer can catch panics from the inner
                let task = tokio::spawn(async move {
                    run_controller(
                        app_handle_2,
                        ctlr_tx,
                        ctlr_rx,
                        logging_handles,
                        advanced_settings,
                        notify_controller,
                    )
                    .await
                });

                // See <https://github.com/tauri-apps/tauri/issues/8631>
                // This should be the ONLY place we call `app.exit` or `app_handle.exit`,
                // because it exits the entire process without dropping anything.
                //
                // This seems to be a platform limitation that Tauri is unable to hide
                // from us. It was the source of much consternation at time of writing.

                match task.await {
                    Err(error) => {
                        tracing::error!(?error, "run_controller panicked");
                        app_handle.exit(1);
                    }
                    Ok(Err(error)) => {
                        tracing::error!(?error, "run_controller returned an error");
                        app_handle.exit(1);
                    }
                    Ok(Ok(_)) => {
                        tracing::info!("GUI controller task exited cleanly. Exiting process");
                        app_handle.exit(0);
                    }
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!());

    let app = match app {
        Ok(x) => x,
        Err(error) => {
            tracing::error!(?error, "Failed to build Tauri app instance");
            match error {
                tauri::Error::Runtime(tauri_runtime::Error::CreateWebview(_)) => {
                    return Err(Error::WebViewNotInstalled);
                }
                error => Err(error)?,
            }
        }
    };

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            // Don't exit if we close our main window
            // https://tauri.app/v1/guides/features/system-tray/#preventing-the-app-from-closing

            api.prevent_exit();
        }
    });
    Ok(())
}

/// Runs a smoke test and then asks Controller to exit gracefully
///
/// You can purposely fail this test by deleting the exported zip file during
/// the 10-second sleep.
async fn smoke_test(ctlr_tx: CtlrTx) -> Result<()> {
    let delay = 10;
    tracing::info!("Will quit on purpose in {delay} seconds as part of the smoke test.");
    let quit_time = tokio::time::Instant::now() + Duration::from_secs(delay);

    // Write the settings so we can check the path for those
    settings::save(&settings::AdvancedSettings::default()).await?;

    // Test log exporting
    let path = PathBuf::from("smoke_test_log_export.zip");

    let stem = "connlib-smoke-test".into();
    match tokio::fs::remove_file(&path).await {
        Ok(()) => {}
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                bail!("Error while removing old zip file")
            }
        }
    }
    ctlr_tx
        .send(ControllerRequest::ExportLogs {
            path: path.clone(),
            stem,
        })
        .await
        .context("Failed to send ExportLogs request")?;

    // Give the app some time to export the zip and reach steady state
    tokio::time::sleep_until(quit_time).await;

    // Check results of tests
    let zip_len = tokio::fs::metadata(&path)
        .await
        .context("Failed to get zip file metadata")?
        .len();
    if zip_len == 0 {
        bail!("Exported log zip has 0 bytes");
    }
    tokio::fs::remove_file(&path)
        .await
        .context("Failed to remove zip file")?;
    tracing::info!(?path, ?zip_len, "Exported log zip looks okay");

    tracing::info!("Quitting on purpose because of `smoke-test` subcommand");
    ctlr_tx
        .send(ControllerRequest::SystemTrayMenu(TrayMenuEvent::Quit))
        .await
        .context("Failed to send Quit request")?;

    Ok::<_, anyhow::Error>(())
}

async fn check_for_updates(ctlr_tx: CtlrTx, always_show_update_notification: bool) -> Result<()> {
    let release = client::updates::check()
        .await
        .context("Error in client::updates::check")?;

    let our_version = client::updates::current_version()?;
    let github_version = &release.tag_name;

    if always_show_update_notification || (our_version < release.tag_name) {
        tracing::info!(?our_version, ?github_version, "Github has a new release");
        // We don't necessarily need to route through the Controller here, but if we
        // want a persistent "Click here to download the new MSI" button, this would allow that.
        ctlr_tx
            .send(ControllerRequest::UpdateAvailable(release))
            .await
            .context("Error while sending UpdateAvailable to Controller")?;
        return Ok(());
    }

    tracing::info!(
        ?our_version,
        ?github_version,
        "Our release is newer than, or the same as Github's latest"
    );
    Ok(())
}

/// Worker task to accept deep links from a named pipe forever
///
/// * `server` An initial named pipe server to consume before making new servers. This lets us also use the named pipe to enforce single-instance
async fn accept_deep_links(mut server: deep_link::Server, ctlr_tx: CtlrTx) -> Result<()> {
    loop {
        if let Ok(url) = server.accept().await {
            ctlr_tx
                .send(ControllerRequest::SchemeRequest(url))
                .await
                .ok();
        }
        // We re-create the named pipe server every time we get a link, because of an oddity in the Windows API.
        server = deep_link::Server::new()?;
    }
}

fn handle_system_tray_event(app: &tauri::AppHandle, event: TrayMenuEvent) -> Result<()> {
    app.try_state::<Managed>()
        .context("can't get Managed struct from Tauri")?
        .ctlr_tx
        .blocking_send(ControllerRequest::SystemTrayMenu(event))?;
    Ok(())
}

pub(crate) enum ControllerRequest {
    /// The GUI wants us to use these settings in-memory, they've already been saved to disk
    ApplySettings(AdvancedSettings),
    Disconnected,
    /// The same as the arguments to `client::logging::export_logs_to`
    ExportLogs {
        path: PathBuf,
        stem: PathBuf,
    },
    Fail(Failure),
    GetAdvancedSettings(oneshot::Sender<AdvancedSettings>),
    SchemeRequest(Secret<SecureUrl>),
    SystemTrayMenu(TrayMenuEvent),
    TunnelReady,
    UpdateAvailable(client::updates::Release),
    UpdateNotificationClicked(client::updates::Release),
}

#[derive(Clone)]
struct CallbackHandler {
    logger: file_logger::Handle,
    notify_controller: Arc<Notify>,
    ctlr_tx: CtlrTx,
    resources: Arc<ArcSwap<Vec<ResourceDescription>>>,
}

#[derive(thiserror::Error, Debug)]
enum CallbackError {
    #[error("system DNS resolver problem: {0}")]
    Resolvers(#[from] client::resolvers::Error),
    #[error("can't send to controller task: {0}")]
    SendError(#[from] mpsc::error::TrySendError<ControllerRequest>),
}

// Callbacks must all be non-blocking
impl connlib_client_shared::Callbacks for CallbackHandler {
    type Error = CallbackError;

    fn on_disconnect(&self, error: &connlib_client_shared::Error) -> Result<(), Self::Error> {
        tracing::debug!("on_disconnect {error:?}");
        self.ctlr_tx.try_send(ControllerRequest::Disconnected)?;
        Ok(())
    }

    fn on_tunnel_ready(&self) -> Result<(), Self::Error> {
        tracing::info!("on_tunnel_ready");
        self.ctlr_tx.try_send(ControllerRequest::TunnelReady)?;
        Ok(())
    }

    fn on_update_resources(&self, resources: Vec<ResourceDescription>) -> Result<(), Self::Error> {
        tracing::debug!("on_update_resources");
        self.resources.store(resources.into());
        self.notify_controller.notify_one();
        Ok(())
    }

    fn get_system_default_resolvers(&self) -> Result<Option<Vec<IpAddr>>, Self::Error> {
        Ok(Some(client::resolvers::get()?))
    }

    fn roll_log_file(&self) -> Option<PathBuf> {
        self.logger.roll_to_new_file().unwrap_or_else(|e| {
            tracing::debug!("Failed to roll over to new file: {e}");

            None
        })
    }
}

struct Controller {
    /// Debugging-only settings like API URL, auth URL, log filter
    advanced_settings: AdvancedSettings,
    app: tauri::AppHandle,
    // Sign-in state with the portal / deep links
    auth: client::auth::Auth,
    ctlr_tx: CtlrTx,
    /// connlib session for the currently signed-in user, if there is one
    session: Option<Session>,
    /// The UUIDv4 device ID persisted to disk
    /// Sent verbatim to Session::connect
    device_id: String,
    logging_handles: client::logging::Handles,
    /// Tells us when to wake up and look for a new resource list. Tokio docs say that memory reads and writes are synchronized when notifying, so we don't need an extra mutex on the resources.
    notify_controller: Arc<Notify>,
    tunnel_ready: bool,
    uptime: client::uptime::Tracker,
}

/// Everything related to a signed-in user session
struct Session {
    callback_handler: CallbackHandler,
    connlib: connlib_client_shared::Session<CallbackHandler>,
}

impl Controller {
    // TODO: Figure out how re-starting sessions automatically will work
    /// Pre-req: the auth module must be signed in
    fn start_session(&mut self, token: SecretString) -> Result<()> {
        if self.session.is_some() {
            bail!("can't start session, we're already in a session");
        }

        let callback_handler = CallbackHandler {
            ctlr_tx: self.ctlr_tx.clone(),
            logger: self.logging_handles.logger.clone(),
            notify_controller: Arc::clone(&self.notify_controller),
            resources: Default::default(),
        };

        let api_url = self.advanced_settings.api_url.clone();
        tracing::info!(
            api_url = api_url.to_string(),
            "Calling connlib Session::connect"
        );
        let connlib = connlib_client_shared::Session::connect(
            api_url,
            token,
            self.device_id.clone(),
            None, // `get_host_name` over in connlib gets the system's name automatically
            None,
            callback_handler.clone(),
            Some(MAX_PARTITION_TIME),
        )?;

        self.session = Some(Session {
            callback_handler,
            connlib,
        });
        self.refresh_system_tray_menu()?;

        Ok(())
    }

    fn copy_resource(&self, id: &str) -> Result<()> {
        let Some(session) = &self.session else {
            bail!("app is signed out");
        };
        let resources = session.callback_handler.resources.load();
        let id = ResourceId::from_str(id)?;
        let Some(res) = resources.iter().find(|r| r.id() == id) else {
            bail!("resource ID is not in the list");
        };
        let mut clipboard = arboard::Clipboard::new()?;
        // TODO: Make this a method on `ResourceDescription`
        match res {
            ResourceDescription::Dns(x) => clipboard.set_text(&x.address)?,
            ResourceDescription::Cidr(x) => clipboard.set_text(&x.address.to_string())?,
        }
        Ok(())
    }

    async fn handle_deep_link(&mut self, url: &Secret<SecureUrl>) -> Result<()> {
        let auth_response =
            client::deep_link::parse_auth_callback(url).context("Couldn't parse scheme request")?;

        tracing::info!("Got deep link");
        // Uses `std::fs`
        let token = self.auth.handle_response(auth_response)?;
        self.start_session(token)
            .context("Couldn't start connlib session")?;
        Ok(())
    }

    async fn handle_request(&mut self, req: ControllerRequest) -> Result<()> {
        match req {
            Req::ApplySettings(settings) => {
                self.advanced_settings = settings;
                // TODO: Update the logger here if we can. I can't remember if there
                // was a reason why the reloading didn't work.
                tracing::info!(
                    "Applied new settings. Log level will take effect at next app start."
                );
            }
            Req::Disconnected => {
                tracing::info!("Disconnected by connlib");
                self.sign_out()?;
                os::show_notification(
                    "Firezone disconnected",
                    "To access resources, sign in again.",
                )?;
            }
            Req::ExportLogs { path, stem } => logging::export_logs_to(path, stem)
                .await
                .context("Failed to export logs to zip")?,
            Req::Fail(_) => bail!("Impossible error: `Fail` should be handled before this"),
            Req::GetAdvancedSettings(tx) => {
                tx.send(self.advanced_settings.clone()).ok();
            }
            Req::SchemeRequest(url) => self
                .handle_deep_link(&url)
                .await
                .context("Couldn't handle deep link")?,
            Req::SystemTrayMenu(TrayMenuEvent::CancelSignIn) => {
                if self.session.is_some() {
                    // If the user opened the menu, then sign-in completed, then they
                    // click "cancel sign in", don't sign out - They can click Sign Out
                    // if they want to sign out. "Cancel" may mean "Give up waiting,
                    // but if you already got in, don't make me sign in all over again."
                    //
                    // Also, by amazing coincidence, it doesn't work in Tauri anyway.
                    // We'd have to reuse the `sign_out` ID to make it work.
                    tracing::info!("This can never happen. Tauri doesn't pass us a system tray event if the menu no longer has any item with that ID.");
                } else {
                    tracing::info!("Calling `sign_out` to cancel sign-in");
                    self.sign_out()?;
                }
            }
            Req::SystemTrayMenu(TrayMenuEvent::ShowWindow(window)) => {
                self.show_window(window)?;
                // When the About or Settings windows are hidden / shown, log the
                // run ID and uptime. This makes it easy to check client stability on
                // dev or test systems without parsing the whole log file.
                let uptime_info = self.uptime.info();
                tracing::debug!(
                    uptime_s = uptime_info.uptime.as_secs(),
                    run_id = uptime_info.run_id.to_string(),
                    "Uptime info"
                );
            }
            Req::SystemTrayMenu(TrayMenuEvent::Resource { id }) => self
                .copy_resource(&id)
                .context("Couldn't copy resource to clipboard")?,
            Req::SystemTrayMenu(TrayMenuEvent::SignIn) => {
                if let Some(req) = self.auth.start_sign_in()? {
                    let url = req.to_url(&self.advanced_settings.auth_base_url);
                    self.refresh_system_tray_menu()?;
                    tauri::api::shell::open(
                        &self.app.shell_scope(),
                        &url.expose_secret().inner,
                        None,
                    )?;
                }
            }
            Req::SystemTrayMenu(TrayMenuEvent::SignOut) => {
                tracing::info!("User asked to sign out");
                self.sign_out()?;
            }
            Req::SystemTrayMenu(TrayMenuEvent::Quit) => {
                bail!("Impossible error: `Quit` should be handled before this")
            }
            Req::TunnelReady => {
                self.tunnel_ready = true;
                self.refresh_system_tray_menu()?;

                os::show_notification(
                    "Firezone connected",
                    "You are now signed in and able to access resources.",
                )?;
            }
            Req::UpdateAvailable(release) => {
                let title = format!("Firezone {} available for download", release.tag_name);

                // We don't need to route through the controller here either, we could
                // use the `open` crate directly instead of Tauri's wrapper
                // `tauri::api::shell::open`
                os::show_clickable_notification(
                    &title,
                    "Click here to download the new version.",
                    self.ctlr_tx.clone(),
                    Req::UpdateNotificationClicked(release),
                )?;
            }
            Req::UpdateNotificationClicked(release) => {
                tracing::info!("UpdateNotificationClicked in run_controller!");
                tauri::api::shell::open(
                    &self.app.shell_scope(),
                    release.browser_download_url,
                    None,
                )?;
            }
        }
        Ok(())
    }

    /// Returns a new system tray menu
    fn build_system_tray_menu(&self) -> tauri::SystemTrayMenu {
        // TODO: Refactor this and the auth module so that "Are we logged in"
        // doesn't require such complicated control flow to answer.
        // TODO: Show some "Waiting for portal..." state if we got the deep link but
        // haven't got `on_tunnel_ready` yet.
        if let Some(auth_session) = self.auth.session() {
            if let Some(connlib_session) = &self.session {
                if self.tunnel_ready {
                    // Signed in, tunnel ready
                    let resources = connlib_session.callback_handler.resources.load();
                    system_tray_menu::signed_in(&auth_session.actor_name, &resources)
                } else {
                    // Signed in, raising tunnel
                    system_tray_menu::signing_in("Signing In...")
                }
            } else {
                tracing::error!("We have an auth session but no connlib session");
                system_tray_menu::signed_out()
            }
        } else if self.auth.ongoing_request().is_ok() {
            // Signing in, waiting on deep link callback
            system_tray_menu::signing_in("Waiting for browser...")
        } else {
            system_tray_menu::signed_out()
        }
    }

    /// Builds a new system tray menu and applies it to the app
    fn refresh_system_tray_menu(&self) -> Result<()> {
        Ok(self
            .app
            .tray_handle()
            .set_menu(self.build_system_tray_menu())?)
    }

    /// Deletes the auth token, stops connlib, and refreshes the tray menu
    fn sign_out(&mut self) -> Result<()> {
        self.auth.sign_out()?;
        self.tunnel_ready = false;
        if let Some(mut session) = self.session.take() {
            tracing::debug!("disconnecting connlib");
            // This is redundant if the token is expired, in that case
            // connlib already disconnected itself.
            session.connlib.disconnect();
        } else {
            // Might just be because we got a double sign-out or
            // the user canceled the sign-in or something innocent.
            tracing::info!("Tried to sign out but there's no session, cancelled sign-in");
        }
        self.refresh_system_tray_menu()?;
        Ok(())
    }

    fn show_window(&self, window: system_tray_menu::Window) -> Result<()> {
        let id = match window {
            system_tray_menu::Window::About => "about",
            system_tray_menu::Window::Settings => "settings",
        };

        let win = self
            .app
            .get_window(id)
            .ok_or_else(|| anyhow!("getting handle to `{id}` window"))?;

        win.show()?;
        win.unminimize()?;
        Ok(())
    }
}

// TODO: Move this into `impl Controller`
async fn run_controller(
    app: tauri::AppHandle,
    ctlr_tx: CtlrTx,
    mut rx: mpsc::Receiver<ControllerRequest>,
    logging_handles: client::logging::Handles,
    advanced_settings: AdvancedSettings,
    notify_controller: Arc<Notify>,
) -> Result<()> {
    let device_id = client::device_id::device_id()
        .await
        .context("Failed to read / create device ID")?;

    let mut controller = Controller {
        advanced_settings,
        app,
        auth: client::auth::Auth::new().context("Failed to set up auth module")?,
        ctlr_tx,
        session: None,
        device_id,
        logging_handles,
        notify_controller,
        tunnel_ready: false,
        uptime: Default::default(),
    };

    if let Some(token) = controller
        .auth
        .token()
        .context("Failed to load token from disk during app start")?
    {
        controller
            .start_session(token)
            .context("Failed to restart session during app start")?;
    } else {
        tracing::info!("No token / actor_name on disk, starting in signed-out state");
    }

    let mut have_internet =
        network_changes::check_internet().context("Failed initial check for internet")?;
    tracing::info!(?have_internet);

    let mut com_worker =
        network_changes::Worker::new().context("Failed to listen for network changes")?;

    loop {
        tokio::select! {
            () = controller.notify_controller.notified() => if let Err(error) = controller.refresh_system_tray_menu() {
                tracing::error!(?error, "Failed to reload resource list");
            },
            () = com_worker.notified() => {
                let new_have_internet = network_changes::check_internet().context("Failed to check for internet")?;
                if new_have_internet != have_internet {
                    have_internet = new_have_internet;
                    // TODO: Stop / start / restart connlib as needed here
                    tracing::info!(?have_internet);
                }
            },
            req = rx.recv() => {
                let Some(req) = req else {
                    break;
                };
                match req {
                    // SAFETY: Crashing is unsafe
                    Req::Fail(Failure::Crash) => {
                        tracing::error!("Crashing on purpose");
                        unsafe { sadness_generator::raise_segfault() }
                    },
                    Req::Fail(Failure::Error) => bail!("Test error"),
                    Req::Fail(Failure::Panic) => panic!("Test panic"),
                    Req::SystemTrayMenu(TrayMenuEvent::Quit) => break,
                    req => if let Err(error) = controller.handle_request(req).await {
                        tracing::error!(?error, "Failed to handle a ControllerRequest");
                    }
                }
            }
        }
    }

    if let Err(error) = com_worker.close() {
        tracing::error!(?error, "com_worker");
    }

    // Last chance to do any drops / cleanup before the process crashes.

    Ok(())
}
