use anyhow::Result;
use clap::Parser;
use connlib_client_shared::{file_logger, Callbacks, Session};
use firezone_cli_utils::{block_on_ctrl_c, setup_global_subscriber, CommonArgs};
use secrecy::SecretString;
use std::{net::IpAddr, path::PathBuf, str::FromStr};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let max_partition_time = cli.max_partition_time.map(|d| d.into());

    let (layer, handle) = cli.log_dir.as_deref().map(file_logger::layer).unzip();
    setup_global_subscriber(layer);

    let mut session = Session::connect(
        cli.common.api_url,
        SecretString::from(cli.common.token),
        cli.firezone_id,
        None,
        None,
        CallbackHandler { handle },
        max_partition_time,
    )
    .unwrap();
    tracing::info!("new_session");

    block_on_ctrl_c();
    tracing::info!("`block_on_ctrl_c` returned");

    session.disconnect(None);
    Ok(())
}

#[derive(Clone)]
struct CallbackHandler {
    handle: Option<file_logger::Handle>,
}

// Using `thiserror` because `anyhow` doesn't seem to implement `std::error::Error`,
// required by connlib
#[derive(Debug, thiserror::Error)]
enum CbError {
    #[error("`resolvectl` reutrned non-zero exit code")]
    ResolveCtlFailed,
    #[error("`resolvectl`'s output was not valid UTF-8")]
    ResolveCtlUtf8,
    #[error("Failed to run `resolvectl` command")]
    RunResolveCtl,
}

impl Callbacks for CallbackHandler {
    type Error = CbError;

    /// Shells out to `resolvectl dns` to get the system DNS resolvers
    ///
    /// May return Firezone's own servers, e.g. `100.100.111.1`.
    fn get_system_default_resolvers(&self) -> Result<Option<Vec<IpAddr>>, CbError> {
        Ok(Some(get_system_default_resolvers()?))
    }

    fn on_disconnect(&self, error: Option<&connlib_client_shared::Error>) -> Result<(), CbError> {
        tracing::error!(?error, "Disconnected");
        Ok(())
    }

    fn roll_log_file(&self) -> Option<PathBuf> {
        self.handle
            .as_ref()?
            .roll_to_new_file()
            .unwrap_or_else(|e| {
                tracing::debug!("Failed to roll over to new file: {e}");
                None
            })
    }
}

fn get_system_default_resolvers() -> Result<Vec<IpAddr>, CbError> {
    // Unfortunately systemd-resolved does not have a machine-readable
    // text output for this command: <https://github.com/systemd/systemd/issues/29755>
    //
    // The officially supported way is probably to use D-Bus.
    let output = std::process::Command::new("resolvectl")
        .arg("dns")
        .output()
        .map_err(|_| CbError::RunResolveCtl)?;
    if !output.status.success() {
        return Err(CbError::ResolveCtlFailed);
    }
    let output = String::from_utf8(output.stdout).map_err(|_| CbError::ResolveCtlUtf8)?;
    Ok(parse_resolvectl_output(&output))
}

/// Parses the text output of `resolvectl dns`
///
/// Cannot fail. If the parsing code is wrong, the IP address vec will just be incomplete.
fn parse_resolvectl_output(s: &str) -> Vec<IpAddr> {
    let mut v = vec![];
    for line in s.lines() {
        for word in line.split(' ') {
            if let Ok(addr) = IpAddr::from_str(word) {
                v.push(addr);
            }
        }
    }
    v
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    /// Identifier generated by the portal to identify and display the device.
    #[arg(short = 'i', long, env = "FIREZONE_ID")]
    pub firezone_id: String,

    /// File logging directory. Should be a path that's writeable by the current user.
    #[arg(short, long, env = "LOG_DIR")]
    log_dir: Option<PathBuf>,

    /// Maximum length of time to retry connecting to the portal if we're having internet issues or
    /// it's down. Accepts human times. e.g. "5m" or "1h" or "30d".
    #[arg(short, long, env = "MAX_PARTITION_TIME")]
    max_partition_time: Option<humantime::Duration>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    #[test]
    fn parse_resolvectl_output() {
        // Typical output from `resolvectl dns` while Firezone is up
        let input = r"
Global:
Link 2 (enp0s3): 192.0.2.1 2001:db8::
Link 3 (tun-firezone): 100.100.111.1 100.100.111.2
";
        let actual = super::parse_resolvectl_output(input);
        let expected = ["192.0.2.1", "2001:db8::", "100.100.111.1", "100.100.111.2"]
            .iter()
            .map(|s| std::net::IpAddr::from_str(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(expected, actual);
    }
}
