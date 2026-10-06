//! CLI runner: `revoke <browser>`.

use crate::audit::Surface;
use crate::ipc::BrowserLabel;

use super::store::revoke_browser;

/// `chromium-bridge revoke <browser>`: forget that browser's enrolled authenticators. Returns a process exit
/// code.
pub fn run_revoke_browser(label: &BrowserLabel) -> i32 {
    match revoke_browser(label, Surface::Cli) {
        Ok(Some(revoked)) => {
            println!(
                "forgot browser '{label}' ({} enrolled credential{})",
                revoked.forgotten.len(),
                if revoked.forgotten.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
            println!(
                "its authenticator no longer vouches for this bridge; the browser enrolls again from its \
                 options page"
            );
            if revoked.trust.enrollments().is_empty() {
                println!(
                    "no browser is enrolled now: the next enrollment is first-time (trust on first use)"
                );
            }
            0
        }
        Ok(None) => {
            eprintln!("revoke: no browser is enrolled under '{label}'");
            1
        }
        Err(e) => {
            eprintln!("revoke: could not write the trust record: {e}");
            1
        }
    }
}
