use crate::audit::Surface;
use crate::ipc::BrowserLabel;

use super::store::{revoke_browser, RevokeBrowserError};

pub fn run_revoke_browser(label: &BrowserLabel) -> i32 {
    match revoke_browser(label, Surface::Cli) {
        Ok(revoked) => {
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
        Err(RevokeBrowserError::NotEnrolled { enrolled }) => {
            eprintln!("revoke: no browser is enrolled under '{label}'");
            if enrolled.is_empty() {
                eprintln!("no browser is enrolled at all");
            } else {
                eprintln!(
                    "enrolled labels: {} (a browser on a shared host manifest enrolls as 'default')",
                    enrolled
                        .iter()
                        .map(BrowserLabel::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            1
        }
        Err(RevokeBrowserError::Io(e)) => {
            eprintln!("revoke: could not update the trust record: {e}");
            1
        }
    }
}
