//! The privilege gate in front of both commands: who runs them, judged once, against the scope they name.

use crate::browsers::Scope;

/// Who runs the command, read once per command. Unix root is a different account from the one whose
/// browser is to be registered (its HOME is `/root`, or a sudo caller's with root as owner), with no browser
/// of its own; a Windows elevated token is the same account with HKLM writable as well.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    User,
    Root,
    Elevated,
}

impl Privilege {
    #[cfg(unix)]
    pub fn current() -> Privilege {
        if nix::unistd::geteuid().is_root() {
            Privilege::Root
        } else {
            Privilege::User
        }
    }

    /// Elevation is judged by the capability the scope needs: a handle on HKLM with write access, which UAC's
    /// filtered token is refused. Any failure to open it reads as not elevated, so the check fails closed.
    #[cfg(windows)]
    pub fn current() -> Privilege {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_SET_VALUE};
        match winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags("SOFTWARE", KEY_SET_VALUE)
        {
            Ok(_) => Privilege::Elevated,
            Err(_) => Privilege::User,
        }
    }

    /// Whether this privilege may write `scope`, with the refusal that names the way out. Both mismatches
    /// fail closed: a user cannot write the system directories, and root must not write into a home (the
    /// macOS .pkg's post-install mirrors this by refusing to run `doctor --fix` as root).
    pub fn admit(self, scope: Scope) -> Result<(), String> {
        match (self, scope) {
            (Privilege::User, Scope::User)
            | (Privilege::Root, Scope::System)
            | (Privilege::Elevated, Scope::User | Scope::System) => Ok(()),
            (Privilege::User, Scope::System) => Err(
                "--system writes the root-owned directories every account's browser reads; run it as \
                 root (sudo), or drop --system to register for this account"
                    .into(),
            ),
            (Privilege::Root, Scope::User) => Err(
                "running as root, which has no browser of its own: pass --system for the machine-wide \
                 registration, or run this as the account whose browser it is"
                    .into(),
            ),
        }
    }
}
