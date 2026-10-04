//! The capability catalogue for connection-time negotiation. Each capability
//! groups tools that share a Chrome permission and scope; its id and
//! description are hand-authored here, the tools it covers are read off the
//! tool catalogue (every bridge tool's record names exactly one capability,
//! so coverage is by construction). On connect, the extension and host
//! advertise which capability ids are actually available (permission
//! granted, tool enabled) and the server negotiates against that list: a
//! tool is callable only if its capability is advertised.

use super::catalogue::{all, Permission, Tool};

/// A negotiable capability's stable wire id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityId {
    TabControl,
    PageSnapshot,
    PageSnapshotPrecise,
    PageInteract,
    PageRead,
    PageEval,
    CookieRead,
    StorageRead,
    ConsoleRead,
    DialogControl,
    FileUpload,
}

/// One negotiable capability: its id, the Chrome permissions it needs, and
/// (via [`CapabilityId::tools`]) the catalogue tools it covers.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    pub id: CapabilityId,
    pub description: &'static str,
    pub permissions: &'static [Permission],
}

impl CapabilityId {
    pub fn as_str(self) -> &'static str {
        match self {
            CapabilityId::TabControl => "tab_control",
            CapabilityId::PageSnapshot => "page_snapshot",
            CapabilityId::PageSnapshotPrecise => "page_snapshot_precise",
            CapabilityId::PageInteract => "page_interact",
            CapabilityId::PageRead => "page_read",
            CapabilityId::PageEval => "page_eval",
            CapabilityId::CookieRead => "cookie_read",
            CapabilityId::StorageRead => "storage_read",
            CapabilityId::ConsoleRead => "console_read",
            CapabilityId::DialogControl => "dialog_control",
            CapabilityId::FileUpload => "file_upload",
        }
    }

    /// The catalogue tools negotiated under this capability.
    pub fn tools(self) -> impl Iterator<Item = Tool> {
        all().filter(move |t| t.capability() == Some(self))
    }

    pub fn capability(self) -> Capability {
        match self {
            CapabilityId::TabControl => Capability {
                id: self,
                description:
                    "Enumerate, focus, open, close browser tabs, navigate history (back/forward/reload), \
                     navigate the active tab to a URL, and capture the visible viewport. Opening, \
                     navigating, and history moves are gated by the allowlist; closing a tab is \
                     confirmed in-page.",
                permissions: &[Permission::Tabs],
            },
            CapabilityId::PageSnapshot => Capability {
                id: self,
                description:
                    "Capture the active tab's interactive elements as an accessibility-style tree via \
                     the content script (fast approximation, ~90% coverage).",
                permissions: &[Permission::Scripting],
            },
            CapabilityId::PageSnapshotPrecise => Capability {
                id: self,
                description: "Capture the authoritative accessibility tree via Chrome's debugger (CDP \
                     Accessibility.getFullAXTree). Requires the debugger permission and briefly shows \
                     the 'Started debugging this browser' banner.",
                permissions: &[Permission::Debugger],
            },
            CapabilityId::PageInteract => Capability {
                id: self,
                description: "Drive the page: click elements, fill form fields, press keys, hover, choose \
                     <select> options, scroll, and wait for conditions. High-risk clicks, key presses, \
                     and selections trigger an on-page confirmation Toast.",
                permissions: &[Permission::Scripting],
            },
            CapabilityId::PageRead => Capability {
                id: self,
                description: "Read the active tab's visible text content (sensitive fields masked).",
                permissions: &[Permission::Scripting],
            },
            CapabilityId::PageEval => Capability {
                id: self,
                description:
                    "Execute arbitrary JavaScript on the active tab. Highest-risk capability: every call \
                     requires explicit user approval and return values are masked by default.",
                permissions: &[Permission::Scripting],
            },
            CapabilityId::CookieRead => Capability {
                id: self,
                description:
                    "Read cookies (including httpOnly) for allowlisted hosts. Read-only; values are \
                     masked. Backed by chrome.cookies in the service worker.",
                permissions: &[Permission::Cookies],
            },
            CapabilityId::StorageRead => Capability {
                id: self,
                description:
                    "Read the active tab's localStorage / sessionStorage (same-origin only). Read-only; \
                     values are always masked.",
                permissions: &[Permission::Scripting],
            },
            CapabilityId::ConsoleRead => Capability {
                id: self,
                description:
                    "Read recent console output from the active tab via Chrome's debugger. Values are \
                     masked. Briefly shows the 'Started debugging this browser' banner.",
                permissions: &[Permission::Debugger],
            },
            CapabilityId::DialogControl => Capability {
                id: self,
                description:
                    "Accept or dismiss JavaScript dialogs (alert / confirm / prompt) via Chrome's \
                     debugger. High-risk and OFF by default (must be enabled in settings).",
                permissions: &[Permission::Debugger],
            },
            CapabilityId::FileUpload => Capability {
                id: self,
                description: "Attach a local file to a page file input via Chrome's debugger \
                     (DOM.setFileInputFiles). Critical-risk local-file egress vector: OFF by default and \
                     confirmed on every call.",
                permissions: &[Permission::Debugger],
            },
        }
    }
}

/// Every capability some catalogue tool is negotiated under, in order of
/// first appearance in the catalogue. A capability no tool names is not
/// advertised: there would be nothing to negotiate.
pub fn capabilities() -> Vec<Capability> {
    let mut seen: Vec<CapabilityId> = Vec::new();
    for tool in all() {
        if let Some(id) = tool.capability() {
            if !seen.contains(&id) {
                seen.push(id);
            }
        }
    }
    seen.into_iter().map(CapabilityId::capability).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // A capability's declared permissions must be exactly what its tools
    // need: the extension requests permissions per advertised capability, so
    // an under-declaration breaks a tool at runtime and an over-declaration
    // asks the user for more than the tools use.
    #[test]
    fn capability_permissions_are_the_union_of_tool_permissions() {
        for c in capabilities() {
            let from_tools: BTreeSet<&str> = c.id.tools().map(|t| t.permission.as_str()).collect();
            let declared: BTreeSet<&str> = c.permissions.iter().map(|p| p.as_str()).collect();
            assert_eq!(declared, from_tools, "capability {}", c.id.as_str());
        }
    }
}
