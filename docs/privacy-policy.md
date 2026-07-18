# Privacy Policy: Chromium Bridge

_Last updated: 2026-07-17_

Chromium Bridge is an open-source browser extension that connects an MCP
client (such as Claude Code, Claude Desktop, or Codex) to your local Chromium
browser through a native-messaging host that runs on your own computer. This
policy explains what the extension accesses and what it does, and does not,
do with that data.

Translations: [Simplified Chinese](./privacy-policy.zh_CN.md),
[Traditional Chinese](./privacy-policy.zh_TW.md).

## Summary

**Chromium Bridge does not collect, transmit, or sell any personal data.** It
has no analytics, no telemetry, and no remote servers. Everything the
extension does happens on your own machine: sites act only after you approve
them, and every high-risk action asks for your confirmation.

## What the extension can access

To let an approved AI agent operate the pages you are already signed into,
the extension can, **only on sites you have explicitly approved** (or on all
sites, if you enable the explicit `allowAllSites` opt-in):

- Read the content of the current page (DOM, text, form fields).
- Read cookies for the active site, including `httpOnly` cookies.
- Read web storage (`localStorage` / `sessionStorage`).
- Execute JavaScript in the page.
- Attach a local file to a page's file input (off by default; every use
  shows the exact path for confirmation).

Independent of site approval, it can read the list of open tabs (titles and
URLs) and open, focus, or close tabs; closing a tab asks for confirmation.

Credential-bearing values (cookies and web storage) are **read-only** (the
extension has no API to write or modify cookies or storage by design) and
are **masked** (JWTs, long hex strings, and long digit runs are redacted)
before being returned.

## How that data is used and where it goes

- All communication stays **on your computer**. The extension talks to a
  local native-messaging host over Chrome's native messaging channel; that
  host talks to your MCP client over a private, authenticated local socket.
- **The extension sends nothing to its authors or to any server of its
  own.** It makes no outbound network requests. What the agent reads is
  returned to the MCP client you configured, on the same machine, at your
  request; what that client then does with it (for example, sending page
  content to the AI service it uses) is governed by that client's own
  privacy policy, not this one.

## Consent and control

- **Per-site approval.** A site's pages cannot be read or acted on until
  you approve its origin in a prompt.
- **Per-action confirmation.** High-risk actions (form submissions, key
  presses, tab close, file uploads, and every JavaScript evaluation) ask for
  confirmation in an extension-owned window that web pages cannot see or
  interact with. On a Mac enrolled with Touch ID, the highest-risk actions
  require a Touch ID approval. These confirmations are on by default; each
  is a setting you control.
- **A kill switch.** You can halt all bridge activity at any time from the
  extension's options page, the desktop app, or the command line; releasing
  it requires your explicit, present approval.

## What the extension stores locally

The extension stores a small amount of configuration in the browser's local
extension storage on your device only:

- Your list of approved sites (the allowlist).
- Your extension settings/preferences.
- If you enroll, the public-key fingerprint used to verify your own
  computer's security hardware (never a private key: that stays in the
  Secure Enclave).
- A bounded, local log of recent security decisions (confirmations,
  revocations), viewable on the options page.

This data never leaves your device and is removed when you uninstall the
extension.

## Remote code

The extension does **not** load or execute remotely-hosted code. The
JavaScript that may be evaluated in a page is code you (or your MCP client,
at your direction) provide locally; it is never fetched from a remote
source.

## Data sharing and sale

Chromium Bridge does **not** sell or share your data with anyone. The only
party that receives anything is the MCP client you yourself configured and
pointed at the bridge.

## Contact

Questions or concerns: please open an issue at
<https://github.com/Vivswan/chromium-bridge/issues>.
