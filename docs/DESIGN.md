# SPICE Launcher RM design

This is the target design, not a statement that all features below exist. See README.md and WORKING-NOTES.md for implemented versus pending functionality. In particular, the GUI, host setup/export tool, enrolment confirmation and firewall assets are not implemented.

Approved scope: one student workstation (Linux, macOS or Windows) connecting to its own Debian/Proxmox host over Tailscale. Cross-platform Python source and launch scripts; no full installers or custom server daemon. Preserve the existing launcher.

## Security boundary

Use existing Tailscale and Proxmox services. Enrol a stable Tailscale peer ID and explicit IPv4 address. Verify the local Tailscale backend is running and the peer ID owns that address before requests and immediately before ticket creation. Connect the HTTPS socket directly to that IP; validate the CA chain and the original Proxmox certificate hostname with TLS 1.2 or newer. No DNS fallback, redirects, HTTP proxies or disabled certificate checks. The SPICE proxy is the same verified peer IP, and the guest TLS configuration must contain the enrolled Proxmox CA.

Bootstrap trust through a root-generated public profile/CA and a SHA256 fingerprint compared with the host through an existing trusted channel. The fingerprint identifies CA material, not a replacement for hostname/chain verification. A separate token file is transferred privately and entered into the OS credential store. No plaintext credential fallback. Allow only explicitly selected native keyring backends; the current implementation has not received an independent security audit.

An imported profile is data: validate all fields and size bounds; it cannot select executables or pass command arguments. Viewer executable selection is local and explicit. Invoke with an argument list, never a shell. Allow only known .vv fields; verify ticket VM/node and proxy; clipboard and USB redirection default off. Per-session private files use POSIX owner permissions or a Windows protected DACL and are cleaned after viewer exit/failure.

The host setup script defaults to a command preview. Explicit --apply creates new dedicated account, pool and minimal role, plus a privilege-separated expiring token. Export files outside the repo in a new root-only directory; never print the secret. Do not overwrite existing accounts/roles or modify certificates. Supply an optional nftables guard and systemd unit restricting inbound API/SPICE to tailscale0/loopback; require explicit administrator installation after reviewing management access. Tailscale grants must restrict device access; remove broad allow-all grants. Never expose via Funnel.

## User experience

Qt/PySide6 window with VM cards, search, refresh, settings/enrolment and connection feedback. Display stopped machines without Connect. Recheck membership/state on Connect. One host profile initially. GUI threads keep networking off the UI thread. Demo mode uses sample data and never reads credentials or connects. CLI doctor checks dependencies, keyring and Tailscale without exposing secrets.

## Limits

Native Windows/macOS checks and actual remote consoles need those systems and authorised test credentials. Do not call this production certified based on Linux tests. Pool membership is manual. No start/stop, RDP, clusters or broader routing. OS/root compromise, guest compromise and malicious same-user software are outside protection offered by the launcher. In-session revocation needs explicit viewer/VM management.
