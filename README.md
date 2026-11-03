# SPICE Launcher RM

Python components for a remote Proxmox SPICE console launcher, intended for a workstation connecting to its own Proxmox host through Tailscale.

**Status: early development; not yet a runnable desktop application or a production-ready remote access product.** The repository currently contains the API, enrolment, credential and viewer modules plus automated tests. The GUI, launch scripts, host provisioning tool and end-to-end platform validation are still pending. There is currently no `launcher.py`, command-line application or installer to run.

This project continues the [SPICE Pool Launcher](https://github.com/TheTangledMind/spice-launcher) work by TheTangledMind. The original launcher is a separate Linux application; RM is the remote, cross-platform development effort.

## Implemented components

- Public profile parsing with an enrolled Tailscale peer ID, overlay IPv4 address, TLS hostname, pool, token ID and Proxmox CA.
- Local Tailscale status checks requiring the enrolled peer identity, address and online state.
- An HTTPS API transport connecting directly to the enrolled overlay address while verifying the original Proxmox certificate hostname and CA, with TLS 1.2 or newer.
- Pool-based VM discovery, running-state checks and fresh SPICE ticket requests.
- Validation of the ticket's selected VM/node, proxy, port and CA before generating a viewer file.
- OS credential-store adapters which reject plaintext fallback backends.
- Private temporary viewer files, direct executable invocation and cleanup after the viewer exits. Clipboard, USB and smartcard redirection are disabled in generated viewer files.
- Ten automated tests covering profile validation, peer checks, unsupported credential backends, pool removal, stopped VMs, accepted display types, tampered tickets and POSIX file cleanup.

SPICE is a VM console protocol, distinct from RDP. This code does not provide RDP or SSH access inside a guest.

## Prerequisites

For development, use Python 3.10 or newer. The current automated tests have been run on Linux with Python 3.13; native Windows and macOS behaviour is unverified.

For a future live integration you also need:

- Tailscale running on the workstation and the Proxmox host, with the CLI available on the workstation.
- Access to that host over the tailnet on TCP `8006` (Proxmox API) and `3128` (SPICE proxy).
- A running QEMU VM with QXL/SPICE, VirtIO-GPU or VirGL enabled.
- A Proxmox resource pool and a dedicated privilege-separated API token. Both the account and token need `Pool.Audit`, `VM.Audit` and `VM.Console` scoped to the pool.
- The trusted Proxmox CA and the hostname covered by the server certificate.
- A supported Remote Viewer executable and an unlocked native OS credential store.

These are integration requirements, not services installed or configured by this repository. A maintained macOS viewer and the Windows/macOS credential and file-permission paths still need native testing.

## Development setup

Clone the repository and enter it:

```bash
git clone https://github.com/TheTangledMind/spice-launcher-RM.git
cd spice-launcher-RM
```

On Linux or macOS:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -v
```

On Windows PowerShell:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -v
```

`requirements.txt` includes the intended Qt/PySide6 GUI dependency; the GUI itself has not been implemented. The current test suite uses Python's standard library and can also be run directly from the repository root:

```bash
python3 -m unittest discover -v
```

The tests use synthetic data and do not require a real Proxmox token, connect to a host, or change network configuration. The POSIX permission assertions are not evidence of Windows DACL correctness.

## Enrolment and configuration

[`examples/profile.json.example`](examples/profile.json.example) is a public template with no credentials. Replace its placeholders with values obtained from your host through an already trusted channel, and save your working copy outside the repository. The template's certificate text is deliberately blank guidance and cannot authenticate a server until replaced with the real PEM CA certificate.

| Field | Meaning |
| --- | --- |
| `version` | Profile format version, currently `1` |
| `label` | Friendly host name |
| `peer_id` | Stable Tailscale ID of the Proxmox host |
| `peer_ip` | That host's Tailscale IPv4 address in `100.64.0.0/10` |
| `tls_name` | Original hostname covered by the Proxmox HTTPS certificate; not necessarily the Tailscale DNS name |
| `pool` | Resource pool containing the authorised QEMU VMs |
| `token_id` | API token identifier such as `spice-rm@pve!desktop`; not its secret |
| `ca_pem` | Trusted Proxmox CA certificate, including PEM headers and JSON-escaped newlines |

The code computes a SHA-256 fingerprint of the profile's CA text for enrolment. The planned import interface must compare this through a trusted channel; that trust-confirmation interface and host export tool do not exist yet. Loading a profile alone is not a completed secure enrolment process.

API secrets are passed to `security.set_secret(profile, secret)` and retrieved from the native OS credential store; they are not fields in the public profile. There is no plaintext fallback. Do not hard-code secrets in scripts, put them in shell command arguments or commit them. Working profiles, private keys, local credentials, temporary viewer files and generated artefacts should remain outside Git.

## Current library usage

The modules can be imported from the repository root. For example, validate a public profile without accessing a token or contacting a server:

```python
from spice_rm.profile import Profile

profile = Profile.load('/path/outside/repository/profile.json')
print(profile.label)
print(profile.ca_fingerprint)
```

For application development, `api.Client(profile).members()` retrieves the configured pool and `connection_file(vmid)` requests and validates a fresh console ticket. `viewer.open_viewer(text)` launches a locally installed Remote Viewer. These calls require the live prerequisites above. Connection-file contents contain a short-lived credential: do not print or log them.

## Security scope and limitations

- Treat this as development code, not a completed or independently audited security product.
- Tailscale access grants and the host firewall must be configured separately. The application does not establish or enforce a complete host firewall policy.
- Do not expose ports `8006` or `3128` directly to the public internet, or publish them using Tailscale Funnel.
- A public profile is trust-sensitive even though it contains no API secret. Authenticate its source before using it.
- No live HTTPS/SPICE session or certificate-mismatch integration test has been demonstrated for RM. Existing unit tests do not establish end-to-end security.
- Native Windows credential storage/DACL handling, macOS Keychain/viewer compatibility and Linux desktop secret-service integration remain unverified.
- Pool membership is administrator-controlled in Proxmox. No pool-edit, VM configuration, start, stop or delete features are supplied.
- Revoking pool access or a token does not guarantee termination of an already connected console.
- Software running as the same user, an administrator or a compromised endpoint can still access credentials or sessions.
- Cluster support, multi-host orchestration and RDP are outside the current scope.

## Source layout and development status

| Path | Responsibility |
| --- | --- |
| `spice_rm/profile.py` | Public enrolment profile validation and identity |
| `spice_rm/security.py` | Native credentials and private files |
| `spice_rm/network.py` | Tailscale status and peer verification |
| `spice_rm/api.py` | Proxmox HTTPS transport and console requests |
| `spice_rm/viewer.py` | SPICE file validation and viewer invocation |
| `tests/` | Existing automated tests |
| `docs/DESIGN.md` | Target design, including unimplemented functionality |
| `docs/PLAN.md` | Remaining implementation tasks |
| `WORKING-NOTES.md` | Current implemented, proposed and unverified state |

Contributions should retain certificate validation, restricted token scope and private credential handling. Run the test suite after relevant code changes, and record native platform or live-session validation separately from unit-test results.

## Licence

GNU General Public License version 3. See [LICENSE](LICENSE).
