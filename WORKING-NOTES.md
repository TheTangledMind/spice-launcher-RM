# SPICE Launcher RM working notes

## Implemented

Core modules for public profile validation, native credential-store selection, private session files, Tailscale peer verification, pinned-address HTTPS API calls, pool membership checks, SPICE ticket validation and viewer invocation. The existing ten unit tests pass on Linux/Python 3.13. Target architecture is in docs/DESIGN.md and remaining work is in docs/PLAN.md.

## Pending and unverified

GUI, client launch scripts, host provisioning/export tool, enrolment trust-confirmation UI, Tailscale grants/firewall assets and production hardening remain unfinished. No native Windows/macOS validation or RM live authenticated HTTPS/SPICE session has been demonstrated. No host, VM, firewall or tailnet deployment has been performed.

## Publication repair — 2026-11-03

The outer project had no commits and its GitHub remote was empty. A nested local repository contained a user-created initial README/licence commit. That commit was imported into the outer repository's local history. The nested repository remains locally preserved and ignored; it is not a submodule. Existing licence and text-normalisation settings are retained.

Andrew explicitly authorised the commit and push for this publication task. This exception does not authorise unrelated feature work or infrastructure deployment. README now describes the actual early-development status, prerequisites, examples and limitations. No instruction or commit-note files were tracked. Ignore rules cover nested instruction files, local notes, credentials and generated/local artefacts.

The shell's HTTPS push failed because no GitHub username/credential helper is configured. The authenticated GitHub connector has write permission and is being used to publish. The original local initial/publication commits will remain on `local-publication-history`, while `main` will track the published GitHub branch. Routine future shell pushes still require GitHub authentication to be configured; connector access does not install a Git credential helper.

No automatic restart/resume is assumed active. Do not create a new one without a user request.
