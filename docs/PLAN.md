# SPICE Launcher RM implementation plan

Goal: runnable cross-platform Python client and reviewable host setup tooling under docs/DESIGN.md.

User authorised autonomous implementation; execute inline, no redundant permission gates or worktree needed in this new isolated repository. Commit/push only with explicit user authorisation (granted for the 2026-11-03 publication repair). This is a target checklist, not completed-work evidence; see WORKING-NOTES.md for the current partial implementation.

- [ ] Enrolment/profile, native secret storage, private files: test hostile profile data, bad backend, POSIX/Windows permissions and no secret persistence.
- [ ] Tailscale identity + pinned HTTPS API + viewer: test wrong peer/offline, wrong CA/hostname, redirects, membership removal, SPICE response tampering and cleanup.
- [ ] Host tools: dry-run default, explicit apply, collision refusal, private exports, expiring tokens, reviewable grants/guard/rollback.
- [ ] Qt GUI + CLI + launch scripts: demo, import trust confirmation, settings, search, connections and dependency diagnostics.
- [ ] Docs and focused verification: Linux integration tests/UI rendering; provide native OS test workflow and explicit remaining live tests. Independent security review of final source if practical.

Review focus: different cert hostname vs overlay address; keyring fallback; imported profile command injection; Windows DACL; host firewall existing rules/rollback.
