# Local v2 validation

Validated on 2026-11-16, Apple M1, macOS 26.6.2 (25G83).
Personal server addresses, account names and network configuration are intentionally
excluded from this report and the public repository.

## Automated checks

- 51 existing protocol/core tests passed.
- 12 application tests passed: profile round-trip and export, model states,
  cancellation, stale callbacks, failed authentication, session ownership,
  UID/protocol trust policy, Keychain and wrong-signature XPC rejection.
- The real Keychain round-trip used and removed a unique temporary test item.
- Four TCP transport checks passed: fragmented/coalesced frames, truncated
  responses, invalid magic cookie and a shared operation timeout.
- Release app and helper compiled; strict ad-hoc signature verification passed.
- Both installed code requirements contain actual pinned cdhash values and match
  their binaries. Build and install scripts fail if a requirement is missing or
  does not match. Installer bundle relocation is disabled.
- A separately compiled client was refused by the installed XPC service while
  the installed GUI could reach it. Different-UID rejection is unit-tested;
  a second macOS login account was not used for a live UID test.

## Live checks

- The package installed the app in `/Applications` and registered the on-demand
  root helper. The GUI connected to the helper as the regular installing user.
- Existing JSON imported all five local subnets.
- The user connected with PAP/no encryption, reached an internal service, and
  confirmed normal disconnection.
- Reconnection using Keychain succeeded without re-entering the password.
- Closing the main window preserved the connection. The internal subnet route
  remained on the PPTP utun interface; two ICMP probes returned with zero loss.
- Normal application quit removed the PPTP interface routes.
- After another connection, SIGKILL terminated the GUI. Loss of XPC caused the
  helper to clean up; the internal address again resolved through the previously
  existing non-PPTP route. Relaunch showed disconnected with the profile intact.
- The user confirmed all menu-bar commands: connect, disconnect, open the main
  window and quit, including preserving VPN after closing the window and
  disconnecting on quit.
- One unattended session reported `PPP keepalive timed out`; the failure reason
  appeared in the GUI and manual reconnection succeeded. This check does not
  establish long-duration connection reliability.

The live sleep/wake and helper-uninstall flows have not been exercised. Supplemental DNS behavior is
implemented but was not exercised with the local profile, which has no DNS domains.
