# PPTPClient for macOS — v2

Experimental native IPv4 PPTP client for Apple Silicon. The CLI implements
PPTP control, GRE flow control, PPP LCP, PAP, IPCP, utun, explicit split routes
and optional supplemental DNS. PAP mode has no encryption.

Native SwiftUI window and menu bar app for macOS 26 on Apple Silicon. One editable
profile, manual connect/disconnect, JSON import/export, split routes and DNS settings.
The window may be closed while connected; quitting or losing the app's XPC connection
stops the session. Sleep requests disconnection; reconnect manually after waking.

## Install and use

Build the matching app and installer on the target Mac:

```sh
bash scripts/build-app.sh
```

An optional output directory can be supplied, for example
`bash scripts/build-app.sh dist/v2`.

Open `dist/PPTPClient.pkg` in macOS Installer and enter the administrator password
in the system dialog. Installation places `PPTPClient.app` in `/Applications` and
registers an on-demand launchd helper. Open the installed app, import your existing
JSON using **Импорт JSON…**, enter the VPN login/password and click **Подключить**.
On first launch, the connection tab prompts you to import a profile or enter settings.
The package authorizes the Mac user signed in at installation time; install while
signed in as the intended user. Only one active session is supported.

The **Сети** tab edits CIDR routes. **DNS** accepts supplemental domains and optional
DNS server addresses. Without domains the system DNS settings are unchanged. JSON
import/export uses the same format as the CLI. The exported configuration contains
neither login nor password. The profile, including the login, is stored in
`~/Library/Application Support/PPTPClient/profile.json` with mode 0600. An optional
password is written to Keychain only after the server accepts authentication.
Passwords are excluded from JSON and diagnostic logs. There is no automatic connect
or reconnect.

Both binaries use local ad-hoc signatures. The package is unsigned and is not
notarized; this is a local build workflow, not a public signed distribution. Install
app and helper together with the same package after each rebuild. Do not replace
one binary independently: the installation pins the exact build's code requirements.
Apple Developer ID signing and Network Extension are outside this version's scope.

## Remove or update

Disconnect, then open **Диагностика → Удалить служебный компонент…**. This removes
the launchd job, helper and trust manifest. Quit the app and move
`/Applications/PPTPClient.app` to Trash. To delete saved credentials, use
**Забыть сохранённый пароль** first; remove the Application Support directory
separately if you also want to delete the profile. For an update, quit the app and
run the new matching package. The installer stops the previous helper before
replacing it.

## CLI

The original CLI baseline is preserved at tag `v1.0.0-cli`. The v2 branch keeps
the CLI using the same VPN runtime as the graphical app.

```sh
swift build
swift test
python3 scripts/transport-smoke.py .build/debug/pptp-client
cp config/example.json config/work.json
```

Edit the local config with your VPN server and routes, then run:

```sh
sudo .build/debug/pptp-client connect --config config/work.json
```

Credentials are requested in the terminal and never stored in JSON. Ctrl+C
disconnects and removes the session's routes. `--check-only` authenticates and
negotiates an address without creating an interface or changing routes/DNS.
The example uses documentation-only addresses. `config/work.json` is local
and ignored by Git. Never commit credentials, certificates, or diagnostic logs.

The v1 baseline has 51 core tests plus four TCP transport smoke tests.
Lost GRE acknowledgments recover the send window rather than disconnecting;
PPP/PPTP keepalives detect an unresponsive peer.

## Helper and validation

The GUI runs as a regular user. Only the helper creates GRE/utun, routes and temporary
DNS settings. XPC checks the pinned client signature and installed owner UID;
the app checks the helper signature. The root-owned trust policy is stored at
`/Library/Application Support/PPTPClient/trust.plist`. The helper independently
validates configuration and exposes no arbitrary command execution. Credentials
are passed through IPC and are never persisted by the helper.

Run `swift test` for protocol, lifecycle, profile, model, Keychain and XPC trust
tests, and the transport smoke command above for TCP framing/timeouts. The real
Keychain test uses a new temporary item and removes it afterward; it can skip if
the login keychain is unavailable. Wrong-signature rejection is exercised using
a local anonymous XPC listener; owner UID rejection is unit-tested. With a working
installed app/helper, also check that a separate executable cannot call the service:

```sh
xcrun swiftc scripts/check-helper-rejection.swift -module-cache-path .build/ModuleCache -o .build/check-helper-rejection
.build/check-helper-rejection
```

The probe sends only `hello` and does not alter a VPN session. Run it only after
confirming the installed app can reach the helper: an unavailable service also
rejects a connection. The local validation run passed 63 tests, four TCP smoke
checks, the installed app/helper handshake and this untrusted-client probe.

Actual VPN reachability requires a local profile and credentials entered by the
user. Manual acceptance checks: connect, verify an internal service, close the
window and verify it remains connected, reopen from the menu, disconnect and
reconnect, then quit and confirm the VPN routes disappear. Repeat with force-quit
to verify XPC-loss cleanup. These checks cannot be replaced by the automated tests.

## Protocols

[RFC 2637](https://www.rfc-editor.org/rfc/rfc2637.html),
[RFC 1661](https://www.rfc-editor.org/rfc/rfc1661.html),
[RFC 1334](https://www.rfc-editor.org/rfc/rfc1334.html),
[RFC 1332](https://www.rfc-editor.org/rfc/rfc1332.html),
[RFC 1877](https://www.rfc-editor.org/rfc/rfc1877.html).
