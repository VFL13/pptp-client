# PPTPClient for macOS

Experimental native IPv4 PPTP client for Apple Silicon. The CLI implements
PPTP control, GRE flow control, PPP LCP, PAP, IPCP, utun, explicit split routes
and optional supplemental DNS. PAP mode has no encryption.

## CLI v1

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

The v1 baseline passes 51 local tests plus four TCP transport smoke tests.
Lost GRE acknowledgments recover the send window rather than disconnecting;
PPP/PPTP keepalives detect an unresponsive peer.

## Status

A native SwiftUI application, menu bar control and an installed privileged
helper are being developed in `codex/v2-ui`. The CLI remains supported.

## Protocols

[RFC 2637](https://www.rfc-editor.org/rfc/rfc2637.html),
[RFC 1661](https://www.rfc-editor.org/rfc/rfc1661.html),
[RFC 1334](https://www.rfc-editor.org/rfc/rfc1334.html),
[RFC 1332](https://www.rfc-editor.org/rfc/rfc1332.html),
[RFC 1877](https://www.rfc-editor.org/rfc/rfc1877.html).
