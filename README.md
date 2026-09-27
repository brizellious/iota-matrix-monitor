# IOTA Matrix Monitor v2.9.32

Installable Matrix/CRT-style single-miner telemetry dashboard for IOTA Train at Home (T@H). Run a separate copy on each miner Mac.

## Installable macOS app

The project builds a Finder-launchable macOS `.app` with bundled Python and a native Cocoa/WebKit window. The dashboard opens inside the app instead of a separate browser; its WebKit data stays in the app's Application Support folder.

1. On a Mac, install Python 3.9 or newer.
2. Run `./build_macos.sh` from this folder. The script installs PyInstaller in a project-local virtual environment, builds the app and creates a `.pkg` installer.
3. Run `dist/IOTA-Matrix-Monitor-macOS.pkg` and follow the installer prompts. It installs the app in `/Applications`.

This build targets the architecture of the Mac used to build it (this copy is Apple silicon). Build separately on Intel Macs for an Intel installer. The app and installer are unsigned, so Gatekeeper may warn. Before public distribution, sign and notarize them.

For development, install the build dependencies in a virtual environment and run `python3 iota_matrix_monitor.py`. The native window is provided by pywebview and macOS WebKit.

## Features

- Macrocosmos T@H API telemetry and local CLI log monitoring
- User-configured public hotkey, optional coldkey and miner ID
- Single-miner dashboard with public Bittensor wallet address detection
- No second-miner selector or Add Miner control
- Run start/kick history with preceding log warnings/errors and measured lag context
- Sticky all-run capacity and performance table with available slots, aggregate progress/loss, and a cautious flat-progress signal
- On-demand public miner lookup page for a second hotkey, current run metrics, and same-layer activation standing
- Kick timeline includes session length, time to next observed run, and system memory headroom
- Low-impact monitoring: no speed tests or recurring public-host latency probes; public telemetry refreshes every five minutes and active polling is scoped to the current run
- Upload/download measurements are read only from T@H's existing CLI log output
- Persistent SQLite history and a 24-hour queue-position timeline
- Run availability, capacity and slot alerts
- Local router latency and system load diagnostics
- Network activation and throughput telemetry
- Red Pill / Blue Pill themes and Matrix-style presentation
- Donation panel with ERC20, Solana, BTC and TAH addresses

## Runtime data and privacy

Configuration and history are stored under `~/Library/Application Support/IOTA Matrix Monitor/`. The monitor reads T@H CLI logs under `~/Library/Logs/`. Wallet detection reads the coldkey public-address file and hotkey data only to extract public SS58 addresses; secrets are not stored or transmitted. Configuration is written with owner-only permissions. The dashboard UI listens only on loopback and uses a random per-launch token for write actions.

The app sends public hotkey/miner identifiers to the configured public Macrocosmos API and reads local T@H data. Never enter seed phrases, private keys, or wallet passwords.

## Source files

- `iota_matrix_monitor.py` — monitor and local HTTP server
- `dashboard.html` — dashboard UI
- `IOTA Matrix Monitor.spec` — PyInstaller macOS app-bundle recipe
- `build_macos.sh` — build helper
- `neo_ascii.png`, `hands_pills.png` — dashboard artwork

## License

See `LICENSE.txt` for the MIT License.
