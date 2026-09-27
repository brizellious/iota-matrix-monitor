#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
python3 -m venv .venv
export PYTHONPYCACHEPREFIX="$PWD/.python-cache"
export PIP_CACHE_DIR="$PWD/.pip-cache"
export PYINSTALLER_CONFIG_DIR="$PWD/.pyinstaller"
if ! .venv/bin/python -c "import PyInstaller, webview, PIL, AppKit, Foundation, WebKit, Quartz, Security, UniformTypeIdentifiers" 2>/dev/null; then
  .venv/bin/python -m pip install pyinstaller pywebview Pillow \
    pyobjc-core==11.1 pyobjc-framework-Cocoa==11.1 pyobjc-framework-Quartz==11.1 \
    pyobjc-framework-WebKit==11.1 pyobjc-framework-Security==11.1 \
    pyobjc-framework-UniformTypeIdentifiers==11.1
fi
.venv/bin/python make_app_icon.py
.venv/bin/python -m PyInstaller --noconfirm "IOTA Matrix Monitor.spec"
printf '\nApp bundle created at: %s\n' "$PWD/dist/IOTA Matrix Monitor.app"
pkgbuild --component "dist/IOTA Matrix Monitor.app" --install-location /Applications \
  --identifier "ai.macrocosmos.iota-matrix-monitor" --version "2.9.32" \
  "dist/IOTA-Matrix-Monitor-component.pkg"
productbuild --synthesize --package "dist/IOTA-Matrix-Monitor-component.pkg" \
  "dist/IOTA-Matrix-Monitor.dist"
productbuild --distribution "dist/IOTA-Matrix-Monitor.dist" --package-path "dist" \
  --resources "pkg-resources" --identifier "ai.macrocosmos.iota-matrix-monitor" \
  --version "2.9.32" "dist/IOTA-Matrix-Monitor-macOS.pkg"
printf 'Installer created at: %s\n' "$PWD/dist/IOTA-Matrix-Monitor-macOS.pkg"
