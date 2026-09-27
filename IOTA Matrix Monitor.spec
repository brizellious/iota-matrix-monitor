# Build with: python3 -m PyInstaller --noconfirm "IOTA Matrix Monitor.spec"
from pathlib import Path

root = Path(SPECPATH)
a = Analysis(
    [str(root / "iota_matrix_monitor.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[(str(root / "dashboard.html"), "."), (str(root / "matrix_hands_banner.png"), "."), (str(root / "neo_ascii.png"), ".")],
    hiddenimports=["webview", "webview.platforms.cocoa", "objc", "AppKit", "Foundation", "WebKit", "Quartz", "Security", "UniformTypeIdentifiers"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True, name="IOTA Matrix Monitor",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=True,
    console=False, disable_windowed_traceback=False, argv_emulation=False,
    target_arch=None, codesign_identity=None, entitlements_file=None, icon=str(root / "AppIcon.icns"),
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, name="IOTA Matrix Monitor")
app = BUNDLE(
    coll, name="IOTA Matrix Monitor.app",
    bundle_identifier="ai.macrocosmos.iota-matrix-monitor",
    icon=str(root / "AppIcon.icns"),
    info_plist={
        "CFBundleName": "IOTA Matrix Monitor",
        "CFBundleDisplayName": "IOTA Matrix Monitor",
        "CFBundleShortVersionString": "2.9.32",
        "CFBundleVersion": "2.9.32",
        "LSMinimumSystemVersion": "11.0",
        "NSHighResolutionCapable": True,
        "NSLocalNetworkUsageDescription": "Receive telemetry from IOTA Train at Home miner agents on your local network.",
        "LSApplicationCategoryType": "public.app-category.utilities",
        "NSPrincipalClass": "NSApplication",
    },
)
