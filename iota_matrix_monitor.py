#!/usr/bin/env python3
import os, re, json, ast, time, sqlite3, threading, webbrowser, urllib.request, urllib.error, urllib.parse, gzip, zlib, hashlib, subprocess, secrets, tempfile, sys, ssl, socket, http.client, uuid, copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from datetime import datetime, timezone
from collections import deque

DEFAULT_PORT = 8765
LOCAL_TOKEN = secrets.token_urlsafe(32)
PORT = DEFAULT_PORT
DB = Path.home() / "Library" / "Application Support" / "IOTA Matrix Monitor" / "history.sqlite3"
LOG_ROOT = Path.home() / "Library" / "Logs"
MINER_ID = ""
DEFAULT_HOTKEY = ""
DEFAULT_COLDKEY = ""
DEFAULT_MINER_NAME = "HOTONE"
RESOLVED_MINER_ID = ""
CONFIG = Path.home() / "Library" / "Application Support" / "IOTA Matrix Monitor" / "config.json"
SUPPORT_DIR = CONFIG.parent
MINERS_FILE = SUPPORT_DIR / "miners.json"
REPORTS_DIR = SUPPORT_DIR / "miner-reports"
HUB_CERT = SUPPORT_DIR / "hub-cert.pem"
HUB_KEY = SUPPORT_DIR / "hub-key.pem"
AGENT_CONFIG = SUPPORT_DIR / "agent.json"
AGENT_PORT = 8766
API_BASE = "https://iota-web.api.macrocosmos.ai/mainnet"
# Public API polling is deliberately infrequent and only reads telemetry. The
# monitor never starts a speed test or probes public hosts while the miner is active.
REMOTE_POLL_SECONDS = 300
API_RUNS = API_BASE + "/runs"
API_RUNS_OCCUPANCY = API_BASE + "/v1/runs_occupancy"
API_MINERS = API_BASE + "/miners"
API_THROUGHPUT = API_BASE + "/v1/throughput_statistics"
API_EPOCH_METRICS = API_BASE + "/v1/epoch_miner_scores/runs/{run_id}/hotkeys/{hotkey}/metrics"
API_ENTITLEMENTS = API_BASE + "/v1/entitlements/history/hotkey/{hotkey}"
API_RUN_PROGRESS = API_BASE + "/progress?run_id="
DONATIONS = {
    "ERC20": "0x59960b005519F7e3bEf269eFd577d3e2F8687eD7",
    "Solana": "GhPW8F1WVxtn27Lvgz9DSVF7K2Ry8XHMmShMNn6Y2vrB",
    "BTC": "bc1q3amhttk6zk0z2ffr4xz8655pjxguc8kga005u0",
    "TAH": "5ELuFz8SntDZdWWy3mWPi377LRKXvWhEfHJqXYEFtWiwDHTg"
}
PROTOCOL_URL = "http://127.0.0.1:8010"
VIZ_URL = "http://127.0.0.1:8009"
DASHBOARD_URL = f"http://127.0.0.1:{PORT}/"

DB.parent.mkdir(parents=True, exist_ok=True)

def resolve_log_dir(configured=""):
    """Use an explicit folder when configured; otherwise find the T@H log folder."""
    configured=str(configured or "").strip()
    if configured:
        path=Path(configured).expanduser().resolve()
        if not path.is_dir():
            raise ValueError("The configured log folder does not exist or is not a folder")
        return path
    candidates=[LOG_ROOT / "IOTA Train at Home", LOG_ROOT]
    app_support=Path.home() / "Library" / "Application Support"
    candidates.extend([app_support / "IOTA Train at Home" / "logs", app_support / "Train At Home" / "logs"])
    for base in candidates:
        if base.is_dir() and any(base.glob("*-cli.log")):
            return base
    # Common installs sometimes put dated CLI logs below the app log folder.
    for base in (LOG_ROOT, app_support / "IOTA Train at Home", app_support / "Train At Home"):
        if base.is_dir():
            try:
                found=next(base.glob("**/*-cli.log"),None)
                if found:
                    return found.parent
            except (OSError, PermissionError):
                pass
    return LOG_ROOT / "IOTA Train at Home"

HOTKEY_RE = re.compile(r"(?i)(?:source[_ ]hotkey|miner[_ ]hotkey|hotkey)\s*[:=]\s*[\"']?(5[1-9A-HJ-NP-Za-km-z]{46,47})")
SS58_RE = re.compile(r"(?<![A-Za-z0-9])(5[1-9A-HJ-NP-Za-km-z]{46,47})(?![A-Za-z0-9])")
# The T@H logger abbreviates the local miner identity in messages like
# "Miner 5GHWGVa2 ...". Eight characters are enough to resolve the full
# hotkey while avoiding unrelated peer addresses.
MINER_PREFIX_RE = re.compile(r"(?i)\bMiner\s+(5[1-9A-HJ-NP-Za-km-z]{7})\b")

def detect_bittensor_wallets():
    """Return public wallet addresses only; never open the coldkey secret file."""
    root=Path.home()/".bittensor"/"wallets"
    if not root.is_dir():return []
    def address_from(path):
        try:
            raw=path.read_text(encoding="utf-8",errors="replace")
            try:obj=json.loads(raw)
            except Exception:obj=None
            found=[]
            def visit(node):
                if isinstance(node,dict):
                    for key,value in node.items():
                        norm=re.sub(r"[^a-z]","",str(key).lower())
                        if norm in ("ss58address","ss58","address") and isinstance(value,str) and SS58_RE.fullmatch(value.strip()):found.append(value.strip())
                        elif isinstance(value,(dict,list)):visit(value)
                elif isinstance(node,list):
                    for value in node:visit(value)
            if obj is not None:visit(obj)
            if not found:
                m=SS58_RE.search(raw)
                if m:found.append(m.group(1))
            return found[0] if found else ""
        except (OSError,PermissionError):return ""
    wallets=[]
    try:dirs=sorted((p for p in root.iterdir() if p.is_dir() and not p.is_symlink()),key=lambda p:p.name.lower())
    except OSError:return []
    for wallet_dir in dirs:
        coldkey=address_from(wallet_dir/"coldkeypub.txt")
        hotkeys_dir=wallet_dir/"hotkeys"
        try:hotkey_files=sorted((p for p in hotkeys_dir.iterdir() if p.is_file() and not p.is_symlink()),key=lambda p:p.name.lower())
        except OSError:continue
        for hotkey_file in hotkey_files:
            hotkey=address_from(hotkey_file)
            if hotkey and coldkey:
                wallets.append({"label":f"{wallet_dir.name} / {hotkey_file.name} · {hotkey[:8]}…","wallet":wallet_dir.name,"hotkey_name":hotkey_file.name,"hotkey":hotkey,"coldkey":coldkey})
    return wallets

def detect_hotkey_from_logs():
    """Find THIS Mac's miner hotkey from its local T@H CLI logs.

    The logs contain many peer hotkeys, so arbitrary SS58 frequency is not a
    safe selector. We first identify the local miner's short prefix from its
    own ``Miner XXXXXXXX`` messages and then resolve that prefix to the full
    SS58 hotkey found in the same log set. Only if that signal is unavailable
    do we consider explicitly labelled hotkey fields.
    """
    try:
        files=sorted(LOG_DIR.glob("*-cli.log"), key=lambda p:p.stat().st_mtime, reverse=True)[:5]
    except Exception:
        return ""
    texts=[]
    for p in files:
        try:
            texts.append(p.read_text(errors="replace"))
        except Exception:
            pass
    if not texts:
        return ""

    from collections import Counter

    # 1) Identify the local miner prefix, then resolve it to a full SS58
    # address. This prevents a coldkey or peer hotkey being selected.
    prefixes=[]
    for text in texts:
        prefixes.extend(m.group(1) for m in MINER_PREFIX_RE.finditer(text))
    if prefixes:
        prefix=Counter(prefixes).most_common(1)[0][0]
        candidates=[]
        for text in texts:
            for addr in SS58_RE.findall(text):
                if addr.startswith(prefix):
                    candidates.append(addr)
        if candidates:
            return Counter(candidates).most_common(1)[0][0]

    # 2) Secondary signal: explicitly labelled hotkey fields only.
    # Never choose an arbitrary SS58 address, because coldkeys and peer
    # identities are also valid SS58 addresses.
    explicit=[]
    for text in texts:
        explicit.extend(m.group(1) for m in HOTKEY_RE.finditer(text))
    if explicit:
        return Counter(explicit).most_common(1)[0][0]
    return ""

def load_config():
    defaults={"name":DEFAULT_MINER_NAME,"hotkey":"","coldkey":"","miner_id":"","log_dir":""}
    try:
        obj=json.loads(CONFIG.read_text())
        if isinstance(obj,dict):
            for k in defaults:
                if k in obj and obj[k] is not None:
                    defaults[k]=str(obj[k])
    except Exception:
        pass
    # Hotkey is deliberately user-configured. Never infer it from the local
    # logs because the logs contain many SS58 addresses, including coldkeys
    # and peer identities.
    if defaults["hotkey"] == defaults["coldkey"] and defaults["hotkey"]:
        defaults["hotkey"] = ""
    return defaults

def save_config(cfg):
    CONFIG.parent.mkdir(parents=True,exist_ok=True)
    payload=json.dumps({
        "name":str(cfg.get("name",DEFAULT_MINER_NAME)).strip() or DEFAULT_MINER_NAME,
        "hotkey":str(cfg.get("hotkey","")).strip(),
        "coldkey":str(cfg.get("coldkey","")).strip(),
        "miner_id":str(cfg.get("miner_id","")).strip(),
        "log_dir":str(cfg.get("log_dir","")).strip()
    },indent=2)
    fd,tmp=tempfile.mkstemp(prefix="config-",suffix=".tmp",dir=str(CONFIG.parent))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            f.write(payload); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,CONFIG)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

CFG=load_config()
LOG_DIR=resolve_log_dir(CFG.get("log_dir"))

def atomic_json(path, obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=path.stem+"-",suffix=".tmp",dir=str(path.parent))
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(obj,f,indent=2);f.flush();os.fsync(f.fileno())
        os.replace(tmp,path)
    finally:
        try:os.unlink(tmp)
        except FileNotFoundError:pass

def load_miners():
    try:
        obj=json.loads(MINERS_FILE.read_text())
        if isinstance(obj,dict) and isinstance(obj.get("miners"),list):
            rows=[m for m in obj["miners"] if isinstance(m,dict) and m.get("id")]
            if rows:return rows
    except Exception:pass
    # Preserve the pre-multi-miner single-machine configuration as the first profile.
    row={"id":"local","name":CFG.get("name",DEFAULT_MINER_NAME),"hotkey":CFG.get("hotkey",""),
         "coldkey":CFG.get("coldkey",""),"miner_id":CFG.get("miner_id",""),"source":"local",
         "agent_token":"","created_at":int(time.time())}
    rows=[row]
    atomic_json(MINERS_FILE,{"miners":rows})
    return rows

MINER_LOCK=threading.RLock()
MINERS=load_miners()
MINER_REPORTS={}
ACTIVE_PROFILE_ID="local"
try:
    for _profile in MINERS:
        _report_file=REPORTS_DIR/(_profile["id"]+".json")
        if _report_file.exists():MINER_REPORTS[_profile["id"]]=json.loads(_report_file.read_text())
except Exception:pass

def save_miners():
    atomic_json(MINERS_FILE,{"miners":MINERS})

def profile_by_id(profile_id):
    return next((p for p in MINERS if p.get("id")==profile_id),None)

def local_network_addresses():
    addresses=[]
    try:
        for info in socket.getaddrinfo(socket.gethostname(),None,socket.AF_INET):
            ip=info[4][0]
            if not ip.startswith("127.") and ip not in addresses:addresses.append(ip)
    except Exception:pass
    return addresses

def ensure_hub_certificate():
    if HUB_CERT.exists() and HUB_KEY.exists():return
    SUPPORT_DIR.mkdir(parents=True,exist_ok=True)
    subprocess.run(["/usr/bin/openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","825",
                    "-keyout",str(HUB_KEY),"-out",str(HUB_CERT),"-subj","/CN=IOTA-Matrix-Monitor-Hub"],
                   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    os.chmod(HUB_KEY,0o600);os.chmod(HUB_CERT,0o600)

def hub_cert_fingerprint():
    ensure_hub_certificate()
    der=ssl.PEM_cert_to_DER_cert(HUB_CERT.read_text())
    return hashlib.sha256(der).hexdigest()

def read_agent_config():
    try:
        obj=json.loads(AGENT_CONFIG.read_text())
        return obj if isinstance(obj,dict) else {}
    except Exception:return {}

def send_agent_report_once():
    cfg=read_agent_config()
    url=str(cfg.get("hub_url","")).strip();pid=str(cfg.get("profile_id","")).strip();token=str(cfg.get("token","")).strip();pin=re.sub(r"[^0-9a-f]","",str(cfg.get("tls_fingerprint","")).lower())
    if not url or not pid or not token or len(pin)!=64:return False
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!="https" or not parsed.hostname:return False
    ctx=ssl._create_unverified_context()
    conn=http.client.HTTPSConnection(parsed.hostname,parsed.port or AGENT_PORT,timeout=12,context=ctx)
    try:
        conn.connect()
        cert=conn.sock.getpeercert(binary_form=True)
        if not secrets.compare_digest(hashlib.sha256(cert).hexdigest(),pin):return False
        with mon.lock:state=copy.deepcopy(mon.state)
        report={"miner_id":pid,"state":state,"queue_history":log_queue_history_today()}
        body=json.dumps(report,separators=(",",":" )).encode()
        path=(parsed.path.rstrip("/") or "")+"/api/agent/report"
        conn.request("POST",path,body=body,headers={"Content-Type":"application/json","X-Agent-Token":token})
        response=conn.getresponse();reply=response.read()
        if response.status==200 and reply:
            try:apply_agent_profile(json.loads(reply).get("profile",{}))
            except Exception:pass
        return 200<=response.status<300
    except Exception:return False
    finally:conn.close()

def apply_agent_profile(remote):
    global CFG,LOG_DIR,RESOLVED_MINER_ID
    if not isinstance(remote,dict) or not remote.get("hotkey"):return
    hk=str(remote.get("hotkey","")).strip();ck=str(remote.get("coldkey","")).strip()
    if not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",hk):return
    if ck and not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",ck):return
    old=profile_identity();new=profile_identity(hk,ck)
    updated={"name":str(remote.get("name",DEFAULT_MINER_NAME)),"hotkey":hk,"coldkey":ck,"miner_id":str(remote.get("miner_id","")),"log_dir":""}
    if updated==CFG:return
    CFG=updated;save_config(CFG);RESOLVED_MINER_ID="";LOG_DIR=resolve_log_dir("")
    if old!=new:mon._clear_profile_data();mon._set_profile_identity(new)
    with mon.lock:mon.state.update({"config_name":CFG["name"],"hotkey":hk,"config_miner_id":CFG["miner_id"],"log_dir":str(LOG_DIR)})
    mon.last_remote_poll=0

def run_agent():
    if sys.platform=="darwin":
        try:
            from AppKit import NSApplication, NSApplicationActivationPolicyProhibited
            NSApplication.sharedApplication().setActivationPolicy_(NSApplicationActivationPolicyProhibited)
        except Exception:pass
    start_monitor_workers()
    while True:
        send_agent_report_once()
        time.sleep(10)

def agent_launch_agent_path():
    return Path.home()/"Library"/"LaunchAgents"/"ai.macrocosmos.iota-matrix-monitor.agent.plist"

def install_agent_launch_agent():
    if getattr(sys,"frozen",False):args=[sys.executable,"--agent"]
    else:args=[sys.executable,str(Path(__file__).resolve()),"--agent"]
    plist={"Label":"ai.macrocosmos.iota-matrix-monitor.agent","ProgramArguments":args,"RunAtLoad":True,"KeepAlive":True,"ProcessType":"Background"}
    path=agent_launch_agent_path();path.parent.mkdir(parents=True,exist_ok=True)
    import plistlib
    path.write_bytes(plistlib.dumps(plist));os.chmod(path,0o600)
    uid=os.getuid()
    subprocess.run(["/bin/launchctl","bootout",f"gui/{uid}",str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(["/bin/launchctl","bootstrap",f"gui/{uid}",str(path)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return str(path)

def active_name(): return CFG.get("name",DEFAULT_MINER_NAME)
def active_hotkey(): return CFG.get("hotkey") or DEFAULT_HOTKEY
def active_coldkey(): return CFG.get("coldkey",DEFAULT_COLDKEY)
def active_miner_id(): return CFG.get("miner_id","")
def effective_miner_id(): return CFG.get("miner_id","") or RESOLVED_MINER_ID
def hotkey_prefix(): return active_hotkey()[:8]

def profile_identity(hotkey=None, coldkey=None):
    hk=(active_hotkey() if hotkey is None else hotkey or "").strip().lower()
    ck=(active_coldkey() if coldkey is None else coldkey or "").strip().lower()
    return hashlib.sha256(f"{hk}|{ck}".encode("utf-8")).hexdigest()[:24]


def resource_path(name):
    roots=(Path(getattr(sys,"_MEIPASS",Path(__file__).resolve().parent)),Path(__file__).resolve().parent,Path(sys.executable).resolve().parent.parent/"Resources")
    for root in roots:
        candidate=root/name
        if candidate.is_file(): return candidate
    return roots[0]/name

HTML = resource_path("dashboard.html").read_text(encoding="utf-8")

RE_TS = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})")
RE_QUEUE = re.compile(r"[\'\"]status[\'\"]\s*:\s*[\'\"](queued|accepted|active|training|idle)[\'\"].*?[\'\"]position[\'\"]\s*:\s*(\d+)", re.I)
RE_QUEUE_ALT = re.compile(r"[\'\"]position[\'\"]\s*:\s*(\d+)", re.I)
RE_SPEED = re.compile(r"Speedtest completed with results: \{[\'\"]download_mbps[\'\"]:\s*([0-9.]+),\s*[\'\"]upload_mbps[\'\"]:\s*([0-9.]+)\}")
RE_ACT = re.compile(r"Activation push RECV \| id=[0-9a-f-]+ dir=(forward|backward) src_layer=(\d+) tgt_layer=(\d+)", re.I)
RE_STATE = re.compile(r"training\.state accepted \{ state: [\'\"]([^\'\"]+)[\'\"](?:, runId: [\'\"]([^\'\"]+)[\'\"], layer: (\d+))?", re.I)
RE_HEARTBEAT = re.compile(r"[\'\"]run_id[\'\"]:\s*[\'\"]([^\'\"]+)[\'\"], [\'\"]layer[\'\"]:\s*(\d+), [\'\"]epoch[\'\"]:\s*(\d+), [\'\"]phase[\'\"]:\s*[\'\"]([^\'\"]+)[\'\"]", re.I)
RE_PEERS = re.compile(r"Broadcast peer status: (\d+)/(\d+) ok", re.I)
RE_LAYER = re.compile(r"\bLayer[ =]+(\d+)", re.I)

class Monitor:
    def __init__(self):
        self.lock=threading.Lock()
        self.state={"status":"SCANNING","queue_position":None,"activations":0,"throughput":0,
                    "activations_fwd":0,"activations_bwd":0,"layer":None,"run_id":None,"epoch":None,
                    "uptime":None,"queue_events":0,"registration_errors":0,"peer_ok":None,"peer_total":None,
                    "download_mbps":None,"upload_mbps":None,"peer_pct":None,"device":None,
                    "protocol_ok":False,"protocol_connected":False,"viz_ok":False,"app_version":None,
                    "events":[],"payouts":[],"series":[],"shit_counts":{},"shit_total":0,"log_files":[],
                    "log_dir":str(LOG_DIR),"last_log_seen":None,"monitor_version":"2.9.32",
                    "config_name":CFG.get("name"),"config_miner_id":CFG.get("miner_id"),"run_availability":[],"run_availability_error":None,"run_availability_updated_at":None,
                    "resolved_miner_id":(CFG.get("miner_id") or RESOLVED_MINER_ID),"miner_id_source":("CONFIGURED" if CFG.get("miner_id") else "NOT RESOLVED"),
                    "hotkey":CFG.get("hotkey"),"hotkey_source":"USER CONFIGURED" ,
                    "network_ok":False,"network_source":None,"network_last_checked":None,
                    "network_activations":None,"network_throughput":None,"network_activations_fwd":None,
                    "network_activations_bwd":None,"network_payload":None,"network_endpoint":None,"network_throughput_source":None,"network_metric_fields":[],
                    "local_activations":0,"local_activations_rate":0,
                    "shit_details":{},"shit_last_detail":"No historical error events loaded.","shit_replayed":False,
                    "shit_source_lines":0,"shit_session":0,"network_diagnostics":{},"payouts_source":None,
                    "router_gateway":None,"router_latency_ms":None,"macrocosmos_icmp_ms":None,"macrocosmos_http_ms":None,"latency_checked":None,
                    "upload_sampled_at":None,"network_metrics_updated_at":None,"network_poll_error":None,
                    "run_started_at":None,"run_history":[],"run_comparison":None,"run_comparison_updated_at":None,"run_comparison_error":None}
        self.started=time.time()
        self.init_db()
        if not self._get_profile_identity():
            self._set_profile_identity(profile_identity())
        self.last_log_size={}
        self.initial_scan_done=False
        self.last_remote_poll=0
        self.remote_poll_lock=threading.Lock()
        self.recent_log_diagnostics=deque(maxlen=1600)
        self.reconcile_shits_from_logs()
        self.load_persisted_events()
        self.load_shit_history_events(prefer_shit=True)
        self.load_run_history()

    def db(self):
        return sqlite3.connect(DB)

    def init_db(self):
        c=self.db()
        c.execute("""CREATE TABLE IF NOT EXISTS samples(
            ts INTEGER, queue_position INTEGER, activations INTEGER, throughput INTEGER, layer TEXT, activations_fwd INTEGER, activations_bwd INTEGER)""")
        cols=[r[1] for r in c.execute("PRAGMA table_info(samples)").fetchall()]
        if "activations_fwd" not in cols: c.execute("ALTER TABLE samples ADD COLUMN activations_fwd INTEGER")
        if "activations_bwd" not in cols: c.execute("ALTER TABLE samples ADD COLUMN activations_bwd INTEGER")
        c.execute("""CREATE TABLE IF NOT EXISTS queue_history(
            ts REAL NOT NULL, position INTEGER NOT NULL)
        """)
        c.execute("""CREATE TABLE IF NOT EXISTS activation_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, direction TEXT NOT NULL, line_hash TEXT UNIQUE)""")
        c.execute("""CREATE TABLE IF NOT EXISTS remote_samples(
            ts INTEGER NOT NULL, activations REAL, throughput REAL, source TEXT, endpoint TEXT,
            fwd REAL, bwd REAL, raw TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS events(
            ts INTEGER, kind TEXT, text TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS payouts(
            ts INTEGER, epoch TEXT, alpha REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS shit_counters(
            kind TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0)""")
        for kind in ("REGISTRATION FAILURES","QUEUE RESETS","P2P TIMEOUTS","ACTIVATION ERRORS","MINER KICKS"):
            c.execute("INSERT OR IGNORE INTO shit_counters(kind,count) VALUES(?,0)",(kind,))
        c.execute("""CREATE TABLE IF NOT EXISTS shit_events(
            event_hash TEXT PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL)""")
        c.execute("""CREATE INDEX IF NOT EXISTS idx_shit_events_kind_ts ON shit_events(kind,ts)""")
        c.execute("""CREATE TABLE IF NOT EXISTS monitor_meta(
            key TEXT PRIMARY KEY, value TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS run_sessions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, started_at REAL NOT NULL,
            ended_at REAL, outcome TEXT, detail TEXT, context_json TEXT, health_json TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS network_health_samples(
            ts REAL NOT NULL, router_ms REAL, api_http_ms REAL, api_icmp_ms REAL,
            upload_mbps REAL, download_mbps REAL, upload_ts REAL, peer_pct REAL,
            load1 REAL, load5 REAL, cpu_cores INTEGER, mem_free_pct REAL)""")
        health_cols=[r[1] for r in c.execute("PRAGMA table_info(network_health_samples)").fetchall()]
        if "mem_free_pct" not in health_cols:c.execute("ALTER TABLE network_health_samples ADD COLUMN mem_free_pct REAL")
        c.execute("""CREATE TABLE IF NOT EXISTS run_public_samples(
            ts REAL NOT NULL, run_id TEXT NOT NULL, signature TEXT NOT NULL,
            unchanged_since REAL NOT NULL, PRIMARY KEY(run_id,ts))""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_health_ts ON network_health_samples(ts)")
        c.commit();c.close()

    def load_run_history(self):
        c=self.db()
        rows=c.execute("SELECT run_id,started_at,ended_at,outcome,detail,context_json,health_json FROM run_sessions ORDER BY id DESC LIMIT 20").fetchall()
        current=c.execute("SELECT started_at FROM run_sessions WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1").fetchone()
        c.close()
        history=[]
        for rid,started,ended,outcome,detail,context,health in rows:
            try:context=json.loads(context or "[]")
            except Exception:context=[]
            try:health=json.loads(health or "{}")
            except Exception:health={}
            history.append({"run_id":rid,"started_at":started,"ended_at":ended,"outcome":outcome,"detail":detail,"context":context,"health":health})
        with self.lock:
            self.state["run_history"]=history
            self.state["run_started_at"]=current[0] if current else None

    def _health_at(self,ts):
        c=self.db()
        rows=c.execute("SELECT ts,router_ms,api_http_ms,api_icmp_ms,upload_mbps,download_mbps,upload_ts,peer_pct,load1,load5,cpu_cores,mem_free_pct FROM network_health_samples WHERE ts BETWEEN ? AND ? ORDER BY ts",(ts-300,ts)).fetchall()
        c.close()
        samples=[]
        for r in rows:
            t,router,http,icmp,up,down,upload_ts,peers,load1,load5,cores,mem_free=r
            samples.append({"time":datetime.fromtimestamp(t).strftime("%H:%M:%S"),"router_ms":router,"api_http_ms":http,"api_icmp_ms":icmp,
                "upload_mbps":up,"download_mbps":down,"upload_age_s":max(0,int(t-upload_ts)) if upload_ts else None,
                "peer_pct":peers,"load1":load1,"load5":load5,"cpu_cores":cores,"mem_free_pct":mem_free})
        def maximum(key):
            vals=[x[key] for x in samples if isinstance(x.get(key),(int,float))]
            return max(vals) if vals else None
        def minimum(key):
            vals=[x[key] for x in samples if isinstance(x.get(key),(int,float))]
            return min(vals) if vals else None
        health={"window_minutes":5,"sample_count":len(samples),"last_sample_age_s":max(0,int(ts-float(rows[-1][0]))) if rows else None,"router_max_ms":maximum("router_ms"),
                "api_http_max_ms":maximum("api_http_ms"),"peer_min_pct":minimum("peer_pct"),"load1_max":maximum("load1"),"mem_free_pct_min":minimum("mem_free_pct"),
                "samples":samples[-24:]}
        if samples:
            latest=samples[-1]
            health.update({"latest_upload_mbps":latest.get("upload_mbps"),"latest_upload_age_s":latest.get("upload_age_s"),
                           "latest_download_mbps":latest.get("download_mbps"),"latest_router_ms":latest.get("router_ms"),
                           "latest_api_http_ms":latest.get("api_http_ms"),"latest_peer_pct":latest.get("peer_pct"),
                           "latest_load1":latest.get("load1"),"cpu_cores":latest.get("cpu_cores"),"latest_mem_free_pct":latest.get("mem_free_pct")})
        return health

    def _open_run_session(self,run_id,ts,detail):
        c=self.db()
        current=c.execute("SELECT id,run_id FROM run_sessions WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1").fetchone()
        if current and current[1]=="UNKNOWN" and run_id:
            c.execute("UPDATE run_sessions SET run_id=?,detail=? WHERE id=?",(str(run_id),detail[-800:],current[0]))
        else:
            c.execute("UPDATE run_sessions SET ended_at=?,outcome='RUN REPLACED',detail=COALESCE(detail,?) WHERE ended_at IS NULL",(ts,"A different active run was detected"))
            c.execute("INSERT INTO run_sessions(run_id,started_at,outcome,detail,context_json,health_json) VALUES(?,?,'ACTIVE',?,'[]','{}')",(str(run_id or "UNKNOWN"),ts,detail[-800:]))
        c.commit();c.close()
        with self.lock:self.state["run_started_at"]=ts
        self.add_event("info",f"RUN STARTED · {run_id or 'UNKNOWN'} · {datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')}")
        self.load_run_history()

    def _close_run_session(self,ts,detail):
        diagnostics=[{"time":datetime.fromtimestamp(t).strftime("%H:%M:%S"),"text":line} for t,line in self.recent_log_diagnostics if ts-300<=t<=ts]
        health=self._health_at(ts)
        c=self.db()
        row=c.execute("SELECT id,run_id,started_at FROM run_sessions WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            c.execute("UPDATE run_sessions SET ended_at=?,outcome='KICKED',detail=?,context_json=?,health_json=? WHERE id=?",
                (ts,detail.strip()[-800:],json.dumps(diagnostics[-100:]),json.dumps(health),row[0]))
        c.commit();c.close()
        stamp=datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        if not row:
            c=self.db();c.execute("INSERT INTO run_sessions(run_id,started_at,ended_at,outcome,detail,context_json,health_json) VALUES(?, ?, ?, 'KICKED', ?, ?, ?)",
                (self.state.get("run_id") or "UNKNOWN",ts,ts,detail.strip()[-800:],json.dumps(diagnostics[-100:]),json.dumps(health)));c.commit();c.close()
        with self.lock:self.state["run_started_at"]=None
        self.add_event("error",f"MINER KICKED · {stamp} · {detail.strip()[-180:]}")
        self.load_run_history()

    SHIT_KINDS=("REGISTRATION FAILURES","QUEUE RESETS","P2P TIMEOUTS","ACTIVATION ERRORS","MINER KICKS")

    def _classify_shits(self,line):
        low=line.lower()
        kinds=[]
        # These definitions track actionable miner incidents; routine server 503 noise is excluded.
        if "EntityNotRegisteredError" in line or "Miner not registered error" in line:
            kinds.append("REGISTRATION FAILURES")
        # T@H reports peer reachability failures as an aggregated warning.
        # Count that concrete incident line rather than unrelated timeout text.
        pm=re.search(r"Broadcast peer status:\s*(\d+)/(\d+) ok,\s*([1-9]\d*) unreachable",line,re.I)
        if pm and int(pm.group(1)) < int(pm.group(2)):
            kinds.append("P2P TIMEOUTS")
        if "activation" in low and any(x in low for x in ("error","failed","failure","timeout")):
            kinds.append("ACTIVATION ERRORS")
        # Count actual miner-state reset routine entries. These are the concrete
        # reset lifecycle messages in the T@H log and are distinct from queue_state 503 noise.
        if "reset_miner_state" in low:
            kinds.append("QUEUE RESETS")
        elif "queue" in low and "503" not in low and any(x in low for x in ("reset","tail","requeue")):
            kinds.append("QUEUE RESETS")
        # Count the explicit protocol kick event, not explanatory prose such as
        # "appears to have been kicked" which can accompany the same incident.
        if "miner.kicked" in low or re.search(r"name:\s*['\"]miner\.kicked['\"]",line,re.I):
            kinds.append("MINER KICKS")
        return kinds

    def _line_timestamp(self,line):
        m=re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3,6})?)",line)
        if not m:return int(time.time())
        raw=m.group(1)
        # T@H log timestamps have no timezone suffix and represent the Mac's
        # local clock.  Keep them in local time so the midnight-to-midnight
        # queue chart lines up with the user's actual day.
        for fmt in ("%Y-%m-%d %H:%M:%S.%f","%Y-%m-%d %H:%M:%S"):
            try:return int(datetime.strptime(raw,fmt).timestamp())
            except Exception:pass
        return int(time.time())

    def _incident_signature(self,kind,line):
        low=line.lower().strip()
        if kind=="REGISTRATION FAILURES":
            return "registration-failure"
        if kind=="MINER KICKS":
            return "miner-kicked"
        if kind=="P2P TIMEOUTS":
            m=re.search(r"Broadcast peer status:\s*(\d+)/(\d+) ok,\s*(\d+) unreachable",line,re.I)
            return "p2p:"+(m.group(3) if m else "timeout")
        if kind=="QUEUE RESETS":
            m=re.search(r"reset_miner_state:(\d+)",line,re.I)
            return "reset:"+(m.group(1) if m else "lifecycle")
        if kind=="ACTIVATION ERRORS":
            return "activation-error"
        return low[:180]

    def record_shit(self,line,kind):
        import hashlib
        detail=line.strip()[-800:]
        ts=self._line_timestamp(line) or time.time()
        sig=self._incident_signature(kind,line)
        # Multi-line protocol events (e.g. miner.kicked) do not repeat the
        # timestamp on every continuation line. Deduplicate those by incident
        # signature alone so a replay can never create a second kick.
        digest_src=(kind+"|"+sig) if kind=="MINER KICKS" else (kind+"|"+str(int(ts))+"|"+sig)
        digest=hashlib.sha1(digest_src.encode("utf-8","replace")).hexdigest()
        c=self.db()
        cur=c.execute("INSERT OR IGNORE INTO shit_events(event_hash,ts,kind,detail) VALUES(?,?,?,?)",(digest,ts,kind,detail))
        inserted=cur.rowcount==1
        c.commit();c.close()
        if inserted:
            with self.lock:self.state["shit_session"] = self.state.get("shit_session",0)+1
        return inserted

    def reconcile_shits_from_logs(self):
        files=sorted(LOG_DIR.glob("*-cli.log"), key=lambda p:p.stat().st_mtime if p.exists() else 0)
        source_lines=0
        c=self.db()
        for p in files:
            try:
                with p.open("r",errors="replace") as f:
                    for line in f:
                        source_lines+=1
                        for kind in self._classify_shits(line):
                            import hashlib
                            ts=self._line_timestamp(line) or time.time()
                            digest=hashlib.sha1((kind+"|"+str(int(ts))+"|"+self._incident_signature(kind,line)).encode("utf-8","replace")).hexdigest()
                            c.execute("INSERT OR IGNORE INTO shit_events(event_hash,ts,kind,detail) VALUES(?,?,?,?)",(digest,int(ts),kind,line.strip()[-800:]))
            except Exception: pass
        c.commit();c.close()
        with self.lock:
            self.state["shit_replayed"]=True
            self.state["shit_source_lines"]=source_lines
        self.refresh_shit_state()
        self.load_shit_history_events(prefer_shit=True)

    def refresh_shit_state(self):
        c=self.db()
        # The live event table is the single source of truth. Older builds had
        # a separate counter table that could double-count or resurrect stale
        # 503-era values, so v2.8 deliberately ignores it for display totals.
        tracked=dict(c.execute("SELECT kind,COUNT(*) FROM shit_events GROUP BY kind").fetchall())
        details={}
        rows=c.execute("SELECT kind,ts,detail FROM shit_events ORDER BY ts DESC").fetchall()
        for kind,ts,detail in rows:
            if kind not in details:
                details[kind]={"last_time":datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"),"last_detail":detail}
        c.close()
        counts={k:int(tracked.get(k,0)) for k in self.SHIT_KINDS}
        with self.lock:
            self.state["shit_counts"]=counts
            self.state["shit_total"]=sum(counts.values())
            self.state["shit_details"]=details
            last=next(iter(rows),None)
            if last:
                self.state["shit_last_detail"]=f"{last[0]} · {datetime.fromtimestamp(last[1]).strftime('%Y-%m-%d %H:%M:%S')} · {last[2]}"

    def shit_counts(self):
        with self.lock:
            return dict(self.state.get("shit_counts",{})), int(self.state.get("shit_total",0))

    def load_shit_history_events(self, prefer_shit=False):
        c=self.db()
        rows=c.execute("SELECT kind,ts,detail FROM shit_events ORDER BY ts DESC LIMIT 120").fetchall()
        c.close()
        if not rows and not prefer_shit:
            return
        if rows:
            events=[{"time":datetime.fromtimestamp(ts).strftime("%H:%M:%S"),"text":f"{kind}: {detail}","error":True} for kind,ts,detail in rows]
            with self.lock:
                self.state["events"]=events

    def load_persisted_events(self):
        c=self.db()
        rows=c.execute("SELECT ts,kind,text FROM events ORDER BY ts DESC LIMIT 120").fetchall()
        c.close()
        with self.lock:
            if rows:
                self.state["events"]=[{"time":datetime.fromtimestamp(ts).strftime("%H:%M:%S"),"text":text,"error":kind=="error"} for ts,kind,text in rows]

    def add_event(self,kind,text):
        now=int(time.time())
        with self.lock:
            self.state["events"].insert(0,{"time":datetime.now().strftime("%H:%M:%S"),"text":text,"error":kind=="error"})
            self.state["events"]=self.state["events"][:120]
        c=self.db();c.execute("INSERT INTO events VALUES(?,?,?)",(now,kind,text));c.commit();c.close()

    def _get_profile_identity(self):
        c=self.db(); row=c.execute("SELECT value FROM monitor_meta WHERE key='profile_identity'").fetchone(); c.close(); return row[0] if row else ''

    def _set_profile_identity(self, identity):
        c=self.db(); c.execute("INSERT INTO monitor_meta(key,value) VALUES('profile_identity',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(identity,)); c.commit(); c.close()

    def _clear_profile_data(self):
        # A local monitor represents one miner on one Mac. When its public identity
        # changes, discard the previous miner's persisted telemetry so it cannot
        # leak into the new miner's activation/queue display.
        c=self.db()
        for table in ('samples','queue_history','activation_events','remote_samples','events','payouts','shit_events','run_sessions','network_health_samples'):
            c.execute(f"DELETE FROM {table}")
        c.execute("UPDATE shit_counters SET count=0")
        c.commit(); c.close()
        with self.lock:
            self.state.update({
                'queue_position':None,'activations':0,'throughput':0,
                'activations_fwd':0,'activations_bwd':0,'queue_events':0,
                'registration_errors':0,'network_ok':False,'network_source':None,
                'network_last_checked':None,'network_activations':None,
                'network_throughput':None,'network_activations_fwd':None,
                'network_activations_bwd':None,'network_payload':None,
                'network_endpoint':None,'network_throughput_source':None,
                'network_metric_fields':[],'local_activations':0,
                'local_activations_rate':0,'series':[],'payouts':[],
                'payouts_source':None,'events':[],'shit_counts':{},
                'shit_total':0,'shit_details':{},'shit_last_detail':'No historical error events loaded.',
                'shit_replayed':False,'shit_source_lines':0,'shit_session':0,
                'network_diagnostics':{},'router_gateway':None,'router_latency_ms':None,
                'macrocosmos_icmp_ms':None,'macrocosmos_http_ms':None,'latency_checked':None,
                'network_metrics_updated_at':None,'network_poll_error':None,'run_started_at':None,'run_history':[],'upload_sampled_at':None,
                'run_comparison':None,'run_comparison_updated_at':None,'run_comparison_error':None
            })
        self.recent_log_diagnostics.clear()
        # Start the new profile at the end of the existing log files. Historical
        # lines may belong to the previous miner on this Mac.
        try:
            files=sorted(LOG_DIR.glob("*-cli.log"), key=lambda p:p.stat().st_mtime if p.exists() else 0)
            self.last_log_size={str(p):p.stat().st_size for p in files}
        except Exception:
            self.last_log_size={}
        self.initial_scan_done=True

    def refresh_configured_hotkey(self):
        with self.lock:
            self.state["hotkey"] = CFG.get("hotkey", "")
            self.state["hotkey_source"] = "USER CONFIGURED"

    def scan(self):
        self.refresh_configured_hotkey()
        files=sorted(LOG_DIR.glob("*-cli.log"), key=lambda p:p.stat().st_mtime if p.exists() else 0)
        with self.lock:
            self.state["log_files"]=[p.name for p in files]
        # On first scan, read the complete latest log so the dashboard immediately
        # reflects the current queue position. Thereafter, tail appended bytes.
        for p in (files if not self.initial_scan_done else files[-3:]):
            try:
                size=p.stat().st_size
                key=str(p)
                first_seen=key not in self.last_log_size
                old=self.last_log_size.get(key,0)
                if old>size or first_seen:
                    old=0
                self.last_log_size[key]=size
                with p.open("r",errors="replace") as f:
                    f.seek(old)
                    chunk=f.read()
                if not chunk:
                    continue

                # The T@H response can be very long and can occasionally be
                # wrapped/truncated visually. Parse each physical line, plus
                # response fragments independently.
                for line in chunk.splitlines():
                    self.parse(line)

                with self.lock:
                    self.state["last_log_seen"]=datetime.now().strftime("%H:%M:%S")
            except Exception as exc:
                self.add_event("error",f"LOG SCAN ERROR: {type(exc).__name__}")
        self.initial_scan_done=True

    def parse(self,line):
        low=line.lower()
        old_status=self.state.get("status")
        old_run_id=self.state.get("run_id")
        line_ts=self._line_timestamp(line)
        if re.search(r"\b(warn(?:ing)?s?|errors?|exceptions?|failed|failures?|timeouts?|timed out|unreachable|disconnect(?:ed|ion)?|reconnect(?:ed|ing)?|lost|reset_miner_state|miner\.kicked|panic|fatal)\b",low):
            self.recent_log_diagnostics.append((line_ts,line.strip()[-800:]))
        for kind in self._classify_shits(line):
            if self.record_shit(line,kind):
                self.add_event("error",f"{kind}: {line.strip()[-240:]}")
        # Authoritative registration queue response. The community parser uses
        # the same response shape; we additionally accept a standalone position.
        m=RE_QUEUE.search(line)
        if m:
            status=m.group(1).lower(); pos=int(m.group(2))
            self._set_queue(status,pos,self._line_timestamp(line))
        else:
            m=RE_QUEUE_ALT.search(line)
            if m and ("register/status" in low or "queue_id" in low):
                self._set_queue("queued" if "queued" in low else self.state.get("status","unknown"),int(m.group(1)),self._line_timestamp(line))

        m=RE_SPEED.search(line)
        if m:
            self.state["download_mbps"]=float(m.group(1)); self.state["upload_mbps"]=float(m.group(2))
            self.state["upload_sampled_at"]=line_ts

        m=RE_ACT.search(line)
        if m:
            direction=m.group(1).lower()
            # Persist individual activation events; duplicate lines cannot double-count.
            import hashlib
            h=hashlib.sha1(line.strip().encode("utf-8","replace")).hexdigest()
            c=self.db()
            try:
                ts=self._line_timestamp(line) or time.time()
                c.execute("INSERT OR IGNORE INTO activation_events(ts,direction,line_hash) VALUES(?,?,?)",(ts,direction,h))
                inserted=c.total_changes
                c.commit()
            finally:
                c.close()
            if inserted:
                if direction=="forward": self.state["activations_fwd"]+=1
                else: self.state["activations_bwd"]+=1
                self.state["activations"] = self.state["activations_fwd"] + self.state["activations_bwd"]
                self.add_event("info",f"ACTIVATION {direction.upper()} RECEIVED")

        m=RE_STATE.search(line)
        if m:
            self.state["status"] = self._norm_status(m.group(1))
            if m.group(2): self.state["run_id"]=m.group(2)
            if m.group(3): self.state["layer"]="L"+m.group(3)

        m=RE_HEARTBEAT.search(line)
        if m:
            self.state["run_id"]=m.group(1); self.state["layer"]="L"+m.group(2); self.state["epoch"]=int(m.group(3))
            self.state["status"]="ACTIVE" if m.group(4).lower() in ("training","active") else self.state["status"]

        if self.state.get("status")=="ACTIVE" and (old_status!="ACTIVE" or (self.state.get("run_id") and self.state.get("run_id")!=old_run_id)):
            self._open_run_session(self.state.get("run_id"),line_ts,line.strip())

        m=RE_PEERS.search(line)
        if m:
            self.state["peer_ok"]=int(m.group(1)); self.state["peer_total"]=int(m.group(2))
            self.state["peer_pct"]=(100.0*int(m.group(1))/int(m.group(2))) if int(m.group(2)) else 0
            if int(m.group(1)) < int(m.group(2)):
                self.record_shit(line, "P2P TIMEOUTS")

        # Errors / state transitions.
        if "EntityNotRegisteredError" in line or "Miner not registered error" in line:
            self.state["registration_errors"]+=1
        if "miner kicked" in low or "miner.kicked" in low:
            self._close_run_session(line_ts,line.strip())
            self.state["status"]="OFFLINE"
        if "shutdown complete" in low:
            self.state["status"]="OFFLINE"
        if "starting miner" in low and self.state.get("status") in ("OFFLINE","SCANNING"):
            self.state["status"]="IDLE"

        l=RE_LAYER.search(line)
        if l: self.state["layer"]="L"+l.group(1)

    def _set_queue(self,status,pos,ts=None):
        previous=self.state.get("queue_position")
        self.state["queue_position"]=pos
        self.state["status"]="QUEUED" if status=="queued" else ("ACTIVE" if status in ("accepted","active","training") else status.upper())
        stamp=float(ts if ts is not None else time.time())
        try:
            c=self.db(); c.execute("INSERT INTO queue_history(ts,position) VALUES(?,?)",(stamp,int(pos)))
            c.execute("DELETE FROM queue_history WHERE ts < ?",(time.time()-30*86400,)); c.commit(); c.close()
        except Exception: pass
        if previous is not None and previous != pos:
            self.state["queue_events"]+=1
            self.add_event("info",f"QUEUE POSITION {pos} ({pos-previous:+d})")

    @staticmethod
    def _norm_status(s):
        s=s.lower()
        return {"training_tick":"ACTIVE","training":"ACTIVE","active":"ACTIVE","queued":"QUEUED","idle":"IDLE","resetting":"RESETTING"}.get(s,s.upper())

    def sample(self):
        now=int(time.time())
        c=self.db()
        rows=c.execute("SELECT ts,direction FROM activation_events ORDER BY ts DESC").fetchall()
        total=len(rows); fwd=sum(1 for _,d in rows if d=="forward"); bwd=total-fwd
        hour=sum(1 for ts,_ in rows if ts >= time.time()-3600)
        self.state["local_activations"]=total; self.state["activations_fwd"]=fwd; self.state["activations_bwd"]=bwd; self.state["local_activations_rate"]=hour
        # The top-line activation/throughput cards use network data when available.
        self.state["activations"]=self.state.get("network_activations") if self.state.get("network_activations") is not None else total
        self.state["throughput"]=self.state.get("network_throughput") if self.state.get("network_throughput") is not None else hour
        row=(now,self.state["queue_position"],total,hour,self.state["layer"],fwd,bwd)
        c.execute("INSERT INTO samples VALUES(?,?,?,?,?,?,?)",row)
        c.execute("DELETE FROM samples WHERE ts < ?",(now-30*86400,))
        remote_rows=c.execute("SELECT ts,activations,throughput FROM remote_samples ORDER BY ts DESC LIMIT 240").fetchall()
        c.commit(); c.close()
        self.state["series"]= [ {"ts":x,"activations":a or 0,"network_activations":a,"network_throughput":t} for x,a,t in reversed(remote_rows)]

    @staticmethod
    def _num(value):
        if isinstance(value,(int,float)) and not isinstance(value,bool): return float(value)
        if isinstance(value,str):
            m=re.search(r"-?[0-9][0-9,]*(?:\.[0-9]+)?",value)
            if m:
                try:return float(m.group(0).replace(",",""))
                except Exception:return None
        return None

    def _fetch_text(self,url,timeout=5):
        req=urllib.request.Request(url,headers={
            "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15 IOTA-Matrix-Monitor/2.9.9",
            "Accept":"application/json, text/plain, */*",
            "Accept-Encoding":"identity",
            "Accept-Language":"en-GB,en;q=0.9",
            "Referer":"https://www.trainathome.ai/",
            "Origin":"https://www.trainathome.ai"})
        with urllib.request.urlopen(req,timeout=timeout) as r:
            data=r.read(8_000_000)
            ctype=r.headers.get("Content-Type","")
            encoding=(r.headers.get("Content-Encoding","") or "").lower()
            if encoding == "gzip":
                try: data=gzip.decompress(data)
                except Exception: pass
            elif encoding == "deflate":
                try: data=zlib.decompress(data)
                except Exception: pass
            text=data.decode("utf-8-sig","replace").strip()
            return text,ctype

    def _candidate_urls(self,host):
        # Discover same-origin JS/API strings first, then try conservative common routes.
        urls=[]
        try:
            html,_=self._fetch_text(host+"/en",4.0)
            scripts=re.findall(r'<script[^>]+src=[\'\"]([^\'\"]+)[\'\"]',html,re.I)
            for src in scripts[:40]:
                if src.startswith("/"): u=host+src
                elif src.startswith("http"): u=src
                else: continue
                try:
                    js,_=self._fetch_text(u,4.0)
                    for m in re.finditer(r"['\"]((?:https?:)?//[^'\"\\s]+|/api/[A-Za-z0-9_./?=&${}:,\-]+)['\"]",js):
                        val=m.group(1).replace("\\u002F","/")
                        if val.startswith("//"): val="https:"+val
                        if val.startswith("/api/"):
                            urls.append(host+val)
                        elif val.startswith(host): urls.append(val)
                except Exception: pass
        except Exception: pass
        direct=[
            host+f"/api/miners/{active_hotkey()}", host+f"/api/miner/{active_hotkey()}",
            host+f"/api/devices/{active_hotkey()}", host+f"/api/device/{active_hotkey()}",
            host+f"/api/telemetry/{active_hotkey()}", host+f"/api/miner/{effective_miner_id()}",
            host+f"/api/miners/{effective_miner_id()}", host+"/api/miners", host+"/api/devices",
            host+"/api/runs", host+"/api/telemetry"
        ]
        # Preserve order but remove duplicates and replace obvious placeholders with real identifiers.
        out=[]
        for u in urls+direct:
            for candidate in (u,):
                if candidate not in out: out.append(candidate)
        expanded=[]
        for u in out[:120]:
            expanded.append(u)
            sep='&' if '?' in u else '?'
            for key in ('hotkey','miner_id','minerId','id'):
                expanded.append(u+sep+key+'='+active_hotkey())
            # Path form only when endpoint doesn't already end with an identifier.
            if not re.search(r'/'+re.escape(active_hotkey())+r'/?$',u) and not re.search(r'/'+re.escape(effective_miner_id())+r'/?$',u):
                expanded.append(u.rstrip('/')+'/'+active_hotkey())
        seen=set(); final=[]
        for u in expanded:
            if u not in seen:
                seen.add(u); final.append(u)
        return final[:220]

    def _extract_network_record(self,obj):
        """Find a miner record matching this exact hotkey/prefix and return network metrics."""
        act_keys={'activations','activation_count','activationCount','activations_total','activationsTotal','act'}
        thr_keys={'throughput','throughput_h','throughputPerHour','throughput_per_hour','throughput_hour','tph'}
        hot_keys={'hotkey','miner_hotkey','minerHotkey','source_hotkey','sourceHotkey','id','miner_id','minerId'}
        if isinstance(obj,dict):
            flat={str(k):v for k,v in obj.items()}
            # Detect matching identity anywhere in the record.
            identity=' '.join(str(flat.get(k,'')) for k in hot_keys).lower()
            match=(active_hotkey().lower() in identity or hotkey_prefix().lower() in identity)
            acts=next((self._num(flat[k]) for k in act_keys if k in flat and self._num(flat[k]) is not None),None)
            thr=next((self._num(flat[k]) for k in thr_keys if k in flat and self._num(flat[k]) is not None),None)
            if match and (acts is not None or thr is not None):
                fwd=next((self._num(flat[k]) for k in ('activations_fwd','forward_activations','forwardActivations') if k in flat and self._num(flat[k]) is not None),None)
                bwd=next((self._num(flat[k]) for k in ('activations_bwd','backward_activations','backwardActivations') if k in flat and self._num(flat[k]) is not None),None)
                return {'activations':acts,'throughput':thr,'fwd':fwd,'bwd':bwd,'raw':flat}
            for v in obj.values():
                r=self._extract_network_record(v)
                if r:return r
        elif isinstance(obj,list):
            for v in obj:
                r=self._extract_network_record(v)
                if r:return r
        return None

    def _fetch_json(self,url,timeout=8):
        txt,ctype=self._fetch_text(url,timeout)
        if not txt:
            raise ValueError("empty response")
        # Be tolerant of common API gateway wrappers.
        for prefix in (")]}'", "\ufeff"):
            if txt.startswith(prefix):
                txt=txt[len(prefix):].lstrip()
        try:
            return json.loads(txt)
        except json.JSONDecodeError as exc:
            # Some internal/proxy routes have historically returned a Python-style
            # dict/list representation (single quotes, None/True/False) even though
            # the endpoint is documented as JSON. Parse that safely as a fallback.
            try:
                obj=ast.literal_eval(txt)
                if isinstance(obj,(dict,list)):
                    return obj
            except Exception:
                pass
            preview=re.sub(r"\s+"," ",txt[:220])
            c=str(ctype or "unknown")
            raise ValueError(f"JSON decode at {exc.pos} [{c}]: {preview}") from exc

    def _walk_records(self,obj, path=''):
        """Yield (path, dict/list-node) for recursive API inspection."""
        yield path,obj
        if isinstance(obj,dict):
            for k,v in obj.items():
                yield from self._walk_records(v, f"{path}/{k}" if path else str(k))
        elif isinstance(obj,list):
            for i,v in enumerate(obj):
                yield from self._walk_records(v, f"{path}[{i}]")

    def _find_identity_record(self,obj):
        """Find the smallest dictionary belonging to this exact miner/hotkey.

        The Macrocosmos responses can be shaped as a list of miner records, a
        dictionary keyed by hotkey, or a nested data/result object. Prefer the
        exact hotkey. Only fall back to miner id 1077 when the field itself is
        explicitly identified as a miner id.
        """
        exact=[]; miner_id=[]
        target=active_hotkey().lower()
        for path,node in self._walk_records(obj):
            if not isinstance(node,dict):
                continue
            keys={str(k).lower() for k in node.keys()}
            vals={str(v).lower() for v in node.values() if isinstance(v,(str,int,float,bool))}
            p=str(path).lower()
            if target and (target in keys or target in vals or target in p):
                exact.append((path,node))
                continue
            for k in ('miner_id','minerid','minerId','miner'):
                if str(k).lower() in keys:
                    v=node.get(k)
                    if str(v).lower() == str(effective_miner_id()).lower():
                        miner_id.append((path,node))
                        break
        if exact:
            # Prefer the smallest node that actually contains a metric we care about.
            metric_keys={'activations','activation_count','activationcount','activations_total',
                         'total_activations','throughput','throughput_10m','average_throughput',
                         'throughput_per_10_min','avg_throughput'}
            for item in reversed(exact):
                if metric_keys & {str(k).lower() for k in item[1].keys()}:
                    return item
            return exact[-1]
        return miner_id[-1] if miner_id else None

    def _extract_keys_recursive(self,obj,keys):
        vals=[]
        wanted={str(k).lower() for k in keys}
        for path,node in self._walk_records(obj):
            if isinstance(node,dict):
                for k,v in node.items():
                    if str(k).lower() in wanted:
                        n=self._num(v)
                        if n is not None:
                            vals.append((str(k),n,path))
        return vals

    def _extract_latest_metric(self,obj, keys):
        vals=self._extract_keys_recursive(obj,keys)
        return vals[-1][1] if vals else None

    def _extract_metric_by_patterns(self,obj,patterns,avoid=()):
        """Return the last numeric field whose name/path contains one of patterns."""
        found=[]
        pats=[p.lower() for p in patterns]
        avoids=[p.lower() for p in avoid]
        for path,node in self._walk_records(obj):
            if not isinstance(node,dict):
                continue
            for k,v in node.items():
                ks=str(k).lower(); ps=str(path).lower()
                if any(a in ks or a in ps for a in avoids):
                    continue
                if any(p in ks for p in pats):
                    n=self._num(v)
                    if n is not None:
                        found.append((path,ks,n))
        return found[-1][2] if found else None

    def _extract_series(self,obj, metric_keys, identity_only=False):
        """Extract ordered metric points from a response for historical charting."""
        source=obj
        if identity_only:
            rec=self._find_identity_record(obj)
            if not rec:
                return []
            source=rec[1]
        out=[]
        for path,node in self._walk_records(source):
            if not isinstance(node,dict):
                continue
            val=self._extract_latest_metric(node,metric_keys)
            if val is None:
                continue
            ts=self._extract_latest_metric(node,('timestamp','ts','time','created_at','date','epoch','epoch_id','epochId'))
            out.append({'ts':ts if ts is not None else len(out),'network_activations':val})
        return out[-180:]

    def _api_runs_availability(self):
        """Merge /runs metadata with /v1/runs_occupancy."""
        try:
            runs_obj=self._fetch_json(API_RUNS,8)
            occ_obj=self._fetch_json(API_RUNS_OCCUPANCY,8)
        except Exception as e:
            return [], f'{type(e).__name__}'
        runs=runs_obj.get('runs',[]) if isinstance(runs_obj,dict) else runs_obj
        merged={}
        if isinstance(runs,list):
            for r in runs:
                if not isinstance(r,dict):
                    continue
                rid=str(r.get('run_id') or r.get('name') or '').strip()
                if not rid:
                    continue
                md=r.get('metadata') if isinstance(r.get('metadata'),dict) else {}
                desc=str(md.get('description') or '')
                tier='UNKNOWN'
                m=re.search(r'(?i)Tier\s*\d+\s*\(([^)]+)\)',desc)
                if m:
                    tier=m.group(1).upper()
                else:
                    m=re.search(r'(?i)\b(Bronze|Silver|Gold|Iron)\b',desc)
                    if m:tier=m.group(1).upper()
                merged[rid]={'run_id':rid,'tier':tier,'description':desc,
                             'state':str(r.get('state') or '').upper(),
                             'max_miners':r.get('max_miners'),'active_miners':None,'slots_remaining':None}
        if isinstance(occ_obj,dict):
            ids=occ_obj.get('run_ids') or []
            maxs=occ_obj.get('max_miners') or []
            acts=occ_obj.get('active_miners') or []
            slots=occ_obj.get('slots_remaining') or []
            for i,rid0 in enumerate(ids):
                rid=str(rid0)
                row=merged.setdefault(rid,{'run_id':rid,'tier':'UNKNOWN','description':'','state':''})
                row['max_miners']=maxs[i] if i<len(maxs) else row.get('max_miners')
                row['active_miners']=acts[i] if i<len(acts) else None
                row['slots_remaining']=slots[i] if i<len(slots) else None
        rows=list(merged.values())
        for row in rows:
            if row.get('slots_remaining') is None and isinstance(row.get('max_miners'),(int,float)) and isinstance(row.get('active_miners'),(int,float)):
                row['slots_remaining']=max(0,int(row['max_miners'])-int(row['active_miners']))
        current=self.state.get('run_id')
        rows.sort(key=lambda r:(0 if r.get('run_id')==current else 1, r.get('run_id','')))
        return rows,'MATCH'

    def _refresh_run_performance(self, rows, now):
        """Attach low-frequency aggregate progress and a cautious flat-progress signal."""
        c=self.db()
        for row in rows:
            if str(row.get('state','')).lower() not in ('active','running'):
                row['health_signal']='RUN NOT ACTIVE'
                continue
            rid=str(row.get('run_id') or '')
            if not rid: continue
            try:
                obj=self._fetch_json(API_RUN_PROGRESS+urllib.parse.quote(rid,safe=''),8)
                metrics={
                    'activations':self._extract_latest_metric(obj,('total_activations','activation_count','activations')),
                    'tokens':self._extract_latest_metric(obj,('total_tokens','token_count','tokens')),
                    'loss':self._extract_latest_metric(obj,('loss','global_loss')),
                    'sample_ts':self._extract_latest_metric(obj,('timestamp','updated_at','ts')),
                }
                row['performance']=metrics
                row['performance_sampled_at']=now
                signature_values=[metrics[k] for k in ('activations','tokens','loss')]
                has_counter=metrics['activations'] is not None or metrics['tokens'] is not None
                signature=json.dumps(signature_values,separators=(',',':'))
                prev=c.execute("SELECT signature,unchanged_since FROM run_public_samples WHERE run_id=? ORDER BY ts DESC LIMIT 1",(rid,)).fetchone()
                unchanged_since=(float(prev[1]) if prev and prev[0]==signature and has_counter else now)
                if not has_counter: unchanged_since=now
                c.execute("INSERT OR REPLACE INTO run_public_samples(ts,run_id,signature,unchanged_since) VALUES(?,?,?,?)",(now,rid,signature,unchanged_since))
                row['progress_unchanged_minutes']=round(max(0,now-unchanged_since)/60,1) if has_counter else None
                count=row.get('active_miners')
                if isinstance(count,(int,float)) and count==0:
                    row['health_signal']='NO ACTIVE MINERS REPORTED'
                elif has_counter and now-unchanged_since>=900:
                    row['health_signal']='PROGRESS FLAT · CHECK RUN'
                elif has_counter:
                    row['health_signal']='PROGRESSING' if not prev or prev[0]!=signature else 'PROGRESS RECENTLY UNCHANGED'
                else:
                    row['health_signal']='PROGRESS DATA UNAVAILABLE'
            except Exception as e:
                row['health_signal']='PROGRESS DATA UNAVAILABLE'
                row['performance_error']=type(e).__name__
        c.execute("DELETE FROM run_public_samples WHERE ts<?",(now-30*86400,))
        c.commit();c.close()

    def lookup_public_miner(self, hotkey, run_id="", coldkey=""):
        """Read one miner's public run record, optionally discovering its run by hotkey."""
        hk=str(hotkey).strip()
        rid=str(run_id).strip()
        ck=str(coldkey).strip()
        if not re.fullmatch(r'5[1-9A-HJ-NP-Za-km-z]{46,47}',hk):
            raise ValueError('Enter a valid public SS58 hotkey')
        if ck and not re.fullmatch(r'5[1-9A-HJ-NP-Za-km-z]{46,47}',ck):
            raise ValueError('Enter a valid public SS58 coldkey')
        if rid and not re.fullmatch(r'[A-Za-z0-9._-]{1,120}',rid):
            raise ValueError('Choose a valid run')
        scanned_runs=0
        if rid:
            candidates=[rid]
        else:
            runs_obj=self._fetch_json(API_RUNS,8)
            runs=runs_obj.get('runs',[]) if isinstance(runs_obj,dict) else runs_obj
            candidates=[]
            if isinstance(runs,list):
                active=[]; other=[]
                for row in runs:
                    if not isinstance(row,dict):continue
                    candidate=str(row.get('run_id') or '').strip()
                    if not candidate or not re.fullmatch(r'[A-Za-z0-9._-]{1,120}',candidate):continue
                    (active if str(row.get('state','')).lower() in ('active','running') else other).append(candidate)
                candidates=list(dict.fromkeys(active+other))[:12]
        mine=None; all_rows=[]; coldkey_mismatch=False
        for candidate in candidates:
            scanned_runs+=1
            obj=self._fetch_json(API_MINERS+'?run_id='+urllib.parse.quote(candidate,safe=''),6)
            raw=obj.get('miners',[]) if isinstance(obj,dict) else obj
            rows=[r for r in raw if isinstance(r,dict)] if isinstance(raw,list) else []
            match=next((r for r in rows if str(r.get('hotkey','')).lower()==hk.lower()),None)
            if match:
                api_ck=str(match.get('coldkey') or '').strip()
                if ck and api_ck and api_ck.lower()!=ck.lower():
                    coldkey_mismatch=True
                    continue
                rid=candidate;mine=match;all_rows=rows;break
        if not mine:
            message=('The hotkey is present, but the API coldkey does not match the one entered.' if coldkey_mismatch else
                     'Hotkey was not present in this run’s public snapshot.' if run_id else
                     'Hotkey was not found in the public miner snapshots searched. The miner may be queued, offline, or not yet published by the API.')
            return {'ok':True,'found':False,'run_id':rid or None,'hotkey':hk,'scanned_runs':scanned_runs,'api_sampled_at':time.time(),'message':message}
        def number(record, keys):
            for key in keys:
                n=self._num(record.get(key))
                if n is not None:return n
            return None
        layer=mine.get('layer')
        cohort=[r for r in all_rows if (layer is None or str(r.get('layer'))==str(layer)) and number(r,('activation_count','activations','total_activations')) is not None]
        activation_count=number(mine,('activation_count','activations','total_activations'))
        higher=sum(1 for r in cohort if number(r,('activation_count','activations','total_activations'))>activation_count) if activation_count is not None else None
        direct_rank=number(mine,('epoch_rank','epochRank','rank_in_epoch','rankInEpoch','rank'))
        metrics_obj=None; epoch_points=[]; metric_error=None
        try:
            url=API_EPOCH_METRICS.format(run_id=urllib.parse.quote(rid,safe=''),hotkey=urllib.parse.quote(hk,safe=''))
            metrics_obj=self._fetch_json(url,10)
            epoch_points=self._extract_series(metrics_obj,('activations','activation_count','activationCount','activations_total','total_activations'))[-30:]
            if direct_rank is None:
                direct_rank=self._extract_latest_metric(metrics_obj,('epoch_rank','epochRank','rank_in_epoch','rankInEpoch'))
        except Exception as e:
            metric_error=type(e).__name__
        record={
            'hotkey':hk,'coldkey':mine.get('coldkey'),'run_id':rid,'layer':layer,'miner_uid':mine.get('miner_uid'),
            'activation_count':activation_count,'throughput':number(mine,('throughput','throughput_per_hour','throughputPerHour')),
            'incentive':number(mine,('incentive','score')),'is_active':mine.get('is_active'),
            'sample_timestamp':number(mine,('timestamp','updated_at','ts')),
            'active_same_layer':sum(1 for r in cohort if r.get('is_active') is True),
            'same_layer_miners_in_snapshot':len(cohort),
            'activation_standing':(int(higher+1) if higher is not None else None),
            'activation_standing_basis':'activation_count among same-layer miners in current /miners snapshot',
            'epoch_rank':direct_rank,
            'epoch_points':epoch_points,
            'epoch_metrics_available':metrics_obj is not None,
            'epoch_metrics_error':metric_error,
            'api_sampled_at':time.time(),
        }
        return {'ok':True,'found':True,'record':record}

    def _api_run_ids(self):
        ids=[]
        rid=self.state.get('run_id')
        if rid:
            # While mining, query only the run already identified by the local
            # T@H log. Avoid broad discovery requests and unrelated run metrics.
            if str(self.state.get('status','')).upper() == 'ACTIVE':
                return [str(rid)]
            ids.append(str(rid))
        try:
            obj=self._fetch_json(API_RUNS,8)
            runs=obj.get('runs',[]) if isinstance(obj,dict) else obj
            if isinstance(runs,list):
                active=[]; other=[]
                for r in runs:
                    if not isinstance(r,dict) or not r.get('run_id'):
                        continue
                    x=str(r['run_id'])
                    (active if str(r.get('state','')).lower()=='active' else other).append(x)
                ids.extend(active+other)
        except Exception as e:
            self.state['network_diagnostics']['runs']=f'{type(e).__name__}'
        out=[]
        for x in ids:
            if x not in out:
                out.append(x)
        return out[:3]

    def _resolve_miner_id_from_network(self,obj):
        """Resolve a miner ID from a network record that matches the user's
        configured public hotkey and/or coldkey.

        Only an explicitly named miner-id field is accepted. A bare unrelated
        numeric value is never treated as the miner ID. As a compatibility
        fallback, a numeric ``id`` is accepted only inside a record that matches
        the configured hotkey/coldkey.
        """
        hk=(active_hotkey() or '').strip().lower()
        ck=(active_coldkey() or '').strip().lower()
        if not hk and not ck:
            return ''
        hot_fields={'hotkey','miner_hotkey','minerhotkey','source_hotkey','sourcehotkey','hot_key'}
        cold_fields={'coldkey','miner_coldkey','minercoldkey','cold_key','owner_coldkey','ownerColdkey'}
        id_fields={'miner_id','minerid','minerId','miner'}
        for path,node in self._walk_records(obj):
            if not isinstance(node,dict):
                continue
            hot_match=False; cold_match=False
            for k,v in node.items():
                kl=str(k).lower()
                vs=str(v).strip().lower() if v is not None else ''
                if kl in hot_fields and hk and vs==hk: hot_match=True
                if kl in cold_fields and ck and vs==ck: cold_match=True
            if not (hot_match or cold_match):
                # Some responses are keyed directly by hotkey/coldkey.
                p=str(path).lower()
                hot_match = bool(hk and hk in p)
                cold_match = bool(ck and ck in p)
            if not (hot_match or cold_match):
                continue
            for k,v in node.items():
                if str(k) in id_fields or str(k).lower() in {x.lower() for x in id_fields}:
                    raw=self._num(v)
                    if raw is not None and float(raw).is_integer() and 0 <= raw <= 10**12:
                        return str(int(raw))
            # Compatibility: accept a numeric 'id' only within the matching record.
            if 'id' in node:
                raw=self._num(node.get('id'))
                if raw is not None and float(raw).is_integer() and 0 <= raw <= 10**12:
                    return str(int(raw))
        return ''

    def _parse_miner_api(self,obj):
        rec=self._find_identity_record(obj)
        if not rec:
            return None
        path,node=rec
        # Prefer explicit cumulative activation counters over rates.
        acts=self._extract_latest_metric(node,(
            'activations','activation_count','activationCount','activations_total',
            'activationsTotal','total_activations','totalActivations','accepted_activations',
            'acceptedActivations','activation_total'))
        if acts is None:
            acts=self._extract_metric_by_patterns(node,('activation_count','activations_total','total_activations','accepted_activations','totalactivation','activationcount'))
        if acts is None:
            acts,_=self._best_activation_metric(node)
        thr=self._extract_latest_metric(node,(
            'throughput_10m','throughput_per_10_min','throughputPer10Min',
            'average_per_10_min','averagePer10Min','average_throughput_10m',
            'average_throughput','avg_throughput','throughput','throughput_h',
            'throughputPerHour','throughput_per_hour'))
        if thr is None:
            thr,_=self._best_throughput_metric(node)
        fwd=self._extract_latest_metric(node,('activations_fwd','forward_activations','forwardActivations'))
        bwd=self._extract_latest_metric(node,('activations_bwd','backward_activations','backwardActivations'))
        return {'path':path,'record':node,'activations':acts,'throughput':thr,'fwd':fwd,'bwd':bwd}

    def _build_run_comparison(self,rows,hotkey,run_id,sampled_at):
        """Build a same-layer peer snapshot; distinguish API rank from calculated standing."""
        def number(record,keys):
            for key in keys:
                value=self._num(record.get(key))
                if value is not None:return value
            return None
        mine=next((r for r in rows if str(r.get('hotkey','')).lower()==str(hotkey).lower()),None)
        if mine is None:return {'found':False,'run_id':run_id,'sampled_at':sampled_at,'miners':[]}
        layer=mine.get('layer')
        same_layer=[r for r in rows if layer is not None and str(r.get('layer'))==str(layer)]
        act_keys=('activation_count','activations','total_activations','activationCount')
        throughput_keys=('throughput','throughput_per_hour','throughputPerHour','throughput_10m','throughput_10_min')
        incentive_keys=('incentive','score')
        rank_keys=('epoch_rank','epochRank','rank_in_epoch','rankInEpoch')
        own_activations=number(mine,act_keys)
        cohort=[r for r in same_layer if number(r,act_keys) is not None]
        activation_rank=(1+sum(1 for r in cohort if number(r,act_keys)>own_activations)) if own_activations is not None else None
        epoch_rank=number(mine,rank_keys)
        peers=[]
        for row in same_layer:
            hk=str(row.get('hotkey') or '')
            peers.append({
                'label':'YOU' if hk.lower()==str(hotkey).lower() else (hk[:8]+'…'+hk[-4:] if hk else 'PEER'),
                'is_miner':hk.lower()==str(hotkey).lower(),
                'activations':number(row,act_keys),'throughput':number(row,throughput_keys),
                'incentive':number(row,incentive_keys),'active':row.get('is_active')
            })
        return {
            'found':True,'run_id':run_id,'layer':layer,'epoch_rank':epoch_rank,
            'activation_rank':activation_rank,'activation_rank_count':len(cohort),
            'rank_basis':'API EPOCH RANK' if epoch_rank is not None else 'ACTIVATION COUNT AMONG SAME-LAYER API RECORDS',
            'same_layer_count':len(same_layer),'metrics':{
                'activations':own_activations,'throughput':number(mine,throughput_keys),
                'incentive':number(mine,incentive_keys)
            },'miners':peers,'sampled_at':sampled_at
        }

    def _metric_candidates(self,obj, token, prefer=(), exclude=()):
        """Return numeric values whose key/path contains token, ordered by relevance."""
        rows=[]
        for path,node in self._walk_records(obj):
            if not isinstance(node,dict):
                continue
            for k,v in node.items():
                ks=str(k).lower(); ps=str(path).lower()
                if token not in ks and token not in ps:
                    continue
                if any(x in ks or x in ps for x in exclude):
                    continue
                n=self._num(v)
                if n is None:
                    continue
                score=0
                for i,key in enumerate(prefer):
                    if key in ks or key in ps:
                        score += (len(prefer)-i)*10
                rows.append((score,path,ks,n))
        rows.sort(key=lambda x:(x[0],str(x[1])))
        return rows

    def _best_activation_metric(self,obj):
        rows=self._metric_candidates(
            obj,'activation',
            prefer=('total_activations','activations_total','activation_count','accepted_activations',
                    'totalactivation','activationcount','activations','activation'),
            exclude=('rate','per_sec','per_second','percentage','ratio','latency','timestamp','time','epoch'))
        if not rows:
            return None,[]
        return rows[-1][3],rows[-12:]

    def _best_throughput_metric(self,obj):
        rows=self._metric_candidates(
            obj,'throughput',
            prefer=('throughput_10m','throughput_10_min','average_per_10_min','average_throughput',
                    'avg_throughput','throughput_per_hour','throughput'),
            exclude=('timestamp','time'))
        if not rows:
            return None,None
        return rows[-1][3],rows[-1][2]

    def _best_direction_metric(self,obj,direction):
        token=direction.lower()
        rows=self._metric_candidates(obj,token,prefer=(f'{token}_activations',f'{token}activations',token),exclude=('timestamp','time'))
        return (rows[-1][3] if rows else None)

    def _series_activation_total(self,obj):
        """Handle APIs that expose activation counts as a time/epoch series rather than a scalar."""
        candidates=[]
        for path,node in self._walk_records(obj):
            if not isinstance(node,list) or not node:
                continue
            vals=[]
            for item in node:
                if isinstance(item,dict):
                    v,_=self._best_activation_metric(item)
                    if v is not None: vals.append(v)
            if len(vals)<2:
                continue
            # A monotonic series is normally cumulative: use its last value.
            if all(vals[i] >= vals[i-1] for i in range(1,len(vals))):
                candidates.append((str(path),vals[-1],"monotonic"))
            else:
                # A non-monotonic series is more likely interval counts. Sum it.
                candidates.append((str(path),sum(vals),"interval_sum"))
        if not candidates:
            return None,None
        # Prefer the longest informative series, then its last occurrence.
        best=max(candidates,key=lambda x:(len(x[0]),x[0]))
        return best[1],best[2]

    def _explicit_activation_metric(self,obj):
        rows=self._metric_candidates(
            obj,'activation',
            prefer=('total_activations','activations_total','activation_count','accepted_activations',
                    'totalactivation','activationcount'),
            exclude=('rate','per_sec','per_second','percentage','ratio','latency','timestamp','time','epoch'))
        return ((rows[-1][3],rows[-1][2],rows) if rows else (None,None,[]))

    def _parse_scoped_metrics(self,obj):
        """Parse the hotkey-scoped epoch metrics endpoint without requiring another identity field.

        The response may be either a scalar metric object or a time/epoch series. Prefer
        explicit cumulative/count fields, then resolve a series, then accept a generic scalar
        `activations` field.
        """
        acts,act_key,explicit_rows=self._explicit_activation_metric(obj)
        series_mode=None
        # Multiple explicit activation values usually mean the response is a time/epoch
        # series. Resolve that series instead of taking the final interval blindly.
        if len(explicit_rows)>1 and any('[' in str(r[1]) for r in explicit_rows):
            series_value,series_mode=self._series_activation_total(obj)
            if series_value is not None:
                acts=series_value
                act_key='activation_series:'+str(series_mode)
        if acts is None:
            acts,series_mode=self._series_activation_total(obj)
            if acts is not None:
                act_key='activation_series:'+str(series_mode)
        if acts is None:
            rows=self._metric_candidates(obj,'activation',prefer=('activations','activation'),exclude=('rate','per_sec','per_second','percentage','ratio','latency','timestamp','time','epoch'))
            if rows:
                acts,act_key=rows[-1][3],rows[-1][2]
        thr,thr_key=self._best_throughput_metric(obj)
        fwd=self._best_direction_metric(obj,'forward')
        bwd=self._best_direction_metric(obj,'backward')
        return {'activations':acts,'throughput':thr,'fwd':fwd,'bwd':bwd,'activation_series_mode':series_mode,
                'activation_field':act_key,'throughput_field':(thr_key if isinstance(thr_key,str) else None)}
    def _parse_entitlements(self,obj):
        found=[]
        for path,node in self._walk_records(obj):
            if not isinstance(node,dict):
                continue
            epoch=self._extract_latest_metric(node,('epoch','epoch_id','epochId','epoch_number','epochNumber'))
            amt=self._extract_latest_metric(node,('alpha','amount_alpha','alpha_amount','entitlement','payout','reward','amount'))
            if amt is not None and (epoch is not None or 'alpha' in str(path).lower() or 'entitlement' in str(path).lower()):
                found.append({'epoch':str(int(epoch)) if epoch is not None and float(epoch).is_integer() else (str(epoch) if epoch is not None else '—'),'alpha':amt})
        dedup={}
        for row in found:
            dedup[(row['epoch'],round(float(row['alpha']),12))]=row
        return list(dedup.values())[-50:]

    def poll_remote_network(self,force=False):
        if not self.remote_poll_lock.acquire(False):return
        try:return self._poll_remote_network(force)
        finally:self.remote_poll_lock.release()

    def _poll_remote_network(self,force=False):
        global RESOLVED_MINER_ID
        now=time.time()
        if not force and now-getattr(self,'last_remote_poll',0) < REMOTE_POLL_SECONDS:
            return
        self.last_remote_poll=now
        diagnostics={}
        primary=None
        series=[]
        availability, availability_status=self._api_runs_availability()
        if availability:
            self._refresh_run_performance(availability,now)
        with self.lock:
            if availability:
                self.state['run_availability']=availability
                self.state['run_availability_error']=None
                self.state['run_availability_updated_at']=now
            else:
                self.state['run_availability_error']=availability_status

        runs=self._api_run_ids()
        if not runs:
            diagnostics['runs']='NO RUNS'

        if not active_hotkey():
            diagnostics['hotkey']='NOT CONFIGURED'
            with self.lock:
                self.state.update({
                    'network_ok':bool(runs),
                    'network_source':'PUBLIC HOTKEY NOT CONFIGURED',
                    'network_last_checked':datetime.now().strftime('%H:%M:%S'),
                    'network_activations':None,'network_throughput':None,
                    'network_activations_fwd':None,'network_activations_bwd':None,
                    'network_endpoint':None,'network_throughput_source':None,
                    'network_metric_fields':[],'network_diagnostics':diagnostics,
                    'network_metrics_updated_at':None,
                    'network_poll_error':'Choose or enter this miner’s public hotkey, then save configuration.'
                })
            return

        matched_run_id=None
        # A) /miners is the first unscoped per-miner source.
        for rid in runs:
            try:
                url=API_MINERS+"?run_id="+urllib.parse.quote(str(rid),safe='')
                obj=self._fetch_json(url,10)
                resolved=self._resolve_miner_id_from_network(obj)
                if resolved:
                    RESOLVED_MINER_ID=resolved
                    with self.lock:
                        if not self.state.get("config_miner_id"):
                            self.state["resolved_miner_id"]=resolved
                            self.state["miner_id_source"]="AUTO-RESOLVED FROM PUBLIC API"
                rec=self._parse_miner_api(obj)
                if not rec:
                    # A few deployments expose optional filtering without documenting it.
                    # Try the same public endpoint with the miner identity explicitly scoped.
                    scoped_url=url+"&hotkey="+urllib.parse.quote(active_hotkey(),safe='')
                    try:
                        scoped_obj=self._fetch_json(scoped_url,10)
                        rec=self._parse_miner_api(scoped_obj)
                        if rec:
                            obj=scoped_obj; url=scoped_url
                    except Exception:
                        pass
                if rec:
                    matched_run_id=rid
                if rec and (rec.get('activations') is not None or rec.get('throughput') is not None):
                    primary={'activations':rec.get('activations'),'throughput':rec.get('throughput'),
                             'fwd':rec.get('fwd'),'bwd':rec.get('bwd'),'record':rec.get('record'),
                             'source':'Macrocosmos /miners','endpoint':url,'run_id':rid}
                    diagnostics['miners']='MATCH'
                    break
                if rec:
                    diagnostics['miners']=f'MINER FOUND · METRICS NOT EXPOSED ({rid})'
                    break
                diagnostics['miners']=f'NO MATCH ({rid})'
            except Exception as e:
                diagnostics['miners']=f'{type(e).__name__} ({rid})'

        # B) The exact hotkey-scoped metrics endpoint is the authoritative
        # activation fallback/verification path supplied by the T@H team.
        for rid in runs:
            try:
                url=API_EPOCH_METRICS.format(run_id=urllib.parse.quote(str(rid),safe=''),hotkey=active_hotkey())
                obj=self._fetch_json(url,10)
                rec=self._parse_scoped_metrics(obj)
                if rec.get('activations') is not None or rec.get('throughput') is not None:
                    if primary is None:
                        primary={'activations':rec.get('activations'),'throughput':rec.get('throughput'),
                                 'fwd':rec.get('fwd'),'bwd':rec.get('bwd'),'record':obj,
                                 'source':'Macrocosmos /epoch_miner_scores','endpoint':url,'run_id':rid, 'activation_field':rec.get('activation_field'), 'throughput_field':rec.get('throughput_field')}
                    else:
                        if primary.get('activations') is None: primary['activations']=rec.get('activations')
                        if primary.get('fwd') is None: primary['fwd']=rec.get('fwd')
                        if primary.get('bwd') is None: primary['bwd']=rec.get('bwd')
                        primary['epoch_endpoint']=url
                    # Keep ordered activation history from the scoped endpoint.
                    series=self._extract_series(obj,('activations','activation_count','activationCount','activations_total','total_activations'))
                    diagnostics['epoch_metrics']='MATCH'
                    break
                diagnostics['epoch_metrics']=f'NO ACTIVATION DATA ({rid})'
            except Exception as e:
                diagnostics['epoch_metrics']=f'{type(e).__name__} ({rid})'

        # C) Throughput statistics are intentionally parsed only from the
        # record matching this hotkey. Never fall back to a network aggregate.
        if runs:
            rid=(primary.get('run_id') if primary else runs[0])
            try:
                url=API_THROUGHPUT+"?run_id="+urllib.parse.quote(str(rid),safe='')
                obj=self._fetch_json(url,10)
                rec=self._parse_miner_api(obj)
                if rec and rec.get('throughput') is not None:
                    if primary is None:
                        primary={'activations':rec.get('activations'),'throughput':rec.get('throughput'),
                                 'fwd':rec.get('fwd'),'bwd':rec.get('bwd'),'record':rec.get('record'),
                                 'source':'Macrocosmos /throughput_statistics','endpoint':url,'run_id':rid}
                    else:
                        primary['throughput']=rec.get('throughput')
                        primary['throughput_endpoint']=url
                    diagnostics['throughput']='MATCH'
                else:
                    diagnostics['throughput']='NO HOTKEY MATCH'
            except Exception as e:
                diagnostics['throughput']=f'{type(e).__name__}'

        diagnostics['miner_id']=('CONFIGURED '+str(effective_miner_id())) if active_miner_id() else (('AUTO-RESOLVED '+str(RESOLVED_MINER_ID)) if RESOLVED_MINER_ID else 'NOT RESOLVED')

        # D) Payout/entitlement history is separate from telemetry.
        payout_rows=[]
        try:
            url=API_ENTITLEMENTS.format(hotkey=active_hotkey())
            obj=self._fetch_json(url,10)
            payout_rows=self._parse_entitlements(obj)
            diagnostics['entitlements']='MATCH' if payout_rows else 'NO ROWS'
            if payout_rows:
                with self.lock:self.state['payouts_source']=url
        except Exception as e:
            diagnostics['entitlements']=f'{type(e).__name__}'

        ts=datetime.now().strftime('%H:%M:%S')
        # Even if no miner metric matched, a successful /runs response means the
        # network service itself is online. Do not label the whole network OFFLINE
        # merely because a metric field has an unexpected schema.
        try:
            network_service_ok = 'runs' not in diagnostics or not str(diagnostics.get('runs','')).startswith(('URLError','HTTPError','ValueError'))
        except Exception:
            network_service_ok=False
        if primary and (primary.get('activations') is not None or primary.get('throughput') is not None):
            acts=primary.get('activations'); thr=primary.get('throughput'); fwd=primary.get('fwd'); bwd=primary.get('bwd')
            source_parts=[]
            if acts is not None: source_parts.append('Macrocosmos activations')
            if thr is not None: source_parts.append('Macrocosmos throughput')
            with self.lock:
                self.state['network_ok']=True
                self.state['network_source']=' + '.join(source_parts) or primary.get('source')
                self.state['network_endpoint']=primary.get('endpoint')
                self.state['network_throughput_source']=primary.get('throughput_endpoint') or primary.get('epoch_endpoint') or primary.get('endpoint')
                self.state['network_last_checked']=ts
                self.state['network_metrics_updated_at']=now
                self.state['network_poll_error']=None
                self.state['network_activations']=int(acts) if acts is not None and float(acts).is_integer() else acts
                self.state['network_throughput']=int(thr) if thr is not None and float(thr).is_integer() else thr
                self.state['network_activations_fwd']=int(fwd) if fwd is not None and float(fwd).is_integer() else fwd
                self.state['network_activations_bwd']=int(bwd) if bwd is not None and float(bwd).is_integer() else bwd
                self.state['network_payload']=primary.get('record')
                # Record which metric keys were actually found; this makes failures diagnosable
                # without dumping the entire API response into the UI.
                fields=[]
                for k in ('activation_field','throughput_field'):
                    if primary.get(k): fields.append(str(primary.get(k)))
                if not fields:
                    for k in ('activations','throughput','fwd','bwd'):
                        if primary.get(k) is not None: fields.append(k)
                self.state['network_metric_fields']=fields
                self.state['network_diagnostics']=diagnostics
                if primary.get('run_id'): self.state['run_id']=primary.get('run_id')
                if series: self.state['series']=series
            c=self.db()
            c.execute("INSERT INTO remote_samples VALUES(?,?,?,?,?,?,?,?)",(
                int(now),acts,thr,self.state.get('network_source'),primary.get('endpoint'),fwd,bwd,json.dumps(primary.get('record'),default=str)[:500000]))
            for p in payout_rows:
                c.execute("INSERT INTO payouts VALUES(?,?,?)",(int(now),str(p['epoch']),float(p['alpha'])))
            c.execute("DELETE FROM remote_samples WHERE ts < ?",(int(now)-30*86400,))
            c.execute("DELETE FROM payouts WHERE ts < ?",(int(now)-365*86400,))
            c.commit();c.close()
            self.state['payouts']=payout_rows[-30:]
            if acts is not None:self.add_event('info',f"MACROCOSMOS ACTIVATIONS {int(acts) if float(acts).is_integer() else acts}")
            if thr is not None:self.add_event('info',f"MACROCOSMOS THROUGHPUT {thr}")
        else:
            with self.lock:
                self.state['network_ok']=bool(network_service_ok)
                self.state['network_last_checked']=ts
                self.state['network_source']='Macrocosmos API ONLINE · METRIC SCHEMA NOT MATCHED' if network_service_ok else None
                self.state['network_endpoint']=API_RUNS if network_service_ok else None
                self.state['network_throughput_source']=None
                self.state['network_metric_fields']=[]
                self.state['network_activations']=None
                self.state['network_throughput']=None
                self.state['network_activations_fwd']=None
                self.state['network_activations_bwd']=None
                self.state['network_metrics_updated_at']=None
                self.state['network_diagnostics']=diagnostics
                self.state['network_poll_error']='No matching activation metric in latest API response'
                if matched_run_id:
                    self.state['run_id']=matched_run_id
                if payout_rows:self.state['payouts']=payout_rows[-30:]

    def tick(self):
        while True:
            self.scan()
            self.sample()
            self.state["uptime"]=self.uptime()
            self.refresh_shit_state()
            time.sleep(5)

    def remote_network_loop(self):
        while True:
            try:self.poll_remote_network(force=True)
            except Exception as exc:
                with self.lock:self.state['network_poll_error']=type(exc).__name__
            time.sleep(REMOTE_POLL_SECONDS)

    def poll_active_run_comparison(self):
        with self.lock:
            status=str(self.state.get('status') or '').upper()
            hotkey=str(self.state.get('hotkey') or '').strip()
            run_id=str(self.state.get('run_id') or '').strip()
        if status!='ACTIVE' or not hotkey or not run_id:
            with self.lock:
                self.state['run_comparison']=None
                self.state['run_comparison_updated_at']=None
            return
        now=time.time()
        url=API_MINERS+'?run_id='+urllib.parse.quote(run_id,safe='')
        obj=self._fetch_json(url,8)
        raw=obj.get('miners',[]) if isinstance(obj,dict) else obj
        rows=[r for r in raw if isinstance(r,dict)] if isinstance(raw,list) else []
        comparison=self._build_run_comparison(rows,hotkey,run_id,now)
        with self.lock:
            self.state['run_comparison']=comparison
            self.state['run_comparison_updated_at']=now
            self.state['run_comparison_error']=None

    def active_run_comparison_loop(self):
        while True:
            try:self.poll_active_run_comparison()
            except Exception as exc:
                with self.lock:self.state['run_comparison_error']=type(exc).__name__
            time.sleep(60)

    def local_api_loop(self):
        while True:
            try:self.poll_local_api()
            except Exception:pass
            time.sleep(15)

    def network_latency_loop(self):
        while True:
            try:self.poll_network_latency()
            except Exception:pass
            time.sleep(30)

    def poll_network_latency(self):
        """Passively sample local health without generating WAN probe traffic.

        T@H owns its transfer path. We only ping the local gateway (one tiny
        LAN packet every 30 seconds) and read CPU/memory pressure; WAN/API timing comes
        from the ordinary, infrequent telemetry requests, never separate
        speed tests or recurring public-host probes.
        """
        def ping(host):
            if not host:
                return None
            try:
                proc=subprocess.run(["/sbin/ping","-c","1","-W","1000",host],capture_output=True,text=True,timeout=2.5)
                if proc.returncode != 0:
                    return None
                m=re.search(r"time[=<]([0-9.]+)\s*ms",proc.stdout)
                return float(m.group(1)) if m else None
            except Exception:
                return None

        gateway=None
        try:
            proc=subprocess.run(["/sbin/route","-n","get","default"],capture_output=True,text=True,timeout=2)
            m=re.search(r"^\s*gateway:\s*(\S+)",proc.stdout,re.M)
            if m: gateway=m.group(1)
        except Exception:
            pass

        router_ms=ping(gateway)
        api_icmp=None
        api_http=None

        checked_at=time.time()
        try:
            load1,load5,_=os.getloadavg()
            cores=os.cpu_count() or 1
        except Exception:load1=load5=None;cores=os.cpu_count() or 1
        mem_free_pct=None
        try:
            mp=subprocess.run(["/usr/bin/memory_pressure","-Q"],capture_output=True,text=True,timeout=2)
            mm=re.search(r"System-wide memory free percentage:\s*(\d+)%",mp.stdout)
            if mm:mem_free_pct=float(mm.group(1))
        except Exception:pass
        with self.lock:
            self.state["router_gateway"]=gateway
            self.state["router_latency_ms"]=router_ms
            self.state["macrocosmos_icmp_ms"]=api_icmp
            self.state["macrocosmos_http_ms"]=api_http
            self.state["latency_checked"]=datetime.now().strftime("%H:%M:%S")
        c=self.db()
        c.execute("INSERT INTO network_health_samples(ts,router_ms,api_http_ms,api_icmp_ms,upload_mbps,download_mbps,upload_ts,peer_pct,load1,load5,cpu_cores,mem_free_pct) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(
            checked_at,router_ms,api_http,api_icmp,self.state.get('upload_mbps'),self.state.get('download_mbps'),
            self.state.get('upload_sampled_at'),self.state.get('peer_pct'),load1,load5,cores,mem_free_pct))
        c.execute("DELETE FROM network_health_samples WHERE ts<?",(checked_at-7*86400,));c.commit();c.close()

    def poll_local_api(self):
        def get(url):
            try:
                req=urllib.request.Request(url,headers={"User-Agent":"IOTA-Matrix-Monitor/2.7"})
                with urllib.request.urlopen(req,timeout=2.5) as r:
                    return json.loads(r.read().decode("utf-8","replace"))
            except Exception:return None
        h=get(PROTOCOL_URL+"/health")
        if isinstance(h,dict):
            self.state["protocol_ok"]=bool(h.get("ok",False)); self.state["protocol_connected"]=bool(h.get("connected",False))
            client=h.get("client") or {}; self.state["app_version"]=client.get("appVersion")
        else:self.state["protocol_ok"]=False; self.state["protocol_connected"]=False
        keys=get(VIZ_URL+"/api/hotkeys")
        timers=get(VIZ_URL+"/api/timer_names")
        self.state["viz_ok"]=isinstance(keys,list)
        if isinstance(keys,list) and keys:
            # Do not display full hotkeys; only use presence as a local API sanity check.
            self.state["local_hotkeys"]=len(keys)
        if isinstance(timers,list):self.state["timer_names"]=timers


    def uptime(self):
        sec=int(time.time()-self.started);d,sec=divmod(sec,86400);h,sec=divmod(sec,3600);m,s=divmod(sec,60)
        return (f"{d}d " if d else "")+f"{h:02}:{m:02}:{s:02}"

def log_queue_history_today():
    """Rebuild today's queue series directly from the T@H CLI logs.

    The chart must reflect every queue position actually written to the logs,
    even if SQLite was cleared, rotated, or missed a write during a restart.
    Log timestamps are local Mac clock timestamps, so we compare by local date.
    """
    today = datetime.now().date()
    rows = []
    try:
        files = sorted(LOG_DIR.glob("*-cli.log"), key=lambda p: p.stat().st_mtime if p.exists() else 0)
    except Exception:
        files = []

    for p in files:
        try:
            with p.open("r", errors="replace") as f:
                for line in f:
                    tm = RE_TS.search(line)
                    if not tm:
                        continue
                    try:
                        raw = tm.group(1)
                        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f")
                    except Exception:
                        continue
                    if dt.date() != today:
                        continue

                    m = RE_QUEUE.search(line)
                    if m:
                        pos = int(m.group(2))
                    else:
                        m = RE_QUEUE_ALT.search(line)
                        if not m or not ("register/status" in line.lower() or "queue_id" in line.lower()):
                            continue
                        pos = int(m.group(1))

                    rows.append((dt.timestamp(), pos))
        except Exception:
            continue

    rows.sort(key=lambda x: x[0])

    # Persist the reconstructed day so the existing history database remains
    # useful, while avoiding duplicate rows from repeated refreshes.
    try:
        start_dt = datetime(today.year, today.month, today.day)
        end_dt = start_dt.timestamp() + 86400
        c = mon.db()
        c.execute("DELETE FROM queue_history WHERE ts >= ? AND ts < ?", (start_dt.timestamp(), end_dt))
        c.executemany("INSERT INTO queue_history(ts,position) VALUES(?,?)", rows)
        c.commit()
        c.close()
    except Exception:
        pass

    return [{"ts": ts, "position": pos} for ts, pos in rows]

mon=Monitor()

def start_monitor_workers():
    for target,name in ((mon.tick,"log-monitor"),(mon.remote_network_loop,"api-monitor"),
                        (mon.active_run_comparison_loop,"active-run-rank"),
                        (mon.local_api_loop,"local-api-monitor"),(mon.network_latency_loop,"latency-monitor")):
        threading.Thread(target=target,name=name,daemon=True).start()

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        req_path=urllib.parse.urlsplit(self.path).path
        query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if self.path in ("/neo_ascii.png","/hands_pills.png","/matrix_hands_banner.png"):
            try:
                asset=resource_path(self.path.lstrip("/"))
                data=asset.read_bytes()
                self.send_response(200); self.send_header("Content-Type","image/png"); self.send_header("Cache-Control","public,max-age=3600"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
            except Exception:
                self.send_response(404); self.end_headers()
            return
        if self.path=="/":
            payload=HTML.replace("__LOCAL_TOKEN__",LOCAL_TOKEN).encode();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(payload)));self.end_headers();self.wfile.write(payload);return
        if req_path=="/api/agent/config":
            cfg=read_agent_config();path=agent_launch_agent_path()
            payload=json.dumps({**cfg,"installed":path.exists(),"fingerprint":hub_cert_fingerprint(),"hub_addresses":local_network_addresses(),"agent_port":AGENT_PORT}).encode();self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(payload);return
        if req_path=="/api/wallets":
            wallets=detect_bittensor_wallets()
            payload=json.dumps({"wallets":wallets,"error":None if wallets else "No readable public hotkey/coldkey pairs found under ~/.bittensor/wallets"}).encode()
            self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(payload);return
        if req_path=="/api/miners":
            with MINER_LOCK:
                rows=[]
                for p in MINERS:
                    report=MINER_REPORTS.get(p["id"],{})
                    online=p.get("source")=="local" or time.time()-float(report.get("received_at",0))<45
                    rows.append({"id":p["id"],"name":p["name"],"hotkey":p.get("hotkey",""),"coldkey":p.get("coldkey",""),"source":p.get("source","agent"),"online":online,"last_seen":report.get("received_at"),"selected":p["id"]==ACTIVE_PROFILE_ID})
            payload=json.dumps({"miners":rows,"active":ACTIVE_PROFILE_ID}).encode();self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(payload);return
        if req_path=="/api/config":
            pid=query.get("miner",[ACTIVE_PROFILE_ID])[0]
            if pid!="local":
                with MINER_LOCK:profile=copy.deepcopy(profile_by_id(pid))
                if not profile:self.send_response(404);self.end_headers();return
                profile.pop("agent_token",None)
                payload=json.dumps({**profile,"hotkey_source":"USER CONFIGURED","log_dir":"REMOTE AGENT","log_dir_configured":"","log_dir_auto":True}).encode();self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(payload);return
            cfg=load_config();
            try: active_logs=resolve_log_dir(cfg.get("log_dir"))
            except ValueError: active_logs=resolve_log_dir("")
            payload=json.dumps({**cfg,"log_dir_configured":cfg.get("log_dir",""),"log_dir":str(active_logs),"log_dir_auto":not bool(cfg.get("log_dir")),"hotkey_source":"USER CONFIGURED"}).encode(); self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(payload); return
        if req_path=="/api/queue_history":
            pid=query.get("miner",[ACTIVE_PROFILE_ID])[0]
            if pid=="local":rows=log_queue_history_today()
            else:
                with MINER_LOCK:report=copy.deepcopy(MINER_REPORTS.get(pid,{}))
                rows=report.get("queue_history",[])
            payload=json.dumps(rows).encode()
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(payload); return
        if self.path=="/api/run_availability":
            with mon.lock:
                rows=list(mon.state.get('run_availability') or []); rid=mon.state.get('run_id'); err=mon.state.get('run_availability_error')
            payload=json.dumps({'runs':rows,'current_run':rid,'error':err}).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(payload);return
        if req_path=="/api/state":
            pid=query.get("miner",[ACTIVE_PROFILE_ID])[0]
            if pid=="local":
                with mon.lock:state=copy.deepcopy(mon.state)
            else:
                with MINER_LOCK:profile=copy.deepcopy(profile_by_id(pid));report=copy.deepcopy(MINER_REPORTS.get(pid,{}))
                state=copy.deepcopy(report.get("state") or {})
                state.update({"config_name":profile.get("name") if profile else "Unknown miner","hotkey":profile.get("hotkey") if profile else "","agent_online":bool(report and time.time()-float(report.get("received_at",0))<45),"agent_last_seen":report.get("received_at") if report else None})
                if not report:state={"status":"AGENT OFFLINE","events":[],"payouts":[],"series":[],"run_availability":[],"shit_counts":{},"shit_details":{},"log_files":[],"agent_online":False,"hotkey":profile.get("hotkey") if profile else "","config_name":profile.get("name") if profile else "Unknown miner"}
            payload=json.dumps(state).encode()
            self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(payload)
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        global CFG, LOG_DIR, RESOLVED_MINER_ID, ACTIVE_PROFILE_ID
        if self.path=="/api/agent/report":
            try:
                n=int(self.headers.get("Content-Length","0"))
                if n<=0 or n>2_000_000:raise ValueError("Invalid report size")
                obj=json.loads(self.rfile.read(n));pid=str(obj.get("miner_id",""));token=self.headers.get("X-Agent-Token","")
                with MINER_LOCK:profile=profile_by_id(pid)
                if not profile or not profile.get("agent_token") or not secrets.compare_digest(token,profile["agent_token"]):
                    self.send_response(403);self.end_headers();return
                if not isinstance(obj.get("state"),dict):raise ValueError("Missing report data")
                report={"received_at":time.time(),"state":obj["state"],"queue_history":obj.get("queue_history",[])}
                with MINER_LOCK:
                    MINER_REPORTS[pid]=report;REPORTS_DIR.mkdir(parents=True,exist_ok=True);atomic_json(REPORTS_DIR/(pid+".json"),report)
                    profile_update={k:profile.get(k,"") for k in ("name","hotkey","coldkey","miner_id")}
                body=json.dumps({"profile":profile_update}).encode();self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body);return
            except Exception:
                self.send_response(400);self.end_headers();return
        if self.headers.get("X-Monitor-Token","") != LOCAL_TOKEN:
            self.send_response(403); self.end_headers(); return
        if self.path=="/api/miner_lookup":
            try:
                n=int(self.headers.get("Content-Length","0"))
                if n<=0 or n>8192:raise ValueError("Invalid request size")
                obj=json.loads(self.rfile.read(n))
                result=mon.lookup_public_miner(obj.get("hotkey",""),obj.get("run_id",""),obj.get("coldkey",""))
                body=json.dumps(result,default=str).encode()
                self.send_response(200);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body);return
            except Exception as e:
                body=json.dumps({"ok":False,"error":str(e)}).encode()
                self.send_response(400);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body);return
        if self.path == "/api/remote_refresh":
            threading.Thread(target=mon.poll_remote_network,kwargs={"force":True},daemon=True).start()
            self.send_response(204); self.end_headers(); return
        if self.path=="/api/agent/install":
            try:
                n=int(self.headers.get("Content-Length","0"));obj=json.loads(self.rfile.read(n))
                cfg={"hub_url":str(obj.get("hub_url","")).strip().rstrip("/"),"profile_id":str(obj.get("profile_id","")).strip(),"token":str(obj.get("token","")).strip(),"tls_fingerprint":re.sub(r"[^0-9a-f]","",str(obj.get("tls_fingerprint","")).lower())}
                parsed=urllib.parse.urlsplit(cfg["hub_url"])
                if parsed.scheme!="https" or not parsed.hostname:raise ValueError("Enter the dashboard Mac HTTPS address")
                if len(cfg["profile_id"])<8 or not cfg["token"]:raise ValueError("Miner pairing details are required")
                if len(cfg["tls_fingerprint"])!=64:raise ValueError("TLS fingerprint must contain 64 hexadecimal characters")
                hk=str(obj.get("hotkey","")).strip();ck=str(obj.get("coldkey","")).strip();name=str(obj.get("name","")).strip() or DEFAULT_MINER_NAME;mid=str(obj.get("miner_id","")).strip()
                if not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",hk):raise ValueError("Enter a valid SS58 public hotkey")
                if ck and not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",ck):raise ValueError("Enter a valid SS58 public coldkey")
                if ck and ck==hk:raise ValueError("Hotkey and coldkey cannot be the same")
                log_dir=str(obj.get("log_dir","")).strip();resolved_logs=resolve_log_dir(log_dir)
                old_identity=profile_identity();new_identity=profile_identity(hk,ck)
                CFG={"name":name,"hotkey":hk,"coldkey":ck,"miner_id":mid,"log_dir":log_dir};save_config(CFG);LOG_DIR=resolved_logs;RESOLVED_MINER_ID=""
                if old_identity!=new_identity:mon._clear_profile_data();mon._set_profile_identity(new_identity)
                with mon.lock:mon.state.update({"config_name":name,"hotkey":hk,"config_miner_id":mid,"log_dir":str(LOG_DIR)})
                mon.last_remote_poll=0
                AGENT_CONFIG.parent.mkdir(parents=True,exist_ok=True);atomic_json(AGENT_CONFIG,cfg);install_agent_launch_agent()
                self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(b'{"ok":true}');return
            except Exception as e:
                self.send_response(400);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(json.dumps({"ok":False,"error":str(e)}).encode());return
        if self.path=="/api/agent/remove":
            path=agent_launch_agent_path();uid=os.getuid()
            subprocess.run(["/bin/launchctl","bootout",f"gui/{uid}",str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:path.unlink()
            except FileNotFoundError:pass
            try:AGENT_CONFIG.unlink()
            except FileNotFoundError:pass
            self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(b'{"ok":true}');return
        if self.path=="/api/miner_select":
            self.send_response(409);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(b'{"ok":false,"error":"This build supports one miner per app instance."}');return
            try:
                obj=json.loads(self.rfile.read(int(self.headers.get("Content-Length","0"))));pid=str(obj.get("miner_id",""))
                with MINER_LOCK:
                    if not profile_by_id(pid):raise ValueError("Miner profile not found")
                    ACTIVE_PROFILE_ID=pid
                self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(b'{"ok":true}');return
            except Exception as e:
                self.send_response(400);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(json.dumps({"ok":False,"error":str(e)}).encode());return
        if self.path=="/api/miners":
            self.send_response(409);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(b'{"ok":false,"error":"This build supports one miner per app instance."}');return
            try:
                n=int(self.headers.get("Content-Length","0"))
                if n<=0 or n>16384:raise ValueError("Invalid request size")
                obj=json.loads(self.rfile.read(n));name=str(obj.get("name","")).strip();hk=str(obj.get("hotkey","")).strip();ck=str(obj.get("coldkey","")).strip();mid=str(obj.get("miner_id","")).strip()
                if not name or len(name)>80:raise ValueError("Enter a miner name (maximum 80 characters)")
                if not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",hk):raise ValueError("Enter a valid SS58 public hotkey")
                if ck and not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",ck):raise ValueError("Enter a valid SS58 public coldkey")
                if ck and ck==hk:raise ValueError("Hotkey and coldkey cannot be the same")
                if len(mid)>128:raise ValueError("Miner ID is too long")
                profile={"id":uuid.uuid4().hex[:16],"name":name,"hotkey":hk,"coldkey":ck,"miner_id":mid,"source":"agent","agent_token":secrets.token_urlsafe(32),"created_at":int(time.time())}
                with MINER_LOCK:MINERS.append(profile);save_miners()
                self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(json.dumps({"ok":True,"miner":{k:v for k,v in profile.items() if k!="agent_token"},"agent_token":profile["agent_token"],"hub_addresses":local_network_addresses(),"agent_port":AGENT_PORT,"tls_fingerprint":hub_cert_fingerprint()}).encode());return
            except Exception as e:
                self.send_response(400);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(json.dumps({"ok":False,"error":str(e)}).encode());return
        if self.path=="/api/config" and ACTIVE_PROFILE_ID!="local":
            try:
                n=int(self.headers.get("Content-Length","0"));obj=json.loads(self.rfile.read(n));hk=str(obj.get("hotkey","")).strip();ck=str(obj.get("coldkey","")).strip();name=str(obj.get("name","")).strip();mid=str(obj.get("miner_id","")).strip()
                if not name or len(name)>80:raise ValueError("Enter a miner name")
                if not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",hk):raise ValueError("Enter a valid SS58 public hotkey")
                if ck and not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",ck):raise ValueError("Enter a valid SS58 public coldkey")
                with MINER_LOCK:
                    p=profile_by_id(ACTIVE_PROFILE_ID)
                    if not p:raise ValueError("Miner profile not found")
                    p.update({"name":name,"hotkey":hk,"coldkey":ck,"miner_id":mid});save_miners()
                self.send_response(200);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(b'{"ok":true}');return
            except Exception as e:
                self.send_response(400);self.send_header("Content-Type","application/json");self.end_headers();self.wfile.write(json.dumps({"ok":False,"error":str(e)}).encode());return
        if self.path!="/api/config":
            self.send_response(404); self.end_headers(); return
        try:
            n=int(self.headers.get("Content-Length","0"))
            if n <= 0 or n > 16384: raise ValueError("Invalid request size")
            obj=json.loads(self.rfile.read(n))
            if not isinstance(obj,dict): raise ValueError("Configuration must be an object")
            hk=str(obj.get("hotkey","")).strip(); ck=str(obj.get("coldkey","")).strip(); name=str(obj.get("name","")).strip() or DEFAULT_MINER_NAME; mid=str(obj.get("miner_id","")).strip(); log_dir=str(obj.get("log_dir","")).strip()
            if not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",hk):
                raise ValueError("Enter a valid SS58 public hotkey")
            if ck and not re.fullmatch(r"5[1-9A-HJ-NP-Za-km-z]{46,47}",ck):
                raise ValueError("Enter a valid SS58 public coldkey")
            if len(name)>80 or len(mid)>128: raise ValueError("Name or miner ID is too long")
            if hk == ck and ck:
                raise ValueError("Hotkey and coldkey cannot be the same")
            resolved_logs=resolve_log_dir(log_dir)
            old_identity=profile_identity()
            new_identity=profile_identity(hk,ck)
            identity_changed=(old_identity != new_identity)
            CFG={"name":name,"hotkey":hk,"coldkey":ck,"miner_id":mid,"log_dir":log_dir}; save_config(CFG)
            with MINER_LOCK:
                local_profile=profile_by_id("local")
                if local_profile:local_profile.update({"name":name,"hotkey":hk,"coldkey":ck,"miner_id":mid});save_miners()
            RESOLVED_MINER_ID=""
            if identity_changed:
                mon._clear_profile_data()
                mon._set_profile_identity(new_identity)
            LOG_DIR=resolved_logs
            with mon.lock:
                mon.state["config_name"]=name; mon.state["config_miner_id"]=mid; mon.state["resolved_miner_id"]=""; mon.state["miner_id_source"]="CONFIGURED" if mid else "NOT RESOLVED"; mon.state["hotkey"]=hk; mon.state["hotkey_source"]="USER CONFIGURED"; mon.state["log_dir"]=str(LOG_DIR)
                if identity_changed:
                    mon.state["run_id"]=None; mon.state["epoch"]=None; mon.state["layer"]=None; mon.state["status"]="SCANNING"
            mon.last_remote_poll=0
            self.send_response(200); self.send_header("Content-Type","application/json"); self.end_headers(); self.wfile.write(b'{"ok":true}')
        except Exception as e:
            self.send_response(400); self.send_header("Content-Type","application/json"); self.end_headers(); self.wfile.write(json.dumps({"ok":False,"error":str(e)}).encode())

class AgentHubHandler(Handler):
    """Network listener exposes only authenticated agent report ingestion."""
    def do_GET(self):
        self.send_response(404);self.end_headers()
    def do_POST(self):
        if self.path=="/api/agent/report":return super().do_POST()
        self.send_response(404);self.end_headers()

def main():
    global PORT, DASHBOARD_URL, AGENT_PORT
    if "--agent" in sys.argv:
        run_agent();return
    start_monitor_workers()

    # Bind only to loopback. The server remains private to the desktop app.
    for candidate in range(DEFAULT_PORT, DEFAULT_PORT + 20):
        try:
            server=ThreadingHTTPServer(("127.0.0.1",candidate),Handler)
            PORT=candidate
            DASHBOARD_URL=f"http://127.0.0.1:{PORT}/"
            break
        except OSError:
            continue
    else:
        raise OSError("No free local monitor port found")

    threading.Thread(target=server.serve_forever,daemon=True).start()
    hub_server=None
    try:
        ensure_hub_certificate()
        for candidate in range(AGENT_PORT,AGENT_PORT+20):
            try:
                hub_server=ThreadingHTTPServer(("0.0.0.0",candidate),AgentHubHandler);AGENT_PORT=candidate;break
            except OSError:continue
        if hub_server is None:raise OSError("No free miner-agent port found")
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(str(HUB_CERT),str(HUB_KEY))
        hub_server.socket=context.wrap_socket(hub_server.socket,server_side=True)
        threading.Thread(target=hub_server.serve_forever,daemon=True).start()
    except Exception as exc:
        if hub_server:
            hub_server.server_close();hub_server=None
        mon.add_event("error",f"REMOTE AGENT HUB UNAVAILABLE: {type(exc).__name__}")
    try:
        import webview
    except ImportError:
        # Keep the source launcher usable without the optional native-webview dependencies.
        webbrowser.open(DASHBOARD_URL)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    else:
        webview.create_window(
            "IOTA Matrix Monitor", DASHBOARD_URL,
            width=1440, height=960, min_size=(900, 620),
            text_select=True, background_color="#020604"
        )
        storage=DB.parent / "WebView"
        storage.mkdir(parents=True,exist_ok=True)
        try:
            webview.start(gui="cocoa",private_mode=False,storage_path=str(storage))
        finally:
            server.shutdown()
            server.server_close()
            if hub_server:
                hub_server.shutdown();hub_server.server_close()

if __name__=="__main__":
    main()
