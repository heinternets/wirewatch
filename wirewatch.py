#!/usr/bin/env python3
"""
Wirewatch — one-command Zeek network monitor.

Checks for Zeek, starts a live capture (or reads a pcap), and streams
enriched, color-coded, cross-referenced protocol output as it happens.

Typical use:
    python3 wirewatch.py                  # brew-installs Zeek if missing,
                                           # sudo zeek -i en0, then tails
    python3 wirewatch.py -i en1
    python3 wirewatch.py --pcap capture.pcap
    python3 wirewatch.py --attach-only    # just tail logs from a Zeek
                                           # process you started yourself
"""
import argparse
import glob
import ipaddress
import json
import os
import platform
import re
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

try:
    import termios
    import tty
    HAS_TERMIOS = True
except ImportError:
    HAS_TERMIOS = False

# --- ANSI Terminal Color Palette ---
C_TIME    = "\033[90m"          # Dark Gray / Muted
C_DNS     = "\033[1;36m"        # Bright Cyan
C_SSL     = "\033[1;35m"        # Bright Magenta
C_HTTP    = "\033[1;33m"        # Bright Yellow
C_CONN    = "\033[1;32m"        # Bright Green
C_NOTICE  = "\033[1;41;97m"     # White text on Red — reserved for Zeek notice.log + fatal errors
C_FILES   = "\033[1;34m"        # Bright Blue
C_WEIRD   = "\033[1;38;5;208m"  # Bright Orange — weird.log + non-fatal warnings
C_NTP     = "\033[1;38;5;75m"   # Sky Blue
C_SSH     = "\033[1;38;5;120m"  # Mint Green
C_DHCP    = "\033[1;38;5;177m"  # Lavender / Violet
C_SOFTWR  = "\033[1;38;5;153m"  # Ice Blue
C_X509    = "\033[1;38;5;141m"  # Light Purple
C_QUIC    = "\033[1;38;5;215m"  # Light Orange — QUIC/HTTP3
C_DPD     = "\033[1;31m"        # Bright Red
C_KNOWN   = "\033[1;38;5;114m"  # Soft Green
C_OTHER   = "\033[1;37m"        # Bright White
C_DOMAIN  = "\033[1;93m"        # Bold Yellow
C_META    = "\033[96m"          # Cyan — lifecycle/info messages
C_APP     = "\033[1;38;5;117m"  # Light Sky Blue — local process/app badge
C_NEW     = "\033[1;38;5;226m"  # Bright Gold — first-seen domain badge
C_TAG     = "\033[38;5;245m"    # Subtle Gray — category/intent tags
C_RESET   = "\033[0m"

# --- Human-readable Zeek connection states ---
CONN_STATE_LABELS = {
    "S0": "no reply", "S1": "established", "SF": "ok",
    "REJ": "rejected", "S2": "resp→orig", "S3": "orig→resp",
    "RSTO": "reset(orig)", "RSTR": "reset(resp)",
    "RSTOS0": "reset(no resp)", "RSTRH": "reset(half)",
    "SH": "half-open", "SHR": "half-open(r)", "OTH": "midstream",
}

CONN_FAILURE_STATES = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"}

CN_RE = re.compile(r"CN=([^,/]+)")
O_RE = re.compile(r"O=([^,/]+)")

socket.setdefaulttimeout(0.3)

# --- mDNS / Bonjour Service Translation Table ---
MDNS_SERVICE_NAMES = {
    "_companion-link._tcp": "Apple Continuity",
    "_airplay._tcp": "AirPlay",
    "_raop._tcp": "AirPlay Audio",
    "_hap._tcp": "HomeKit",
    "_homekit._tcp": "HomeKit",
    "_googlecast._tcp": "Chromecast",
    "_spotify-connect._tcp": "Spotify Connect",
    "_ipp._tcp": "Printer (IPP)",
    "_ipps._tcp": "Printer (IPPS)",
    "_pdl-datastream._tcp": "Printer",
    "_printer._tcp": "Printer",
    "_scanner._tcp": "Scanner",
    "_smb._tcp": "SMB Share",
    "_afpovertcp._tcp": "AFP Share",
    "_rfb._tcp": "Screen Sharing",
    "_ssh._tcp": "SSH",
    "_sftp-ssh._tcp": "SFTP",
    "_rdlink._tcp": "Apple Remote Dir",
    "_sleep-proxy._udp": "Sleep Proxy",
    "_dns-sd._udp": "Bonjour Browse",
    "_matter._tcp": "Matter SmartHome",
    "_matterc._udp": "Matter Commissioning",
    "_sonos._tcp": "Sonos",
    "_airdrop._tcp": "AirDrop",
    "_usbmuxd._tcp": "iOS USB Mux",
    "_remotepairing._tcp": "Apple Pairing",
}

# --- Traffic Intent / Category Classification ---
DOMAIN_CATEGORIES = {
    # Telemetry, Analytics & Crash Reporting
    "events.data.microsoft.com": "TELEM",
    "vortex.data.microsoft.com": "TELEM",
    "settings-win.data.microsoft.com": "TELEM",
    "telemetry.microsoft.com": "TELEM",
    "clarity.ms": "TELEM",
    "metrics.icloud.com": "TELEM",
    "metrics.apple.com": "TELEM",
    "xp.apple.com": "TELEM",
    "smoot.apple.com": "TELEM",
    "pancake.apple.com": "TELEM",
    "sentry.io": "TELEM",
    "datadoghq.com": "TELEM",
    "browser-intake-datadoghq.com": "TELEM",
    "segment.io": "TELEM",
    "segment.com": "TELEM",
    "amplitude.com": "TELEM",
    "mixpanel.com": "TELEM",
    "posthog.com": "TELEM",
    "hotjar.com": "TELEM",
    "fullstory.com": "TELEM",
    "bugsnag.com": "TELEM",
    "crashlytics.com": "TELEM",
    "app-measurement.com": "TELEM",
    "google-analytics.com": "TELEM",
    "googletagmanager.com": "TELEM",
    "doubleclick.net": "TELEM",
    "googlesyndication.com": "TELEM",
    "googleadservices.com": "TELEM",
    "scorecardresearch.com": "TELEM",
    "newrelic.com": "TELEM",
    "nr-data.net": "TELEM",
    "launchdarkly.com": "TELEM",
    "statsig.com": "TELEM",
    "honeycomb.io": "TELEM",
    # AI Services
    "openai.com": "AI",
    "chatgpt.com": "AI",
    "anthropic.com": "AI",
    "claude.ai": "AI",
    "generativelanguage.googleapis.com": "AI",
    "aistudio.google.com": "AI",
    "copilot-proxy.githubusercontent.com": "AI",
    "githubcopilot.com": "AI",
    "cursor.sh": "AI",
    "cursor.com": "AI",
    "perplexity.ai": "AI",
    "mistral.ai": "AI",
    "cohere.ai": "AI",
    "huggingface.co": "AI",
    "replicate.com": "AI",
    "groq.com": "AI",
    # OS / Sync / Push Infrastructure
    "push.apple.com": "OS/SYNC",
    "icloud.com": "OS/SYNC",
    "icloud-content.com": "OS/SYNC",
    "mzstatic.com": "OS/SYNC",
    "itunes.apple.com": "OS/SYNC",
    "configuration.apple.com": "OS/SYNC",
    "gs.apple.com": "OS/SYNC",
    "ess.apple.com": "OS/SYNC",
    "time.apple.com": "OS/SYNC",
    "captive.apple.com": "OS/SYNC",
    "mesu.apple.com": "OS/SYNC",
    "swscan.apple.com": "OS/SYNC",
    "gdmf.apple.com": "OS/SYNC",
    "connectivity-check.ubuntu.com": "OS/SYNC",
    "ntp.ubuntu.com": "OS/SYNC",
    "windowsupdate.com": "OS/SYNC",
}

# Friendly provider names for cryptic rDNS / CDN domains
CDN_PROVIDER_HINTS = {
    "1e100.net": "Google",
    "googleusercontent.com": "Google Cloud",
    "gvt1.com": "Google CDN",
    "gvt2.com": "Google CDN",
    "akamaiedge.net": "Akamai CDN",
    "akamai.net": "Akamai CDN",
    "akadns.net": "Akamai DNS",
    "akamaitechnologies.com": "Akamai",
    "edgekey.net": "Akamai CDN",
    "edgesuite.net": "Akamai CDN",
    "cloudfront.net": "CloudFront",
    "amazonaws.com": "AWS",
    "fastly.net": "Fastly CDN",
    "cloudflare.com": "Cloudflare",
    "cloudflare-dns.com": "Cloudflare DoH",
    "fbcdn.net": "Meta CDN",
    "azureedge.net": "Azure CDN",
    "trafficmanager.net": "Azure",
}

MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.nz", "org.nz", "govt.nz",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.mx", "co.in", "co.za",
}


def configure_colors(enabled):
    """Null out every color constant when colors are disabled (--no-color,
    NO_COLOR env var, or non-tty stdout) instead of threading a flag through
    every print call."""
    global C_TIME, C_DNS, C_SSL, C_HTTP, C_CONN, C_NOTICE, C_FILES, C_WEIRD
    global C_NTP, C_SSH, C_DHCP, C_SOFTWR, C_X509, C_QUIC, C_DPD, C_KNOWN, C_OTHER
    global C_DOMAIN, C_META, C_APP, C_NEW, C_TAG, C_RESET
    if enabled:
        return
    (C_TIME, C_DNS, C_SSL, C_HTTP, C_CONN, C_NOTICE, C_FILES, C_WEIRD,
     C_NTP, C_SSH, C_DHCP, C_SOFTWR, C_X509, C_QUIC, C_DPD, C_KNOWN, C_OTHER,
     C_DOMAIN, C_META, C_APP, C_NEW, C_TAG, C_RESET) = [""] * 23


def resolve_color_setting(cli_no_color):
    if cli_no_color:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


# --- Log type filtering (--only / --exclude) ---
ONLY_TYPES = None
EXCLUDE_TYPES = set()
VERBOSE_MODE = False


def apply_filters(only_arg, exclude_arg, verbose=False):
    global ONLY_TYPES, EXCLUDE_TYPES, VERBOSE_MODE
    VERBOSE_MODE = bool(verbose)
    if only_arg:
        ONLY_TYPES = {t.strip().lower() for t in only_arg.split(",") if t.strip()}
    if exclude_arg:
        EXCLUDE_TYPES = {t.strip().lower() for t in exclude_arg.split(",") if t.strip()}


def type_allowed(log_type):
    lt = log_type.lower()
    if ONLY_TYPES is not None and lt not in ONLY_TYPES:
        return False
    if lt in EXCLUDE_TYPES:
        return False
    return True


def is_explicitly_requested(log_type):
    """True when the user specifically asked for this log_type via --only or --verbose."""
    if VERBOSE_MODE:
        return True
    if ONLY_TYPES is not None and log_type.lower() in ONLY_TYPES:
        return True
    return False


# --- Display filters (--match / --min-bytes / --min-duration / --hide-lan / --only-new) ---
MATCH_TEXT = None    # case-insensitive substring every printed line must contain
MIN_BYTES = 0        # CONN rows below this total byte count are hidden
MIN_DURATION = 0.0   # CONN rows shorter than this many seconds are hidden
HIDE_LAN = False     # suppress unnamed local-network traffic
ONLY_NEW = False     # only display first-seen domains, alerts, and anomalies
PROCS_ENABLED = True # resolve local sockets to process names

# --- Pause / Bookmark interactive state ---
PAUSED = False
PAUSED_BUFFER = deque(maxlen=500)
PAUSED_DROPPED = 0
PAUSE_LOCK = threading.Lock()

MARK_COUNT = 0
MARK_TIME = 0.0
MARK_EVENTS = 0
MARK_BYTES_IN = 0
MARK_BYTES_OUT = 0

# --- Local IP addresses (for self-IP suppression & directionality) ---
LOCAL_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}
LOCAL_IPS_LOCK = threading.Lock()

# --- Watchlist (--watchlist) ---
WATCHLIST_DOMAINS = set()
WATCHLIST_IPS = set()
WATCHLIST_CIDRS = []
WATCHLIST_LOADED = False

# --- Alert-on pattern (--alert-on) ---
ALERT_PATTERN = None  # compiled regex, applied to every printed line

# --- Periodic stats (--stats-interval) ---
STATS_INTERVAL = 0  # seconds between summary lines, 0 = disabled

# --- Session tracking (for exit & live summary) ---
SESSION_START = 0.0
SESSION_STATS = defaultdict(int)       # log_type -> event count
SESSION_CATEGORIES = defaultdict(int)  # category -> event count
SESSION_APPS = defaultdict(int)        # local process -> connection/event count
SESSION_BYTES_IN = 0
SESSION_BYTES_OUT = 0
SESSION_STATS_LOCK = threading.Lock()
UNIQUE_REMOTE_HOSTS = set()
UNIQUE_HOSTS_LOCK = threading.Lock()
TOP_DESTINATIONS = defaultdict(lambda: {"conns": 0, "bytes": 0, "up": 0, "down": 0})
TOP_DEST_LOCK = threading.Lock()
HEAVY_UPLOADS = []                     # list of (domain, orig_bytes, ts_str)

# --- Novelty tracking (first-seen base domains) ---
SEEN_BASE_DOMAINS = set()
SESSION_NEW_DOMAINS = []
NOVELTY_LOCK = threading.Lock()
KNOWN_DOMAINS_FILE = ".wirewatch-known.json"

# --- Beaconing detection ---
BEACON_TIMESTAMPS = defaultdict(list)   # (src, dst, port) -> [wall-clock ts]
BEACON_LOCK = threading.Lock()
BEACON_ALERTED = set()                  # keys already flagged this session
BEACON_MIN_CONNS = 10                   # minimum sample size before checking
BEACON_MAX_COV = 0.15                   # coefficient-of-variation threshold


def apply_display_filters(args):
    global MATCH_TEXT, MIN_BYTES, MIN_DURATION, HIDE_LAN, ONLY_NEW, PROCS_ENABLED
    global ALERT_PATTERN, STATS_INTERVAL
    if args.match:
        MATCH_TEXT = args.match
    try:
        MIN_BYTES = int(args.min_bytes)
    except (TypeError, ValueError):
        MIN_BYTES = 0
    try:
        MIN_DURATION = float(args.min_duration)
    except (TypeError, ValueError):
        MIN_DURATION = 0.0
    HIDE_LAN = bool(args.hide_lan)
    ONLY_NEW = bool(getattr(args, "only_new", False))
    PROCS_ENABLED = not bool(getattr(args, "no_procs", False)) and not bool(args.pcap)
    if getattr(args, "alert_on", None):
        try:
            ALERT_PATTERN = re.compile(args.alert_on, re.IGNORECASE)
        except re.error as e:
            print(f"{C_NOTICE}[!] Invalid --alert-on pattern: {e}{C_RESET}")
    try:
        STATS_INTERVAL = int(getattr(args, "stats_interval", 0) or 0)
    except (TypeError, ValueError):
        STATS_INTERVAL = 0


# --- Domain helpers, classification & novelty ---

def base_domain(domain):
    """Extract the registrable base domain (eTLD+1 approximation), e.g.:
    'api.github.com' -> 'github.com', 'bbc.co.uk' -> 'bbc.co.uk'."""
    if not domain or domain in ("-", "LAN/Local") or ":" in domain:
        return ""
    d = domain.lower().strip(".")
    if d.startswith("cert:"):
        d = d[5:]
    if d.endswith(".local") or d.endswith(".arpa") or d.endswith(".lan"):
        return d
    try:
        ipaddress.ip_address(d)
        return d
    except ValueError:
        pass
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def smart_truncate_domain(domain, max_len=30):
    """Truncate a long domain while preserving its root/base domain on the right.
    Example: 'ec2-54-239-28-85.compute-1.amazonaws.com' (40 chars)
             -> 'ec2-54-239…amazonaws.com' (24 chars)."""
    if not domain:
        return "-"
    if len(domain) <= max_len:
        return domain
    b = base_domain(domain)
    if b and len(b) < max_len - 4 and domain.endswith(b):
        prefix_budget = max_len - len(b) - 2
        if prefix_budget >= 4:
            return f"{domain[:prefix_budget]}…{b}"
    # Fallback: keep start and end
    half = (max_len - 1) // 2
    return f"{domain[:half]}…{domain[-(max_len - 1 - half):]}"


def classify_domain(domain):
    """Return (category_tag, provider_hint) for a domain name."""
    if not domain or domain in ("-", "LAN/Local"):
        return None, None
    d = domain.lower().strip(".")
    if d.startswith("cert:"):
        d = d[5:]
    # Check exact or suffix match against DOMAIN_CATEGORIES
    for suffix, cat in DOMAIN_CATEGORIES.items():
        if d == suffix or d.endswith("." + suffix):
            return cat, None
    # Heuristic telemetry keywords in subdomain
    first_label = d.split(".")[0]
    if first_label in ("telemetry", "metrics", "analytics", "collector", "beacon", "crash", "sentry"):
        return "TELEM", None
    # Check CDN / Cloud provider hints
    for suffix, provider in CDN_PROVIDER_HINTS.items():
        if d == suffix or d.endswith("." + suffix):
            return None, provider
    return None, None


def decode_mdns_service(query):
    """Translate mDNS/Bonjour service queries into human-friendly labels."""
    if not query or query == "-":
        return None
    q = query.lower()
    for pattern, label in MDNS_SERVICE_NAMES.items():
        if pattern in q:
            return label
    if q.endswith("._tcp.local") or q.endswith("._udp.local"):
        # Extract generic service name
        parts = [p for p in q.split(".") if p.startswith("_") and p not in ("_tcp", "_udp", "_sub")]
        if parts:
            return f"Bonjour:{parts[0].lstrip('_')}"
    return None


def load_known_domains(work_dir):
    path = os.path.join(work_dir, KNOWN_DOMAINS_FILE)
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            with NOVELTY_LOCK:
                SEEN_BASE_DOMAINS.update(str(x).lower() for x in data if x)
    except Exception:
        pass


def save_known_domains(work_dir):
    path = os.path.join(work_dir, KNOWN_DOMAINS_FILE)
    try:
        with NOVELTY_LOCK:
            # Cap persisted domains to 10,000 entries
            items = sorted(SEEN_BASE_DOMAINS)[-10000:]
        if not items:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(items, f)
    except Exception:
        pass


def check_novel_domain(domain):
    """True the very first time a registrable base domain is seen."""
    b = base_domain(domain)
    if not b or b.endswith(".local") or b.endswith(".arpa") or b.endswith(".lan"):
        return False
    try:
        ip = ipaddress.ip_address(b)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
    except ValueError:
        pass
    with NOVELTY_LOCK:
        if b in SEEN_BASE_DOMAINS:
            return False
        SEEN_BASE_DOMAINS.add(b)
        SESSION_NEW_DOMAINS.append(domain)
        return True


# --- Local process / application attribution ---
PORT_PROC_CACHE = OrderedDict()  # int(local_port) -> str(app_name)
PEER_PROC_CACHE = OrderedDict()  # str(remote_ip) -> str(app_name)
PORT_PROC_MAX = 10000
PORT_PROC_LOCK = threading.Lock()
_LAST_PROC_SCAN = 0.0
_PROC_SCAN_LOCK = threading.Lock()

# macOS `netstat -anv` process:pid regex
_MACOS_NETSTAT_RE = re.compile(
    r"\s+\d+\s+\d+\s+\d+\s+\d+\s+([^\s].*?):(\d+)\s+[0-9a-fA-F]{4,8}\s+"
)
# Linux `ss -tupn` process regex
_LINUX_SS_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')


def _clean_proc_name(name):
    if not name:
        return ""
    for suffix in (" Helper (Renderer)", " Helper (GPU)", " Helper (Plugin)",
                   " Helper", " He", " Help", ".app"):
        if name.endswith(suffix) and len(name) > len(suffix):
            name = name[:-len(suffix)].strip()
    aliases = {
        "Google Chrome": "Chrome",
        "Brave Browser": "Brave",
        "Opera": "Opera",
        "com.apple.WebKit.Networking": "Safari",
        "com.apple.WebKit.WebContent": "Safari",
        "com.apple.Safari.SafeBrowsing": "Safari",
        "identityservicesd": "iMessage",
        "identityservices": "iMessage",
        "nsurlsessiond": "macOS-Sync",
        "apsd": "ApplePush",
        "cloudd": "iCloud",
        "mDNSResponder": "mDNS",
        "rapportd": "Continuity",
        "sharingd": "AirDrop/Share",
        "wifianalyticsd": "WiFi-Diag",
        "Code Helper": "VSCode",
        "language_server": "LangServer",
        "agy": "Antigravity",
    }
    clean = aliases.get(name, name)
    return clean[:13]


def _scan_local_processes(min_interval=0.05):
    """Populate PORT_PROC_CACHE and PEER_PROC_CACHE from OS socket tables."""
    global _LAST_PROC_SCAN
    if not PROCS_ENABLED:
        return
    now = time.time()
    with _PROC_SCAN_LOCK:
        if now - _LAST_PROC_SCAN < min_interval:
            return
        _LAST_PROC_SCAN = now

    system = platform.system()
    found_ports = {}
    found_peers = {}
    try:
        if system == "Darwin":
            r = subprocess.run(["netstat", "-anv"], capture_output=True, text=True, timeout=1.5)
            for line in r.stdout.splitlines():
                if not line.startswith(("tcp", "udp")):
                    continue
                parts = line.split()
                if len(parts) < 6:
                    continue
                local_addr = parts[3]
                if "." not in local_addr:
                    continue
                port_str = local_addr.rsplit(".", 1)[1]
                if not port_str.isdigit():
                    continue
                m = _MACOS_NETSTAT_RE.search(line)
                if m:
                    proc_name = _clean_proc_name(m.group(1).strip())
                    if proc_name:
                        found_ports[int(port_str)] = proc_name
                        foreign_addr = parts[4]
                        if "." in foreign_addr and foreign_addr != "*.*":
                            peer_ip = foreign_addr.rsplit(".", 1)[0]
                            if peer_ip and not peer_ip.startswith(("127.", "0.")):
                                found_peers[peer_ip] = proc_name
        elif system == "Linux":
            r = subprocess.run(["ss", "-tupn"], capture_output=True, text=True, timeout=1.5)
            for line in r.stdout.splitlines():
                m = _LINUX_SS_RE.search(line)
                if not m:
                    continue
                parts = line.split()
                if len(parts) < 6:
                    continue
                local_addr = parts[4]
                if ":" not in local_addr:
                    continue
                port_str = local_addr.rsplit(":", 1)[1]
                if port_str.isdigit():
                    proc_name = _clean_proc_name(m.group(1).strip())
                    if proc_name:
                        found_ports[int(port_str)] = proc_name
                        foreign_addr = parts[5]
                        if ":" in foreign_addr:
                            peer_ip = foreign_addr.rsplit(":", 1)[0].strip("[]")
                            if peer_ip and peer_ip not in ("*", "0.0.0.0", "127.0.0.1", "::"):
                                found_peers[peer_ip] = proc_name
    except Exception:
        pass

    if found_ports or found_peers:
        with PORT_PROC_LOCK:
            for port, app in found_ports.items():
                PORT_PROC_CACHE[port] = app
                PORT_PROC_CACHE.move_to_end(port)
            while len(PORT_PROC_CACHE) > PORT_PROC_MAX:
                PORT_PROC_CACHE.popitem(last=False)
            for peer_ip, app in found_peers.items():
                PEER_PROC_CACHE[peer_ip] = app
                PEER_PROC_CACHE.move_to_end(peer_ip)
            while len(PEER_PROC_CACHE) > PORT_PROC_MAX:
                PEER_PROC_CACHE.popitem(last=False)


def proc_scanner_worker():
    while True:
        _scan_local_processes(min_interval=0.2)
        time.sleep(0.4)


def lookup_local_app(orig_h, orig_p, resp_h="", resp_p="", uid=None):
    """Best-effort lookup of the local process that owns a connection."""
    if uid:
        meta = uid_meta_get(uid)
        if meta and meta.get("app"):
            return meta["app"]
    if not PROCS_ENABLED:
        return ""
    port_candidates = []
    if is_local_self(orig_h) and str(orig_p).isdigit():
        port_candidates.append(int(orig_p))
    elif is_local_self(resp_h) and str(resp_p).isdigit():
        port_candidates.append(int(resp_p))
    if not port_candidates:
        return ""
    with PORT_PROC_LOCK:
        for p in port_candidates:
            app = PORT_PROC_CACHE.get(p)
            if app:
                PORT_PROC_CACHE.move_to_end(p)
                if uid:
                    uid_meta_update(uid, app=app)
                return app
    # Skip expensive on-demand scan for ephemeral UDP :53 queries (already closed by the time Zeek flushes)
    if str(resp_p) != "53":
        _scan_local_processes(min_interval=0.03)
        with PORT_PROC_LOCK:
            for p in port_candidates:
                app = PORT_PROC_CACHE.get(p)
                if app:
                    if uid:
                        uid_meta_update(uid, app=app)
                    return app
            if resp_h and resp_h != "-":
                app = PEER_PROC_CACHE.get(resp_h)
                if app:
                    if uid:
                        uid_meta_update(uid, app=app)
                    return app
    return ""


# --- Local IP & Endpoint formatting ---

def is_local_self(ip_str):
    if not ip_str or ip_str == "-":
        return False
    with LOCAL_IPS_LOCK:
        if ip_str in LOCAL_IPS:
            return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_private_or_local(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return True
        if isinstance(ip, ipaddress.IPv4Address):
            # Strict RFC 1918 + CGNAT (100.64/10) check so TEST-NET IPs aren't mislabeled as LAN
            o1, o2 = ip.packed[0], ip.packed[1]
            return (
                o1 == 10
                or (o1 == 172 and 16 <= o2 <= 31)
                or (o1 == 192 and o2 == 168)
                or (o1 == 100 and 64 <= o2 <= 127)
            )
        return ip.is_private
    except ValueError:
        return False


def is_unnamed_local(ip_str):
    """True for private/loopback/link-local/multicast IPs that have no cached
    name (no DNS/SNI/DHCP hostname seen for them yet)."""
    if not is_private_or_local(ip_str):
        return False
    return cache_get(ip_str) is None


def shorten_ip(ip_str, max_len=17):
    """Compress IPv6 addresses so they never blow up column alignment."""
    if not ip_str or ip_str == "-":
        return "-"
    if ":" not in ip_str:
        return ip_str
    try:
        comp = ipaddress.ip_address(ip_str).compressed
    except ValueError:
        comp = ip_str
    if len(comp) <= max_len:
        return comp
    parts = comp.split(":")
    if len(parts) >= 4:
        short = f"{parts[0]}:{parts[1]}..{parts[-2]}:{parts[-1]}"
        if len(short) <= max_len:
            return short
    return f"{comp[:max_len - 2]}..{comp[-1:]}"


def format_endpoint(ip_str, port=""):
    s = shorten_ip(ip_str, max_len=17)
    if not port or port == "-":
        return s
    if ":" in s:
        return f"[{s}]:{port}"
    return f"{s}:{port}"


def format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=None, proto_hint=""):
    """Format a compact 19-char WHO/DIRECTION column:
    - Outbound from this machine: 'Brave    ↗ :443    ' or 'OUT      ↗ tcp/8443'
    - Inbound to this machine:    'IN       ↙ tcp/22  '
    - Peer-to-peer on LAN:        '10.1.2.5 → :443    '
    """
    app = lookup_local_app(orig_h, orig_p, resp_h, resp_p, uid=uid)
    if app:
        record_app(app)

    port_tag = f":{resp_p}" if resp_p and resp_p != "-" else ""
    if proto_hint:
        port_tag = f"{proto_hint}/{resp_p}" if resp_p and resp_p != "-" else proto_hint
    port_tag = port_tag[:9]

    if is_local_self(orig_h):
        who = f"{C_APP}{app[:8]:<8}{C_RESET}" if app else f"{C_TIME}{'OUT':<8}{C_RESET}"
        return f"{who} ↗ {port_tag:<8}"
    elif is_local_self(resp_h) and not is_local_self(orig_h):
        who = f"{C_WEIRD}{'IN':<8}{C_RESET}" if not app else f"{C_WEIRD}IN:{app[:5]:<5}{C_RESET}"
        return f"{who} ↙ {port_tag:<8}"
    else:
        src = shorten_ip(orig_h, 8)
        who = f"{C_APP}{app[:8]:<8}{C_RESET}" if app else f"{src:<8}"
        return f"{who} → {port_tag:<8}"


def select_peer_ip(orig_h, resp_h):
    """Return the remote/interesting peer IP for a flow (orig_h if inbound to us, else resp_h)."""
    if is_local_self(resp_h) and not is_local_self(orig_h):
        return orig_h
    return resp_h


def format_target_label(domain, peer_ip):
    """Choose the best 26-char display string for the TARGET column:
    - If a real domain is known, display it.
    - If it's an unnamed LAN address, display '<ip> (LAN)'.
    - If it's an unresolved public IP, display the IP directly instead of '-'."""
    if domain and domain not in ("-", "LAN/Local"):
        return domain
    if peer_ip and peer_ip != "-":
        short_ip = shorten_ip(peer_ip, 19)
        if domain == "LAN/Local" or is_private_or_local(peer_ip):
            return f"{short_ip} (LAN)"
        return short_ip
    return domain or "-"


# --- Watchlist loading & matching ---

def load_watchlist(filepath):
    """Load domains, IPs, and CIDRs from a newline-delimited text file."""
    global WATCHLIST_LOADED
    if not filepath:
        return
    try:
        with open(filepath, "r") as f:
            for raw in f:
                entry = raw.strip()
                if not entry or entry.startswith("#"):
                    continue
                if "/" in entry:
                    try:
                        WATCHLIST_CIDRS.append(ipaddress.ip_network(entry, strict=False))
                        continue
                    except ValueError:
                        pass
                try:
                    ipaddress.ip_address(entry)
                    WATCHLIST_IPS.add(entry)
                    continue
                except ValueError:
                    pass
                WATCHLIST_DOMAINS.add(entry.lower().lstrip("*."))
        WATCHLIST_LOADED = True
        total = len(WATCHLIST_DOMAINS) + len(WATCHLIST_IPS) + len(WATCHLIST_CIDRS)
        safe_print(f"{C_META}[*] Watchlist loaded: {total} entries from {filepath}{C_RESET}")
    except OSError as e:
        print(f"{C_NOTICE}[!] Could not load watchlist: {e}{C_RESET}")


def check_watchlist(value):
    """True if value (an IP or domain string) matches any watchlist entry."""
    if not WATCHLIST_LOADED or not value or value == "-":
        return False
    try:
        ip = ipaddress.ip_address(value)
        if value in WATCHLIST_IPS:
            return True
        for net in WATCHLIST_CIDRS:
            if ip in net:
                return True
    except ValueError:
        pass
    domain = value.lower()
    for wd in WATCHLIST_DOMAINS:
        if domain == wd or domain.endswith("." + wd):
            return True
    return False


# --- Session statistics helpers ---

def record_stat(log_type, category=None):
    global MARK_EVENTS
    with SESSION_STATS_LOCK:
        SESSION_STATS[log_type] += 1
        MARK_EVENTS += 1
        if category:
            SESSION_CATEGORIES[category] += 1


def record_app(app_name):
    if not app_name:
        return
    with SESSION_STATS_LOCK:
        SESSION_APPS[app_name] += 1


def record_bytes(orig, resp):
    global SESSION_BYTES_OUT, SESSION_BYTES_IN, MARK_BYTES_OUT, MARK_BYTES_IN
    with SESSION_STATS_LOCK:
        SESSION_BYTES_OUT += orig
        SESSION_BYTES_IN += resp
        MARK_BYTES_OUT += orig
        MARK_BYTES_IN += resp


def record_remote_host(ip_str):
    if not ip_str or ip_str == "-":
        return
    if not is_private_or_local(ip_str):
        with UNIQUE_HOSTS_LOCK:
            UNIQUE_REMOTE_HOSTS.add(ip_str)


def record_destination(domain, orig_bytes, resp_bytes):
    if not domain or domain in ("-", "LAN/Local"):
        return
    total = orig_bytes + resp_bytes
    with TOP_DEST_LOCK:
        d = TOP_DESTINATIONS[domain]
        d["conns"] += 1
        d["bytes"] += total
        d["up"] += orig_bytes
        d["down"] += resp_bytes


# --- Beaconing detection ---

def check_beaconing(src, dst, port, uid=None):
    """Track connection timing and flag suspiciously regular intervals.
    Only alerts once per (src, dst, port) tuple per session."""
    key = (src, dst, port)
    now = time.time()
    with BEACON_LOCK:
        ts_list = BEACON_TIMESTAMPS[key]
        ts_list.append(now)
        if len(ts_list) > 60:
            BEACON_TIMESTAMPS[key] = ts_list[-60:]
            ts_list = BEACON_TIMESTAMPS[key]
        if len(ts_list) < BEACON_MIN_CONNS or key in BEACON_ALERTED:
            return
    intervals = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
    if not intervals:
        return
    mean = sum(intervals) / len(intervals)
    if mean < 1.0:
        return
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    cov = std_dev / mean if mean > 0 else float("inf")
    if cov < BEACON_MAX_COV:
        with BEACON_LOCK:
            if key in BEACON_ALERTED:
                return
            BEACON_ALERTED.add(key)
        domain = resolve_target(dst, uid=uid)
        ts_str = time.strftime("%H:%M:%S", time.localtime(now))
        window = int(ts_list[-1] - ts_list[0])
        safe_print(
            f"{C_TIME}{ts_str}{C_RESET} {C_NOTICE}[BEACON? ]{C_RESET} "
            f"{shorten_ip(src)} → {format_endpoint(dst, port)} ({C_DOMAIN}{domain}{C_RESET}) — "
            f"{len(ts_list)} conns in {window}s, interval ~{mean:.0f}s ±{std_dev:.0f}s"
        )


# --- Per-UID and Provenance-Aware DNS/SNI Resolution Caches ---
DNS_CACHE = OrderedDict()       # ip -> {"domain": str, "source": str}
DNS_CACHE_MAX = 20000
DNS_SEEN_IPS = set()            # IPs explicitly returned in dns.log answers
DNS_SEEN_DOMAINS = set()        # Domains explicitly queried in dns.log
UID_CACHE = OrderedDict()       # uid -> {"domain": str, "app": str, "source": str, ...}
UID_CACHE_MAX = 20000
CACHE_LOCK = threading.Lock()

RDNS_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="rdns")
RDNS_INFLIGHT = set()
RDNS_INFLIGHT_LOCK = threading.Lock()

PRINT_LOCK = threading.Lock()
ACTIVE_THREADS = set()
ACTIVE_THREADS_LOCK = threading.Lock()


def uid_meta_update(uid, **kwargs):
    if not uid or uid == "-":
        return
    with CACHE_LOCK:
        entry = UID_CACHE.get(uid)
        if entry is None:
            entry = {}
            UID_CACHE[uid] = entry
        else:
            UID_CACHE.move_to_end(uid)
        for k, v in kwargs.items():
            if v and v != "-":
                entry[k] = v
        while len(UID_CACHE) > UID_CACHE_MAX:
            UID_CACHE.popitem(last=False)


def uid_meta_get(uid):
    if not uid or uid == "-":
        return None
    with CACHE_LOCK:
        entry = UID_CACHE.get(uid)
        if entry is not None:
            UID_CACHE.move_to_end(uid)
            return dict(entry)
        return None


def cache_put(ip, domain, source="dns"):
    """Store an IP -> domain mapping with provenance ('dns', 'sni', 'http', 'dhcp', 'rdns').
    Never allow a generic 'rdns' entry to overwrite an authoritative 'dns'/'sni'/'http'/'dhcp' name."""
    if not ip or ip == "-" or not domain or domain == "-":
        return
    with CACHE_LOCK:
        existing = DNS_CACHE.get(ip)
        if existing is not None:
            if source == "rdns" and existing.get("source") in ("dns", "sni", "http", "dhcp"):
                return
            DNS_CACHE.move_to_end(ip)
        DNS_CACHE[ip] = {"domain": domain, "source": source}
        if source == "dns":
            DNS_SEEN_IPS.add(ip)
            DNS_SEEN_DOMAINS.add(domain.lower())
        while len(DNS_CACHE) > DNS_CACHE_MAX:
            DNS_CACHE.popitem(last=False)


def cache_get(ip, include_rdns=True):
    with CACHE_LOCK:
        entry = DNS_CACHE.get(ip)
        if entry is not None:
            if not include_rdns and entry.get("source") == "rdns":
                return None
            DNS_CACHE.move_to_end(ip)
            return entry["domain"]
        return None


def cache_get_entry(ip):
    with CACHE_LOCK:
        entry = DNS_CACHE.get(ip)
        if entry is not None:
            DNS_CACHE.move_to_end(ip)
            return dict(entry)
        return None


def note_dns_query(query):
    if query and query != "-":
        with CACHE_LOCK:
            DNS_SEEN_DOMAINS.add(query.lower())


def was_dns_resolved(ip, domain=None):
    """True if this IP or domain was preceded by a plaintext DNS query/answer.
    When a specific domain (e.g. SNI) is known, require that domain (or its
    base domain) to have been queried via DNS rather than just sharing an anycast IP."""
    with CACHE_LOCK:
        if domain and domain not in ("-", "LAN/Local") and not domain.startswith("cert:"):
            d = domain.lower()
            if d in DNS_SEEN_DOMAINS:
                return True
            b = base_domain(d)
            if b and any(q == b or q.endswith("." + b) for q in DNS_SEEN_DOMAINS):
                return True
            return False
        if ip and ip in DNS_SEEN_IPS:
            return True
        return False


# Leaf-certificate metadata keyed by cert fingerprint (bounded, LRU).
X509_CN_BY_FP = OrderedDict()
X509_META_BY_FP = OrderedDict()
X509_CN_MAX = 5000


def x509_cn_put(fp, cn, meta=None):
    if not fp or fp == "-":
        return
    with CACHE_LOCK:
        if cn and cn != "-":
            if fp in X509_CN_BY_FP:
                X509_CN_BY_FP.move_to_end(fp)
            X509_CN_BY_FP[fp] = cn
            while len(X509_CN_BY_FP) > X509_CN_MAX:
                X509_CN_BY_FP.popitem(last=False)
        if meta:
            if fp in X509_META_BY_FP:
                X509_META_BY_FP.move_to_end(fp)
            X509_META_BY_FP[fp] = meta
            while len(X509_META_BY_FP) > X509_CN_MAX:
                X509_META_BY_FP.popitem(last=False)


def x509_cn_get(fp):
    with CACHE_LOCK:
        cn = X509_CN_BY_FP.get(fp)
        if cn is not None:
            X509_CN_BY_FP.move_to_end(fp)
        return cn


def x509_meta_get(fp):
    with CACHE_LOCK:
        m = X509_META_BY_FP.get(fp)
        if m is not None:
            X509_META_BY_FP.move_to_end(fp)
            return dict(m)
        return None


@lru_cache(maxsize=4096)
def rdns_lookup(ip_str):
    """Blocking reverse DNS lookup. Only ever called from the background
    executor so it never stalls the print/parse path."""
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return "-"


def _schedule_rdns(ip_str):
    with RDNS_INFLIGHT_LOCK:
        if ip_str in RDNS_INFLIGHT:
            return
        RDNS_INFLIGHT.add(ip_str)

    def _work():
        try:
            name = rdns_lookup(ip_str)
            if name != "-":
                cache_put(ip_str, name, source="rdns")
        finally:
            with RDNS_INFLIGHT_LOCK:
                RDNS_INFLIGHT.discard(ip_str)

    RDNS_EXECUTOR.submit(_work)


def resolve_target(ip_str, uid=None):
    """Non-blocking:
    1. Check per-connection UID_CACHE first (prevents multi-tenant CDN IP collisions).
    2. Check DNS/SNI/DHCP cache next.
    3. Check fast LAN/Private range.
    4. Schedule background rDNS lookup for next time."""
    if uid:
        meta = uid_meta_get(uid)
        if meta and meta.get("domain"):
            return meta["domain"]

    if not ip_str or ip_str == "-":
        return "-"

    cached = cache_get(ip_str)
    if cached:
        return cached

    if is_private_or_local(ip_str):
        return "LAN/Local"

    _schedule_rdns(ip_str)
    return "-"


def format_domain_badges(domain, ip_str="", uid=None, allow_novel=True):
    """Build trailing insight badges for a target domain/IP:
    - ★ NEW (first time base domain is seen)
    - [AI] / [TELEM] / [OS/SYNC] (intent classification)
    - [Google] / [Cloudflare] / [AWS] (when domain is a cryptic rDNS hostname)
    - [DIRECT-IP] (when talking to a public IP with no DNS or SNI)"""
    badges = []
    if allow_novel and domain and domain not in ("-", "LAN/Local") and check_novel_domain(domain):
        badges.append(f"{C_NEW}★ NEW{C_RESET}")

    cat, provider = classify_domain(domain)
    if cat:
        cat_color = C_WEIRD if cat == "TELEM" else (C_SSL if cat == "AI" else C_TAG)
        badges.append(f"{cat_color}[{cat}]{C_RESET}")
    elif provider:
        entry = cache_get_entry(ip_str) if ip_str else None
        if entry and entry.get("source") == "rdns":
            badges.append(f"{C_TAG}[{provider}]{C_RESET}")

    return (" " + " ".join(badges)) if badges else "", cat, bool(badges and "★ NEW" in badges[0])


def get_time(ts_raw):
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts_raw)))
    except Exception:
        return "--:--:--"


def format_bytes(byte_str):
    try:
        b = float(byte_str)
        if b < 1024:
            return f"{b:.0f}B"
        if b < 1024 ** 2:
            return f"{b / 1024:.1f}KB"
        if b < 1024 ** 3:
            return f"{b / (1024 ** 2):.1f}MB"
        return f"{b / (1024 ** 3):.2f}GB"
    except Exception:
        return "-B"


ANSI_RE = re.compile(r"\033\[[0-9;]*m")
CONTROL_RE = re.compile(r"[\x00-\x1a\x1c-\x1f\x7f]")


def _visible_len(msg):
    return len(ANSI_RE.sub("", msg))


def _pad_visible(styled_str, width):
    """Pad a styled string (which may contain ANSI escapes) to `width` visible chars."""
    vis = _visible_len(styled_str)
    if vis >= width:
        return styled_str
    return styled_str + (" " * (width - vis))


def _clip_to_width(msg, max_cols):
    """Hard-cap a styled line to max_cols visible cells."""
    budget = max_cols - 1
    if _visible_len(msg) <= budget:
        return msg
    out, width, pos = [], 0, 0
    for m in ANSI_RE.finditer(msg):
        seg = msg[pos:m.start()]
        if width + len(seg) > budget:
            out.append(seg[:budget - width])
            break
        out.append(seg)
        width += len(seg)
        out.append(m.group())
        pos = m.end()
    else:
        out.append(msg[pos:pos + budget - width])
    return "".join(out) + C_RESET + "…"


def safe_print(msg, bypass_pause=False):
    global PAUSED_DROPPED
    msg = CONTROL_RE.sub(" ", msg)
    if not bypass_pause:
        with PAUSE_LOCK:
            if PAUSED:
                if len(PAUSED_BUFFER) == PAUSED_BUFFER.maxlen:
                    PAUSED_DROPPED += 1
                PAUSED_BUFFER.append(msg)
                return
    if sys.stdout.isatty():
        cols = shutil.get_terminal_size((120, 24)).columns - 1
        out_line = _clip_to_width(msg, cols)
    else:
        out_line = msg
    with PRINT_LOCK:
        print(out_line)
        sys.stdout.flush()


def format_row_line(ts, badge_color, badge_text, flow_col, target_domain, details_str, peer_ip=""):
    """Render a uniform aligned row across all protocol parsers:
    TIME (8) | BADGE (8) | FLOW/APP (19) | TARGET DOMAIN/IP (26) | DETAILS"""
    badge = f"{badge_color}[{badge_text:<6}]{C_RESET}"
    flow_padded = _pad_visible(flow_col, 19)
    label = format_target_label(target_domain, peer_ip)
    dom_short = smart_truncate_domain(label, 26)
    is_real_domain = bool(target_domain and target_domain not in ("-", "LAN/Local"))
    dom_color = C_DOMAIN if is_real_domain else C_TIME
    dom_styled = f"{dom_color}{dom_short:<26}{C_RESET}"
    return f"{C_TIME}{ts}{C_RESET} {badge} {flow_padded} {dom_styled} {details_str}"


def emit(log_type, msg, category=None, is_important=False):
    """Filtered print for parsed log rows: --only/--exclude/--only-new gate visibility
    here so every row still reaches its parser and enrichment caches keep filling."""
    record_stat(log_type, category=category)
    plain = ANSI_RE.sub("", msg)
    if MATCH_TEXT is not None and MATCH_TEXT.lower() not in plain.lower():
        return
    if not type_allowed(log_type):
        return

    # Watchlist / alert-on prefixing
    prefix = ""
    if WATCHLIST_LOADED:
        for token in plain.split():
            cleaned = token.strip("()[]{},:/<>")
            if check_watchlist(cleaned):
                prefix = f"{C_NOTICE} [WATCH] {C_RESET} "
                is_important = True
                break
    if not prefix and ALERT_PATTERN and ALERT_PATTERN.search(plain):
        prefix = f"{C_DPD}[!]{C_RESET} "
        is_important = True

    if ONLY_NEW and not is_important and "★ NEW" not in plain and log_type not in ("notice", "weird", "dpd"):
        return

    safe_print(prefix + msg)


# --- Dropped/malformed line tracking ---
DROPPED_COUNTS = defaultdict(int)
DROPPED_LOCK = threading.Lock()
_dropped_warned = set()


def note_dropped(log_type):
    first = False
    with DROPPED_LOCK:
        DROPPED_COUNTS[log_type] += 1
        if log_type not in _dropped_warned:
            _dropped_warned.add(log_type)
            first = True
    if first:
        safe_print(f"{C_WEIRD}[!] {log_type}.log: some lines don't match the header field "
                   f"count and are being skipped.{C_RESET}")


def print_dropped_summary():
    with DROPPED_LOCK:
        items = {k: v for k, v in DROPPED_COUNTS.items() if v}
    if items:
        detail = ", ".join(f"{k}={v}" for k, v in items.items())
        safe_print(f"{C_META}[i] Skipped malformed lines this session: {detail}{C_RESET}")


# --- Specialized Log Parsers ---

DNS_DEDUP_WINDOW = 15.0
_dns_state = {}
_dns_lock = threading.Lock()

TLS_DEDUP_WINDOW = 15.0
_tls_state = {}
_tls_lock = threading.Lock()


def _clean_answers(answers):
    """Split the answer vector into (ips, cnames), dropping mDNS TXT blobs and duplicates."""
    seen = set()
    ips, cnames = [], []
    for ans in answers.split(","):
        ans = ans.strip()
        if not ans or " " in ans or ("." not in ans and ":" not in ans) or ans in seen:
            continue
        seen.add(ans)
        try:
            ipaddress.ip_address(ans)
            ips.append(ans)
        except ValueError:
            cnames.append(ans)
    return ips, cnames


def parse_dns(row, emit_enabled=True):
    query = row.get("query", "-")
    qtype = row.get("qtype_name", "-")
    answers = row.get("answers", "-")
    rcode = row.get("rcode_name", "-")
    rtt = row.get("rtt", "-")
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "53")
    uid = row.get("uid", "-")

    note_dns_query(query)

    ips, cnames = _clean_answers(answers) if answers != "-" else ([], [])
    if ips and query != "-":
        for ip_ans in ips:
            cache_put(ip_ans, query, source="dns")

    if not emit_enabled:
        return

    if HIDE_LAN and query != "-" and (query.lower().endswith(".local") or resp_p == "5353"):
        return

    # Fold companion browser HTTPS/SVCB (type 64/65) queries that return no IP
    # (only CNAME aliases or service hints alongside the real A/AAAA query)
    if qtype in ("HTTPS", "SVCB") and not ips and rcode in ("-", "NOERROR") and not VERBOSE_MODE:
        return

    # Deduplicate repeated identical DNS queries within DNS_DEDUP_WINDOW
    prior_count = 0
    if not VERBOSE_MODE and query != "-":
        dkey = (query.lower(), qtype, rcode, bool(ips or cnames))
        now = time.time()
        with _dns_lock:
            st = _dns_state.get(dkey)
            if st is not None and (now - st["start"]) < DNS_DEDUP_WINDOW:
                st["count"] += 1
                return
            if st is not None:
                prior_count = st["count"]
            _dns_state[dkey] = {"start": now, "count": 1}

    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)

    # DNS health / error & answer formatting (prioritizing resolved IPs over CNAME chains)
    is_important = False
    if rcode not in ("-", "NOERROR"):
        ans_str = f"{C_WEIRD}[{rcode}]{C_RESET}"
        is_important = True
    elif answers == "-":
        ans_str = f"{C_TIME}(query){C_RESET}"
    elif ips:
        shown = [shorten_ip(a, 18) for a in ips[:2]]
        more = len(ips) - len(shown)
        cname_hint = f" {C_TIME}(+{len(cnames)} CNAME){C_RESET}" if cnames and not more else ""
        ans_str = ", ".join(shown) + (f" (+{more})" if more else "") + cname_hint
    elif cnames:
        shown = [smart_truncate_domain(c, 22) for c in cnames[-1:]]
        ans_str = f"CNAME {shown[0]}"
    else:
        ans_str = f"({qtype} data)" if qtype != "-" else "(record data)"

    # RTT latency insight
    rtt_str = ""
    if rtt != "-":
        try:
            rtt_ms = float(rtt) * 1000.0
            if rtt_ms >= 150.0:
                rtt_str = f" {C_WEIRD}[slow:{rtt_ms:.0f}ms]{C_RESET}"
                is_important = True
            elif rtt_ms > 0:
                rtt_str = f" {C_TIME}({rtt_ms:.0f}ms){C_RESET}"
        except ValueError:
            pass

    # Bonjour / mDNS service translation
    mdns_label = decode_mdns_service(query)
    mdns_str = f" {C_META}[{mdns_label}]{C_RESET}" if mdns_label else ""

    badges_str, cat, is_new = format_domain_badges(query, allow_novel=(answers != "-"))
    if is_new:
        is_important = True

    repeat_note = f" {C_TIME}(+{prior_count - 1} repeats){C_RESET}" if prior_count > 1 else ""
    details = f"[{C_META}{qtype:<4}{C_RESET}] → {ans_str}{rtt_str}{mdns_str}{badges_str}{repeat_note}"
    emit("dns", format_row_line(ts, C_DNS, "DNS", flow, query, details, peer_ip=resp_h), category=cat, is_important=is_important)


def parse_ssl(row, emit_enabled=True):
    server = row.get("server_name", "-")
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "443")
    version = row.get("version", "-")
    val_status = row.get("validation_status", "-")
    uid = row.get("uid", "-")

    peer_ip = select_peer_ip(orig_h, resp_h)
    had_dns = was_dns_resolved(peer_ip, server)

    if server != "-" and resp_h != "-":
        cache_put(resp_h, server, source="sni")
        uid_meta_update(uid, domain=server, source="sni", tls_ver=version)

    # Check leaf certificate metadata from x509.log
    fps = row.get("cert_chain_fps", "") or ""
    fp = fps.split(",")[0].strip() if fps else ""
    cert_meta = x509_meta_get(fp) if fp and fp != "-" else None

    server_disp = server
    if server == "-":
        cn = x509_cn_get(fp) if fp and fp != "-" else None
        if cn:
            server_disp = f"cert:{cn}"
            uid_meta_update(uid, domain=server_disp, source="cert")
        else:
            server_disp = resolve_target(peer_ip, uid=uid)

    if not emit_enabled:
        return

    # Always resolve flow/app up front so UID_CACHE[uid]["app"] is populated for conn.log
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)

    # Deduplicate parallel TLS handshakes to the same (peer_ip, port, server, version) within TLS_DEDUP_WINDOW
    prior_count = 0
    if not VERBOSE_MODE and val_status in ("-", "ok") and not (cert_meta and (cert_meta.get("expired") or cert_meta.get("self_signed"))):
        tkey = ("ssl", peer_ip, resp_p, server_disp, version)
        now = time.time()
        with _tls_lock:
            st = _tls_state.get(tkey)
            if st is not None and (now - st["start"]) < TLS_DEDUP_WINDOW:
                st["count"] += 1
                return
            if st is not None:
                prior_count = st["count"]
            _tls_state[tkey] = {"start": now, "count": 1}

    ech_suffix = ""
    if row.get("ech_kdf_id", "-") != "-" or row.get("ech_aead_id", "-") != "-":
        ech_suffix = "+ECH"

    # TLS hygiene & provenance badges
    is_important = False
    ver_color = C_META
    if version in ("SSLv2", "SSLv3", "TLSv10", "TLSv11"):
        ver_color = C_WEIRD
        is_important = True

    extra_tags = []
    if cert_meta:
        if cert_meta.get("expired"):
            extra_tags.append(f"{C_NOTICE}[EXPIRED-CERT]{C_RESET}")
            is_important = True
        elif cert_meta.get("self_signed") and not is_private_or_local(peer_ip):
            extra_tags.append(f"{C_WEIRD}[SELF-SIGNED]{C_RESET}")
            is_important = True
        elif cert_meta.get("issuer"):
            extra_tags.append(f"{C_TAG}({cert_meta['issuer']}){C_RESET}")

    if val_status not in ("-", "ok") and not extra_tags:
        extra_tags.append(f"{C_WEIRD}[cert:{val_status[:18]}]{C_RESET}")
        is_important = True

    if not is_private_or_local(peer_ip):
        if server == "-" and not had_dns:
            extra_tags.append(f"{C_WEIRD}[DIRECT-IP]{C_RESET}")
            is_important = True
        elif server != "-" and not had_dns and (time.time() - SESSION_START) > 5.0:
            extra_tags.append(f"{C_TAG}[No-DNS/DoH]{C_RESET}")

    badges_str, cat, is_new = format_domain_badges(server_disp, ip_str=peer_ip, uid=uid)
    if is_new:
        is_important = True

    ts = get_time(row.get("ts"))
    tags_str = (" " + " ".join(extra_tags)) if extra_tags else ""
    ip_note = f" {C_TIME}{shorten_ip(peer_ip, 15)}{C_RESET}" if server_disp not in ("-", "LAN/Local") else ""
    repeat_note = f" {C_TIME}(+{prior_count - 1} parallel){C_RESET}" if prior_count > 1 else ""
    details = f"[{ver_color}{version}{ech_suffix}{C_RESET}]{tags_str}{badges_str}{ip_note}{repeat_note}"
    emit("ssl", format_row_line(ts, C_SSL, "TLS", flow, server_disp, details, peer_ip=peer_ip), category=cat, is_important=is_important)


def parse_http(row, emit_enabled=True):
    method = row.get("method", "-")
    host = row.get("host", "-")
    uri = row.get("uri", "-")
    status = row.get("status_code", "-")
    user_agent = row.get("user_agent", "-")
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "80")
    uid = row.get("uid", "-")

    peer_ip = select_peer_ip(orig_h, resp_h)
    if host != "-" and resp_h != "-":
        cache_put(resp_h, host, source="http")
        uid_meta_update(uid, domain=host, source="http")

    if user_agent and user_agent != "-":
        ua_short = user_agent.split("/")[0].strip()[:12]
        if ua_short and ua_short not in ("Mozilla",):
            uid_meta_update(uid, app=ua_short)

    if not emit_enabled:
        return

    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    badges_str, cat, is_new = format_domain_badges(host, ip_str=peer_ip, uid=uid)

    cleartext_warn = f" {C_WEIRD}[cleartext]{C_RESET}" if not is_private_or_local(peer_ip) else ""
    status_color = C_CONN if status.startswith("2") else (C_WEIRD if status.startswith(("4", "5")) else C_META)
    details = f"{C_META}{method:<4}{C_RESET} {uri[:32]} [{status_color}{status}{C_RESET}]{cleartext_warn}{badges_str}"
    emit("http", format_row_line(ts, C_HTTP, "HTTP", flow, host, details, peer_ip=peer_ip), category=cat, is_important=(is_new or bool(cleartext_warn)))


def parse_quic(row, emit_enabled=True):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "443")
    version = row.get("version", "-")
    server = row.get("server_name", "-")
    client_protocol = row.get("client_protocol", "-")
    uid = row.get("uid", "-")

    peer_ip = select_peer_ip(orig_h, resp_h)
    had_dns = was_dns_resolved(peer_ip, server)

    if server != "-" and resp_h != "-":
        cache_put(resp_h, server, source="sni")
        uid_meta_update(uid, domain=server, source="sni")

    if not emit_enabled:
        return

    server_disp = server if server != "-" else resolve_target(peer_ip, uid=uid)
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)

    prior_count = 0
    if not VERBOSE_MODE:
        qkey = ("quic", peer_ip, resp_p, server_disp, version)
        now = time.time()
        with _tls_lock:
            st = _tls_state.get(qkey)
            if st is not None and (now - st["start"]) < TLS_DEDUP_WINDOW:
                st["count"] += 1
                return
            if st is not None:
                prior_count = st["count"]
            _tls_state[qkey] = {"start": now, "count": 1}

    badges_str, cat, is_new = format_domain_badges(server_disp, ip_str=peer_ip, uid=uid)
    doh_tag = ""
    if not is_private_or_local(peer_ip) and server != "-" and not had_dns and (time.time() - SESSION_START) > 5.0:
        doh_tag = f" {C_TAG}[No-DNS/DoH]{C_RESET}"

    ts = get_time(row.get("ts"))
    proto_str = client_protocol if client_protocol != "-" else f"v{version}"
    ip_note = f" {C_TIME}{shorten_ip(peer_ip, 15)}{C_RESET}" if server_disp not in ("-", "LAN/Local") else ""
    repeat_note = f" {C_TIME}(+{prior_count - 1} parallel){C_RESET}" if prior_count > 1 else ""
    details = f"[{C_META}{proto_str}{C_RESET}]{doh_tag}{badges_str}{ip_note}{repeat_note}"
    emit("quic", format_row_line(ts, C_QUIC, "QUIC", flow, server_disp, details, peer_ip=peer_ip), category=cat, is_important=is_new)


WEIRD_DEDUP_WINDOW = 30.0
_weird_state = {}
_weird_lock = threading.Lock()


def parse_weird(row):
    name = row.get("name", "Weird Activity")
    addl = row.get("addl", "")
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "")
    uid = row.get("uid", "-")

    peer_ip = select_peer_ip(orig_h, resp_h)
    key = (name, peer_ip)
    now = time.time()
    prior_count = 0
    with _weird_lock:
        st = _weird_state.get(key)
        if st is not None and (now - st["start"]) < WEIRD_DEDUP_WINDOW:
            st["count"] += 1
            return
        if st is not None:
            prior_count = st["count"]
        _weird_state[key] = {"start": now, "count": 1}

    domain = resolve_target(peer_ip, uid=uid) if peer_ip != "-" else "-"
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    detail = f" ({addl})" if addl and addl != "-" else ""
    repeat_note = (f" {C_TIME}(+{prior_count - 1} suppressed){C_RESET}"
                   if prior_count > 1 else "")
    details = f"{C_WEIRD}{name}{C_RESET}{detail}{repeat_note}"
    emit("weird", format_row_line(ts, C_WEIRD, "WEIRD", flow, domain, details, peer_ip=peer_ip), is_important=True)


def parse_ntp(row, log_type="ntp"):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "123")
    version = row.get("version", "-")
    mode = row.get("mode", "-")
    stratum = row.get("stratum", "-")
    uid = row.get("uid", "-")

    if log_type == "ntp_control":
        badge = "NTP-CT"
        op = row.get("op_code", "-")
        extra = f"v{version} Mode:6 Op:{op}"
    elif log_type == "ntp_private":
        badge = "NTP-PV"
        req = row.get("request_code", "-")
        extra = f"v{version} Mode:7 Req:{req}"
    else:
        badge = "NTP"
        extra = f"v{version} Stratum:{stratum} Mode:{mode}"

    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    details = f"[{extra}] {C_TIME}{shorten_ip(peer_ip, 15)}{C_RESET}"
    emit("ntp", format_row_line(ts, C_NTP, badge, flow, domain, details, peer_ip=peer_ip))


def parse_ssh(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "22")
    auth_success = row.get("auth_success", "-")
    server = row.get("server", "-")
    client = row.get("client", "-")
    uid = row.get("uid", "-")

    if client and client != "-":
        uid_meta_update(uid, app=client.replace("SSH-2.0-", "")[:12])

    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    auth_badge = f"{C_CONN}SUCCESS{C_RESET}" if auth_success == "T" else (f"{C_NOTICE}FAILED{C_RESET}" if auth_success == "F" else "-")

    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    details = f"Auth:{auth_badge} | Srv:{server[:22]}"
    emit("ssh", format_row_line(ts, C_SSH, "SSH", flow, domain, details, peer_ip=peer_ip), is_important=True)


def parse_dhcp(row, emit_enabled=True):
    client_addr = row.get("client_addr", row.get("assigned_ip", "-"))
    mac = row.get("mac", "-")
    host_name = row.get("host_name", "-")
    server_addr = row.get("server_addr", "-")
    msg_types = row.get("msg_types", "-")

    if host_name and host_name != "-" and client_addr and client_addr != "-":
        try:
            ipaddress.ip_address(client_addr)
            cache_put(client_addr, host_name, source="dhcp")
        except ValueError:
            pass

    if not emit_enabled:
        return

    ts = get_time(row.get("ts"))
    flow = f"{C_TIME}{mac[:17]:<18}{C_RESET}"
    details = f"IP: {client_addr} | Srv: {server_addr} [{msg_types}]"
    emit("dhcp", format_row_line(ts, C_DHCP, "DHCP", flow, host_name, details, peer_ip=client_addr))


def parse_software(row):
    host = row.get("host", "-")
    software_type = row.get("software_type", "-")
    name = row.get("name", "-")
    version = row.get("unparsed_version", "-")
    domain = resolve_target(host)

    ts = get_time(row.get("ts"))
    flow = f"{shorten_ip(host, 17):<18}"
    details = f"{software_type}: {C_META}{name}{C_RESET} v{version}"
    emit("software", format_row_line(ts, C_SOFTWR, "SOFTWR", flow, domain, details, peer_ip=host))


def _simplify_issuer(issuer):
    if not issuer or issuer == "-":
        return ""
    m_o = O_RE.search(issuer)
    if m_o:
        return m_o.group(1).strip()[:20]
    m_cn = CN_RE.search(issuer)
    if m_cn:
        return m_cn.group(1).strip()[:20]
    return issuer[:20]


def parse_x509(row, emit_enabled=True):
    subject = row.get("certificate.subject", "-")
    issuer = row.get("certificate.issuer", "-")
    san_dns = row.get("san.dns", "-")
    not_after = row.get("certificate.not_valid_after", "-")
    fp = row.get("fingerprint", "-")

    cn_match = CN_RE.search(subject)
    if cn_match:
        cn = cn_match.group(1)
    elif san_dns != "-":
        cn = san_dns.split(",")[0]
    else:
        cn = "-"

    short_issuer = _simplify_issuer(issuer)
    is_self_signed = (subject != "-" and subject == issuer)
    is_expired = False
    if not_after != "-":
        try:
            if float(not_after) < time.time():
                is_expired = True
        except ValueError:
            pass

    meta = {
        "cn": cn,
        "issuer": short_issuer,
        "self_signed": is_self_signed,
        "expired": is_expired,
    }
    x509_cn_put(fp, cn if cn not in ("-", "(empty)") else None, meta=meta)

    if not emit_enabled:
        return

    # Fold routine certificates into the [TLS] line unless anomalous or explicitly requested
    if not is_expired and not is_self_signed and not is_explicitly_requested("x509"):
        return

    ts = get_time(row.get("ts"))
    flags = []
    if is_expired:
        flags.append(f"{C_NOTICE}[EXPIRED]{C_RESET}")
    if is_self_signed:
        flags.append(f"{C_WEIRD}[SELF-SIGNED]{C_RESET}")
    flag_str = (" ".join(flags) + " ") if flags else ""
    flow = f"{C_TIME}{'cert':<18}{C_RESET}"
    details = f"{flag_str}Issuer: {short_issuer or issuer[:30]}"
    emit("x509", format_row_line(ts, C_X509, "X509", flow, cn, details), is_important=bool(flags))


def parse_dpd(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "")
    proto = row.get("proto", "-")
    analyzer = row.get("analyzer", "-")
    failure_reason = row.get("failure_reason", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)

    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    details = f"Proto: {proto}/{analyzer} | Fail: {failure_reason}"
    emit("dpd", format_row_line(ts, C_DPD, "DPD", flow, domain, details, peer_ip=peer_ip), is_important=True)


def parse_known_services(row):
    host = row.get("host", "-")
    port_num = row.get("port_num", "-")
    port_proto = row.get("port_proto", "")
    svc = row.get("service", "-")
    domain = resolve_target(host)
    proto_str = f"/{port_proto}" if port_proto and port_proto != "-" else ""

    ts = get_time(row.get("ts"))
    flow = f"{shorten_ip(host, 17):<18}"
    details = f"Service: {port_num}{proto_str} ({C_META}{svc}{C_RESET})"
    emit("known_services", format_row_line(ts, C_KNOWN, "K-SVC", flow, domain, details, peer_ip=host))


def parse_known_certs(row):
    host = row.get("host", "-")
    port_num = row.get("port_num", "-")
    subject = row.get("subject", "-")
    issuer = row.get("issuer_subject", row.get("issuer", "-"))
    domain = resolve_target(host)
    cn_match = CN_RE.search(subject)
    cn = cn_match.group(1) if cn_match else subject[:30]

    ts = get_time(row.get("ts"))
    flow = f"{format_endpoint(host, port_num):<18}"
    details = f"CN: {C_DOMAIN}{cn[:24]}{C_RESET} | Issuer: {_simplify_issuer(issuer)}"
    emit("known_certs", format_row_line(ts, C_KNOWN, "K-CRT", flow, domain, details, peer_ip=host))


def parse_known_hosts(row):
    host = row.get("host", "-")
    domain = resolve_target(host)
    ts = get_time(row.get("ts"))
    flow = f"{shorten_ip(host, 17):<18}"
    emit("known_hosts", format_row_line(ts, C_KNOWN, "K-HOST", flow, domain, "Host discovered", peer_ip=host))


def parse_known_generic(log_type, row):
    host = row.get("host", "-")
    domain = resolve_target(host)
    svc = row.get("service", "")
    port_num = row.get("port_num", "")
    detail = f"Service: {port_num}/{svc}" if svc else ""

    ts = get_time(row.get("ts"))
    flow = f"{shorten_ip(host, 17):<18}"
    emit(log_type, format_row_line(ts, C_KNOWN, log_type.upper()[:6], flow, domain, detail, peer_ip=host))


def parse_notice(row):
    note = row.get("note", "Notice")
    msg = row.get("msg", "-")
    src = row.get("src", "-")
    dst = row.get("dst", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(src, dst)
    dst_dom = resolve_target(peer_ip, uid=uid) if peer_ip != "-" else "-"

    ts = get_time(row.get("ts"))
    flow = f"{shorten_ip(src, 7)} → {shorten_ip(dst, 7)}"
    details = f"{C_META}{note}{C_RESET} | {msg}"
    emit("notice", format_row_line(ts, C_NOTICE, "ALERT", flow, dst_dom, details, peer_ip=peer_ip), is_important=True)


def parse_files(row):
    source = row.get("source", "-")
    mime = row.get("mime_type", "-")
    filename = row.get("filename", "-")
    total_bytes = row.get("total_bytes", row.get("seen_bytes", "-"))
    size_str = format_bytes(total_bytes)

    # Suppress noisy SSL handshake certificate file entries unless explicitly requested
    if ("x509" in mime or source == "SSL") and not is_explicitly_requested("files"):
        return

    tx_hosts = row.get("tx_hosts", row.get("id.resp_h", "-")).split(",")[0].strip()
    conn_uids = row.get("conn_uids", row.get("uid", "-")).split(",")[0].strip()
    domain = resolve_target(tx_hosts, uid=conn_uids) if tx_hosts != "-" else "-"

    if filename != "-":
        label = f"'{filename}' ({mime})"
    else:
        label = f"({mime})"

    ts = get_time(row.get("ts"))
    flow = f"{C_META}{source:<5}{C_RESET} {shorten_ip(tx_hosts, 12):<12}"
    details = f"{C_CONN}{size_str:<7}{C_RESET} {label}"
    emit("files", format_row_line(ts, C_FILES, "FILES", flow, domain, details, peer_ip=tx_hosts), is_important=(filename != "-"))


def parse_smtp(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "25")
    mailfrom = row.get("mailfrom", row.get("from", "-"))
    rcptto = row.get("rcptto", row.get("to", "-"))
    subject = row.get("subject", "-")
    tls = row.get("tls", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    tls_badge = f"{C_CONN}TLS{C_RESET}" if tls == "T" else f"{C_WEIRD}plain{C_RESET}"
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    subj_str = f" | Subj: {subject[:30]}" if subject and subject != "-" else ""
    details = f"[{tls_badge}] {mailfrom} → {rcptto}{subj_str}"
    emit("smtp", format_row_line(ts, C_HTTP, "SMTP", flow, domain, details, peer_ip=peer_ip), is_important=(tls != "T"))


def parse_ftp(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "21")
    user = row.get("user", "-")
    command = row.get("command", "-")
    arg = row.get("arg", "-")
    reply_code = row.get("reply_code", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    arg_str = f" {arg[:35]}" if arg and arg != "-" else ""
    details = f"User:{user} | {command}{arg_str} [{reply_code}]"
    emit("ftp", format_row_line(ts, C_HTTP, "FTP", flow, domain, details, peer_ip=peer_ip), is_important=True)


def parse_smb_files(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "445")
    action = row.get("action", "-")
    name = row.get("name", "-")
    path = row.get("path", "-")
    size = row.get("size", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    size_str = format_bytes(size)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    file_path = f"{path}\\{name}" if path != "-" and name != "-" else (name if name != "-" else path)
    details = f"{action} {file_path[:40]} ({size_str})"
    emit("smb_files", format_row_line(ts, C_DPD, "SMB-F", flow, domain, details, peer_ip=peer_ip))


def parse_smb_mapping(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "445")
    path = row.get("path", "-")
    share_type = row.get("share_type", "-")
    native_file_system = row.get("native_file_system", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    details = f"Share: {path} [{share_type}] FS: {native_file_system}"
    emit("smb_mapping", format_row_line(ts, C_DPD, "SMB-M", flow, domain, details, peer_ip=peer_ip))


def parse_rdp(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "3389")
    cookie = row.get("cookie", "-")
    security_protocol = row.get("security_protocol", "-")
    result = row.get("result", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    cookie_str = f" | Cookie:{cookie}" if cookie and cookie != "-" else ""
    result_str = f" | {result}" if result and result != "-" else ""
    details = f"[{security_protocol}]{cookie_str}{result_str}"
    emit("rdp", format_row_line(ts, C_SSH, "RDP", flow, domain, details, peer_ip=peer_ip), is_important=True)


def parse_tunnel(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "")
    tunnel_type = row.get("tunnel_type", "-")
    action = row.get("action", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    details = f"{tunnel_type} [{action}]"
    emit("tunnel", format_row_line(ts, C_QUIC, "TUNNEL", flow, domain, details, peer_ip=peer_ip))


def parse_radius(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "")
    username = row.get("username", "-")
    result = row.get("result", "-")
    mac = row.get("mac", "-")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    result_badge = f"{C_CONN}OK{C_RESET}" if result == "success" else (f"{C_NOTICE}FAIL{C_RESET}" if result == "failed" else result)
    details = f"User:{username} | {result_badge} | MAC:{mac}"
    emit("radius", format_row_line(ts, C_DHCP, "RADIUS", flow, domain, details, peer_ip=peer_ip))


def parse_sip(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "")
    method = row.get("method", "-")
    uri = row.get("uri", "-")
    status_code = row.get("status_code", "-")
    request_from = row.get("request_from", row.get("from", "-"))
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig_h, resp_h)
    domain = resolve_target(peer_ip, uid=uid)
    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid)
    details = f"{method} {uri[:30]} [{status_code}] From:{request_from}"
    emit("sip", format_row_line(ts, C_NTP, "SIP", flow, domain, details, peer_ip=peer_ip))


def parse_multicast_participants(row):
    orig_h = row.get("orig_h", "-")
    group_addr = row.get("group_addr", "-")
    group_p = row.get("group_p", "")
    participants = row.get("participants", "-")
    domain = resolve_target(group_addr)
    ts = get_time(row.get("ts"))
    flow = f"{shorten_ip(orig_h, 9):<9} → :{group_p:<5}"
    details = f"[Members: {participants}]"
    emit("conn", format_row_line(ts, C_KNOWN, "MCAST", flow, domain, details, peer_ip=group_addr))


CONN_DEDUP_WINDOW = 30.0
_conn_state = {}
_conn_lock = threading.Lock()


def parse_conn(row):
    proto = row.get("proto", "").lower()
    orig_h = row.get("id.orig_h", "")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "")
    resp_p = row.get("id.resp_p", "")
    service = row.get("service", "-")
    state = row.get("conn_state", "-")
    duration = row.get("duration", "-")
    uid = row.get("uid", "-")

    # Avoid duplicating rows covered by specialized protocol listeners
    if resp_p in ("53", "5353") or service in ("dns", "ntp") or "quic" in service:
        return

    try:
        orig_bytes = int(row.get("orig_bytes", "0")) if row.get("orig_bytes", "-") != "-" else 0
    except ValueError:
        orig_bytes = 0
    try:
        resp_bytes = int(row.get("resp_bytes", "0")) if row.get("resp_bytes", "-") != "-" else 0
    except ValueError:
        resp_bytes = 0
    total_bytes = orig_bytes + resp_bytes

    try:
        dur_val = float(duration)
    except ValueError:
        dur_val = 0.0

    if total_bytes < MIN_BYTES or dur_val < MIN_DURATION:
        return

    peer_ip = select_peer_ip(orig_h, resp_h)
    key = (proto, peer_ip, resp_p, state)
    now = time.time()
    prior_count = 0
    # Don't fold large transfers (>100KB) or connection failures into silent dedup
    if total_bytes < 100_000 and state not in CONN_FAILURE_STATES:
        with _conn_lock:
            st = _conn_state.get(key)
            if st is not None and (now - st["start"]) < CONN_DEDUP_WINDOW:
                st["count"] += 1
                return
            if st is not None:
                prior_count = st["count"]
            _conn_state[key] = {"start": now, "count": 1}

    domain = resolve_target(peer_ip, uid=uid)
    had_dns_or_sni = was_dns_resolved(peer_ip, domain) or (uid_meta_get(uid) is not None)

    record_remote_host(peer_ip)
    record_bytes(orig_bytes, resp_bytes)
    record_destination(domain if domain not in ("-", "LAN/Local") else peer_ip, orig_bytes, resp_bytes)
    check_beaconing(orig_h, resp_h, resp_p, uid=uid)

    ts = get_time(row.get("ts"))
    flow = format_flow_col(orig_h, orig_p, resp_h, resp_p, uid=uid, proto_hint=proto)

    # Traffic volume & directionality formatting
    if total_bytes > 0:
        vol_str = f"↑{format_bytes(orig_bytes):<6} ↓{format_bytes(resp_bytes):<6}"
    else:
        vol_str = f"{C_TIME}{'0B':<15}{C_RESET}"

    # Upload anomaly / exfiltration detection
    is_important = False
    extra_tags = []
    if is_private_or_local(orig_h) and not is_private_or_local(resp_h):
        if orig_bytes >= 100_000 and orig_bytes > 2 * max(resp_bytes, 1):
            extra_tags.append(f"{C_WEIRD}[↑ UPLOAD {format_bytes(orig_bytes)}]{C_RESET}")
            is_important = True
            with TOP_DEST_LOCK:
                HEAVY_UPLOADS.append((domain if domain != "-" else peer_ip, orig_bytes, ts))

    if not is_private_or_local(peer_ip) and not had_dns_or_sni and domain in ("-", "LAN/Local") and cache_get(peer_ip, include_rdns=False) is None:
        extra_tags.append(f"{C_WEIRD}[DIRECT-IP]{C_RESET}")
        is_important = True

    # Connection state health coloring
    state_label = CONN_STATE_LABELS.get(state, "")
    state_raw = f"{state}({state_label})" if state_label else state
    if state in CONN_FAILURE_STATES:
        state_disp = f"{C_WEIRD}{state_raw:<13}{C_RESET}"
        is_important = True
    else:
        state_disp = f"{C_TIME}{state_raw:<13}{C_RESET}"

    dur_str = f"{dur_val:.1f}s" if duration != "-" else "-"
    badges_str, cat, is_new = format_domain_badges(domain, ip_str=peer_ip, uid=uid)
    if is_new:
        is_important = True

    repeat_note = (f" {C_TIME}(+{prior_count - 1} more){C_RESET}" if prior_count > 1 else "")
    tags_str = (" " + " ".join(extra_tags)) if extra_tags else ""
    details = f"{vol_str} {state_disp} {dur_str}{tags_str}{badges_str}{repeat_note}"
    emit("conn", format_row_line(ts, C_CONN, "CONN", flow, domain, details, peer_ip=peer_ip), category=cat, is_important=is_important)


def parse_generic(log_type, row):
    ts = get_time(row.get("ts"))
    resp = row.get("id.resp_h", row.get("host", "-"))
    orig = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_p = row.get("id.resp_p", "")
    uid = row.get("uid", "-")
    peer_ip = select_peer_ip(orig, resp) if orig != "-" else resp
    dom = resolve_target(peer_ip, uid=uid) if peer_ip != "-" else "-"

    flow = format_flow_col(orig, orig_p, resp, resp_p, uid=uid) if orig != "-" else f"{shorten_ip(resp, 17):<18}"
    fields = [
        f"{k}={str(v)[:35]}"
        for k, v in row.items()
        if k not in ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "host", "proto")
        and v != "-"
        and not k.startswith("tunnel")
    ]
    summary = " | ".join(fields[:3])
    emit(log_type, format_row_line(ts, C_OTHER, log_type.upper()[:6], flow, dom, summary, peer_ip=peer_ip))


HIDE_LAN_DST_FIELDS = {
    "conn": "id.resp_h",
    "weird": "id.resp_h",
    "ntp": "id.resp_h",
    "ntp_control": "id.resp_h",
    "ntp_private": "id.resp_h",
    "ssh": "id.resp_h",
    "dpd": "id.resp_h",
    "notice": "dst",
}

ENRICHMENT_LOG_TYPES = {"dns", "x509", "ssl", "quic", "http", "dhcp"}


def process_row(log_type, row, emit_enabled=True):
    if not emit_enabled:
        if log_type == "dns":
            parse_dns(row, emit_enabled=False)
        elif log_type == "ssl":
            parse_ssl(row, emit_enabled=False)
        elif log_type == "http":
            parse_http(row, emit_enabled=False)
        elif log_type == "quic":
            parse_quic(row, emit_enabled=False)
        elif log_type == "dhcp":
            parse_dhcp(row, emit_enabled=False)
        elif log_type == "x509":
            parse_x509(row, emit_enabled=False)
        return

    if HIDE_LAN:
        dst_field = HIDE_LAN_DST_FIELDS.get(log_type)
        if dst_field and is_unnamed_local(row.get(dst_field, "-")):
            return
    if log_type == "dns": parse_dns(row)
    elif log_type == "ssl": parse_ssl(row)
    elif log_type == "http": parse_http(row)
    elif log_type == "quic": parse_quic(row)
    elif log_type == "weird": parse_weird(row)
    elif log_type in ("ntp", "ntp_control", "ntp_private"): parse_ntp(row, log_type)
    elif log_type == "ssh": parse_ssh(row)
    elif log_type == "dhcp": parse_dhcp(row)
    elif log_type == "software": parse_software(row)
    elif log_type == "x509": parse_x509(row)
    elif log_type == "dpd": parse_dpd(row)
    elif log_type == "known_services": parse_known_services(row)
    elif log_type == "known_certs": parse_known_certs(row)
    elif log_type == "known_hosts": parse_known_hosts(row)
    elif "known" in log_type: parse_known_generic(log_type, row)
    elif log_type == "notice": parse_notice(row)
    elif log_type == "files": parse_files(row)
    elif log_type == "smtp": parse_smtp(row)
    elif log_type == "ftp": parse_ftp(row)
    elif log_type == "smb_files": parse_smb_files(row)
    elif log_type == "smb_mapping": parse_smb_mapping(row)
    elif log_type == "rdp": parse_rdp(row)
    elif log_type == "tunnel": parse_tunnel(row)
    elif log_type == "radius": parse_radius(row)
    elif log_type == "sip": parse_sip(row)
    elif log_type == "multicast_participants": parse_multicast_participants(row)
    elif log_type == "conn": parse_conn(row)
    else: parse_generic(log_type, row)


# --- Log File Tailing & Discovery ---

IDLE_EXIT_SECONDS = 30 * 60
ATTACH_ONLY_MODE = False
PCAP_MODE = False

LOG_PRIORITY_ORDER = {
    "dns": 0,
    "x509": 1,
    "dhcp": 2,
    "ssl": 3,
    "quic": 4,
    "http": 5,
    "known_hosts": 6,
    "known_services": 7,
    "known_certs": 8,
    "conn": 90,
    "files": 95,
    "weird": 98,
}


def _log_sort_key(filepath):
    lt = os.path.basename(filepath).replace(".log", "")
    return (LOG_PRIORITY_ORDER.get(lt, 50), lt)


def _read_header_and_initial_lines(f, log_type, tail_n=None):
    """Stream initial lines of a log file.
    - When tail_n is None (default for live captures and --pcap), every line is
      returned so no startup or pcap traffic is lost.
    - When tail_n is set (for pre-existing logs in --attach-only mode), earlier
      lines still warm the DNS/SNI/X509 caches silently while only the final
      tail_n lines are emitted to the screen."""
    fields = []
    if tail_n is None:
        lines = []
        for raw in f:
            line = raw.rstrip("\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            lines.append((fields, line))
        return fields, lines

    tail = deque(maxlen=tail_n)
    is_enrichment = log_type in ENRICHMENT_LOG_TYPES
    for raw in f:
        line = raw.rstrip("\n")
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        if is_enrichment and len(tail) == tail.maxlen:
            old_fields, old_line = tail[0]
            vals = old_line.split("\t")
            if len(vals) == len(old_fields):
                process_row(log_type, dict(zip(old_fields, vals)), emit_enabled=False)
        tail.append((fields, line))
    return fields, list(tail)


def _file_ino(f):
    st = os.fstat(f.fileno())
    return (st.st_dev, st.st_ino)


def _was_rotated(f, filepath, ident):
    try:
        new_stat = os.stat(filepath)
    except OSError:
        return True
    if (new_stat.st_dev, new_stat.st_ino) != ident:
        return True
    if new_stat.st_size < f.tell():
        return True
    return False


def prewarm_enrichment_logs():
    """Quick non-emitting pass over existing enrichment logs so DNS/SNI/UID/X509
    caches are populated before conn.log rows are printed."""
    for filepath in sorted(glob.glob("*.log"), key=_log_sort_key):
        lt = os.path.basename(filepath).replace(".log", "")
        if lt not in ENRICHMENT_LOG_TYPES:
            continue
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                fields = []
                for raw in f:
                    line = raw.rstrip("\n")
                    if not line:
                        continue
                    if line.startswith("#fields"):
                        fields = line.split("\t")[1:]
                        continue
                    if line.startswith("#"):
                        continue
                    vals = line.split("\t")
                    if len(vals) == len(fields):
                        process_row(lt, dict(zip(fields, vals)), emit_enabled=False)
        except OSError:
            pass


def tail_file(filepath, pre_existing=False):
    filename = os.path.basename(filepath)
    log_type = filename.replace(".log", "")
    safe_print(f"{C_META}[+] Attached to log: {filename}{C_RESET}")

    try:
        f = open(filepath, "r", encoding="utf-8", errors="ignore")
    except OSError as e:
        safe_print(f"{C_NOTICE}[!] Couldn't open {filename}: {e}{C_RESET}")
        with ACTIVE_THREADS_LOCK:
            ACTIVE_THREADS.discard(filepath)
        return

    try:
        # Only limit initial tail when attaching to old pre-existing logs that
        # were modified before this Wirewatch session started.
        tail_n = None
        if pre_existing and ATTACH_ONLY_MODE:
            tail_n = 10
        elif pre_existing and not PCAP_MODE:
            try:
                if os.path.getmtime(filepath) < SESSION_START - 2.0:
                    tail_n = 5
            except OSError:
                pass

        fields, init_lines = _read_header_and_initial_lines(f, log_type, tail_n=tail_n)
        for row_fields, line in init_lines:
            values = line.split("\t")
            if len(values) == len(row_fields):
                process_row(log_type, dict(zip(row_fields, values)))
            else:
                note_dropped(log_type)

        ident = _file_ino(f)
        last_activity = time.time()

        while True:
            line = f.readline()
            if not line:
                if _was_rotated(f, filepath, ident):
                    safe_print(f"{C_META}[~] {filename} was rotated — reattaching.{C_RESET}")
                    try:
                        f.close()
                    except OSError:
                        pass
                    try:
                        f = open(filepath, "r", encoding="utf-8", errors="ignore")
                    except OSError:
                        time.sleep(0.5)
                        continue
                    fields = []
                    ident = _file_ino(f)
                    last_activity = time.time()
                    continue
                if time.time() - last_activity > IDLE_EXIT_SECONDS:
                    safe_print(f"{C_TIME}[~] {filename}: no new data in a while, releasing watcher.{C_RESET}")
                    return
                time.sleep(0.1)
                continue

            last_activity = time.time()
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue

            values = line.split("\t")
            if len(values) == len(fields):
                process_row(log_type, dict(zip(fields, values)))
            else:
                note_dropped(log_type)
    finally:
        try:
            f.close()
        except Exception:
            pass
        with ACTIVE_THREADS_LOCK:
            ACTIVE_THREADS.discard(filepath)


def log_watcher(initial_existing=None):
    initial_set = set(initial_existing or [])
    first_pass = True
    while True:
        files = sorted(glob.glob("*.log"), key=_log_sort_key)
        for filepath in files:
            if os.path.basename(filepath) == "zeek-console.log":
                continue
            with ACTIVE_THREADS_LOCK:
                already = filepath in ACTIVE_THREADS
                if not already:
                    ACTIVE_THREADS.add(filepath)
            if not already:
                is_pre = filepath in initial_set
                t = threading.Thread(target=tail_file, args=(filepath, is_pre), daemon=True)
                t.start()
                # Small stagger on first pass so enrichment logs (dns, ssl) parse ahead of conn.log
                if first_pass and os.path.basename(filepath).replace(".log", "") in ENRICHMENT_LOG_TYPES:
                    time.sleep(0.03)
        first_pass = False
        time.sleep(0.5)


# --- Prerequisites & Zeek process management ---
ZEEK_MODE = "native"  # "native" or "docker"
DOCKER_CONTAINER_NAME = None


def ensure_zeek(no_install=False):
    global ZEEK_MODE
    if shutil.which("zeek"):
        ZEEK_MODE = "native"
        return True
    for candidate in ["/opt/zeek/bin/zeek", "/opt/zeek-9.0/bin/zeek", "/opt/zeek-8.0/bin/zeek", "/usr/local/zeek/bin/zeek"]:
        if os.path.exists(candidate):
            os.environ["PATH"] = os.path.dirname(candidate) + ":" + os.environ.get("PATH", "")
            ZEEK_MODE = "native"
            return True

    docker_bin = shutil.which("docker")
    system = platform.system()
    arch = platform.machine().lower()

    if no_install:
        if docker_bin:
            ZEEK_MODE = "docker"
            return True
        print(f"{C_NOTICE}[!] Zeek not found on PATH and no Docker available (--no-install set).{C_RESET}")
        return False

    if system == "Darwin":
        if not shutil.which("brew"):
            print(f"{C_NOTICE}[!] Zeek not found, and Homebrew isn't installed.{C_RESET}")
            print(f"    Install Homebrew first: {C_DOMAIN}https://brew.sh{C_RESET}, then re-run this script.")
            return False
        print(f"{C_META}[*] Zeek not found — installing with 'brew install zeek' (this can take a few minutes)...{C_RESET}")
        try:
            subprocess.run(["brew", "install", "zeek"], check=True)
            if shutil.which("zeek"):
                ZEEK_MODE = "native"
                print(f"{C_CONN}[+] Zeek installed successfully.{C_RESET}")
                return True
        except subprocess.CalledProcessError:
            print(f"{C_NOTICE}[!] Homebrew installation of Zeek failed.{C_RESET}")
            return False

    elif system == "Linux":
        if arch in ("x86_64", "amd64") and shutil.which("apt-get"):
            print(f"{C_META}[*] Zeek not found — configuring official Zeek repository...{C_RESET}")
            prefix = [] if os.geteuid() == 0 else ["sudo"]
            try:
                dist = "xUbuntu_22.04"
                dist_id = ""
                version_id = ""
                if os.path.exists("/etc/os-release"):
                    with open("/etc/os-release") as f:
                        for line in f:
                            if line.startswith("ID="):
                                dist_id = line.split("=", 1)[1].strip().strip('"')
                            elif line.startswith("VERSION_ID="):
                                version_id = line.split("=", 1)[1].strip().strip('"')
                    if dist_id in ("ubuntu", "pop"):
                        dist = f"xUbuntu_{version_id}"
                    elif dist_id == "debian":
                        dist = f"Debian_{version_id.split('.')[0]}"
                repo_url = f"https://download.opensuse.org/repositories/security:/zeek/{dist}/"
                subprocess.run(prefix + ["apt-get", "update", "-y"], check=True)
                subprocess.run(prefix + ["apt-get", "install", "-y", "curl", "gnupg", "ca-certificates"], check=True)
                subprocess.run(f"curl -fsSL https://download.opensuse.org/repositories/security:zeek/{dist}/Release.key | gpg --dearmor | {' '.join(prefix)} tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null", shell=True, check=True)
                subprocess.run(f'echo "deb {repo_url} /" | {" ".join(prefix)} tee /etc/apt/sources.list.d/security:zeek.list > /dev/null', shell=True, check=True)
                subprocess.run(prefix + ["apt-get", "update", "-y"], check=True)
                pkg_cmd = prefix + ["apt-get", "install", "-y"]
                installed = False
                for pkg in ["zeek-lts", "zeek-9.0", "zeek-8.0"]:
                    if subprocess.run(pkg_cmd + [pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                        installed = True
                        break
                if not installed:
                    subprocess.run(pkg_cmd + ["zeek"], check=True)
                for candidate in ["/opt/zeek/bin/zeek", "/opt/zeek-9.0/bin/zeek", "/opt/zeek-8.0/bin/zeek"]:
                    if os.path.exists(candidate):
                        os.environ["PATH"] = os.path.dirname(candidate) + ":" + os.environ.get("PATH", "")
                        ZEEK_MODE = "native"
                        print(f"{C_CONN}[+] Zeek installed successfully.{C_RESET}")
                        return True
            except Exception as e:
                print(f"{C_WEIRD}[!] Native Zeek installation failed ({e}). Falling back to Docker...{C_RESET}")

        if not docker_bin and shutil.which("apt-get"):
            print(f"{C_META}[*] Installing Docker (docker.io) for containerized Zeek...{C_RESET}")
            prefix = [] if os.geteuid() == 0 else ["sudo"]
            try:
                subprocess.run(prefix + ["apt-get", "update", "-y"], check=True)
                subprocess.run(prefix + ["apt-get", "install", "-y", "docker.io"], check=True)
                subprocess.run(prefix + ["systemctl", "start", "docker"], check=False)
                docker_bin = shutil.which("docker")
            except Exception as e:
                print(f"{C_NOTICE}[!] Docker installation failed: {e}{C_RESET}")

        if docker_bin:
            ZEEK_MODE = "docker"
            print(f"{C_CONN}[+] Using Docker for Zeek capture (zeek/zeek:lts).{C_RESET}")
            return True

    print(f"{C_NOTICE}[!] Zeek is not available and could not be installed automatically.{C_RESET}")
    print(f"    On ARM64 Linux, install Docker: {C_DOMAIN}sudo apt-get install -y docker.io{C_RESET}")
    print(f"    See {C_DOMAIN}https://zeek.org/get-zeek/{C_RESET} for manual installation instructions.")
    return False


def interface_looks_valid(iface):
    if iface.startswith(("udp::", "af_packet::")):
        return True
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=3)
            return iface in out.stdout.split()
        return os.path.exists(f"/sys/class/net/{iface}")
    except Exception:
        return True


def launch_zeek(args, work_dir):
    global DOCKER_CONTAINER_NAME

    tuning_path = os.path.join(work_dir, "wirewatch-tuning.zeek")
    try:
        with open(tuning_path, "w") as tf:
            tf.write("# Auto-generated by Wirewatch — safe to delete.\n")
            tf.write("redef Log::flush_interval = 0.1 secs;\n")
    except OSError:
        tuning_path = None

    if ZEEK_MODE == "docker":
        DOCKER_CONTAINER_NAME = f"wirewatch-zeek-{os.getpid()}"

        needs_sudo = False
        if os.geteuid() != 0:
            test = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if test.returncode != 0:
                needs_sudo = True

        prefix = []
        if needs_sudo:
            print(f"{C_META}[*] Checking sudo access for Docker capture "
                  f"(you may be prompted for your password)...{C_RESET}")
            try:
                subprocess.run(["sudo", "-v"], timeout=120)
            except subprocess.TimeoutExpired:
                print(f"{C_NOTICE}[!] Timed out waiting for your sudo password.{C_RESET}")
                return None
            if subprocess.run(["sudo", "-n", "true"]).returncode != 0:
                print(f"{C_NOTICE}[!] Sudo authentication failed or was cancelled. Aborting.{C_RESET}")
                return None
            prefix = ["sudo", "-n"]

        subprocess.run(prefix + ["docker", "rm", "-f", DOCKER_CONTAINER_NAME],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cmd = prefix + [
            "docker", "run", "--rm",
            "--name", DOCKER_CONTAINER_NAME,
            "--net=host",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "-v", f"{work_dir}:/workdir",
            "-w", "/workdir",
            "zeek/zeek:lts",
            "zeek"
        ]

        if args.pcap:
            pcap_abs = os.path.abspath(args.pcap)
            pcap_dir = os.path.dirname(pcap_abs)
            pcap_name = os.path.basename(pcap_abs)
            if pcap_dir != work_dir:
                cmd = prefix + [
                    "docker", "run", "--rm",
                    "--name", DOCKER_CONTAINER_NAME,
                    "-v", f"{work_dir}:/workdir",
                    "-v", f"{pcap_dir}:/pcap_mount:ro",
                    "-w", "/workdir",
                    "zeek/zeek:lts",
                    "zeek", "-r", f"/pcap_mount/{pcap_name}"
                ]
            else:
                cmd.extend(["-r", pcap_name])
        else:
            if not interface_looks_valid(args.iface):
                print(f"{C_WEIRD}[!] Interface '{args.iface}' wasn't found on this system — "
                      f"continuing anyway, Zeek will report an error if it's wrong.{C_RESET}")
            cmd.extend(["-i", args.iface])
            if getattr(args, "save_pcap", None):
                cmd.extend(["-w", os.path.basename(args.save_pcap)])

        if tuning_path:
            cmd.append("wirewatch-tuning.zeek")

    else:
        zeek_bin = shutil.which("zeek")
        if args.pcap:
            cmd = [zeek_bin, "-r", os.path.abspath(args.pcap)]
        else:
            if not interface_looks_valid(args.iface):
                print(f"{C_WEIRD}[!] Interface '{args.iface}' wasn't found on this system — "
                      f"continuing anyway, Zeek will report an error if it's wrong.{C_RESET}")
            print(f"{C_META}[*] Checking sudo access for packet capture "
                  f"(you may be prompted for your password)...{C_RESET}")
            try:
                subprocess.run(["sudo", "-v"], timeout=120)
            except subprocess.TimeoutExpired:
                print(f"{C_NOTICE}[!] Timed out waiting for your sudo password.{C_RESET}")
                return None
            if subprocess.run(["sudo", "-n", "true"]).returncode != 0:
                print(f"{C_NOTICE}[!] Sudo authentication failed or was cancelled. Aborting.{C_RESET}")
                return None
            cmd = ["sudo", "-n", zeek_bin, "-i", args.iface]
            if getattr(args, "save_pcap", None):
                cmd.extend(["-w", os.path.abspath(args.save_pcap)])
        if tuning_path:
            cmd.append(tuning_path)

    print(f"{C_META}[*] Starting Zeek: {' '.join(cmd)}{C_RESET}")
    console_path = os.path.join(work_dir, "zeek-console.log")
    try:
        proc = subprocess.Popen(cmd, cwd=work_dir, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=open(console_path, "w"))
    except FileNotFoundError as e:
        print(f"{C_NOTICE}[!] Failed to execute Zeek command: {e}. Aborting.{C_RESET}")
        return None
    time.sleep(0.5 if args.pcap else 1.5)
    rc = proc.poll()
    if rc is not None:
        if args.pcap:
            if rc == 0:
                return proc
            print(f"{C_NOTICE}[!] Zeek exited immediately while reading the pcap (code {rc}). "
                  f"See zeek-console.log for Zeek's output.{C_RESET}")
        else:
            print(f"{C_NOTICE}[!] Zeek exited immediately (code {rc}). "
                  f"Check the interface name, Docker/sudo access — see zeek-console.log for details.{C_RESET}")
        return None
    return proc


def stop_zeek(proc, used_sudo):
    global DOCKER_CONTAINER_NAME
    if DOCKER_CONTAINER_NAME:
        print(f"{C_META}[*] Stopping Zeek container ({DOCKER_CONTAINER_NAME})...{C_RESET}")
        subprocess.run(["docker", "rm", "-f", DOCKER_CONTAINER_NAME],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if used_sudo:
            subprocess.run(["sudo", "docker", "rm", "-f", DOCKER_CONTAINER_NAME],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    if proc.poll() is not None:
        return
    if used_sudo:
        print(f"{C_META}[*] Stopping Zeek (pid {proc.pid})... you may be asked for your sudo password again.{C_RESET}")
        kill_cmds = [["sudo", "kill", str(proc.pid)], ["sudo", "kill", "-9", str(proc.pid)]]
    else:
        print(f"{C_META}[*] Stopping Zeek (pid {proc.pid})...{C_RESET}")
        kill_cmds = [["kill", str(proc.pid)], ["kill", "-9", str(proc.pid)]]

    for cmd in kill_cmds:
        try:
            subprocess.run(cmd, timeout=30)
            proc.wait(timeout=5)
            return
        except Exception:
            continue
    safe_print(f"{C_NOTICE}[!] Couldn't stop Zeek (pid {proc.pid}) cleanly.{C_RESET}")
    safe_print(f"{C_NOTICE}    sudo pkill -9 zeek{C_RESET}")


# --- Startup info, session summary, periodic stats & interactive hotkeys ---

def get_interface_info(iface):
    """Best-effort local IP and description for the capture interface, plus
    populating LOCAL_IPS with all local IPv4/IPv6 addresses."""
    ip_addr = "?"
    desc = ""
    found_ips = set()
    try:
        if platform.system() == "Darwin":
            out_all = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=3)
            for line in out_all.stdout.splitlines():
                ls = line.strip()
                if ls.startswith("inet "):
                    found_ips.add(ls.split()[1])
                elif ls.startswith("inet6 "):
                    addr = ls.split()[1].split("%")[0]
                    found_ips.add(addr)

            out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    ip_addr = line.split()[1]
                    break
            try:
                ns = subprocess.run(["networksetup", "-listallhardwareports"],
                                    capture_output=True, text=True, timeout=3)
                lines = ns.stdout.splitlines()
                for i, l in enumerate(lines):
                    if f"Device: {iface}" in l and i > 0:
                        desc = lines[i - 1].replace("Hardware Port: ", "")
                        break
            except Exception:
                pass
        else:
            out_all = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=3)
            for line in out_all.stdout.splitlines():
                ls = line.strip()
                if ls.startswith(("inet ", "inet6 ")):
                    addr = ls.split()[1].split("/")[0].split("%")[0]
                    found_ips.add(addr)

            out = subprocess.run(["ip", "-4", "addr", "show", iface],
                                 capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    ip_addr = line.split()[1].split("/")[0]
                    break
    except Exception:
        pass

    if found_ips:
        with LOCAL_IPS_LOCK:
            LOCAL_IPS.update(found_ips)
    return ip_addr, desc


def flush_dedup_state():
    """Emit any remaining suppressed counts from dedup windows at exit."""
    with _weird_lock:
        for key, st in _weird_state.items():
            if st["count"] > 1:
                safe_print(f"{C_TIME}[~]{C_RESET} {C_WEIRD}[WEIRD  ]{C_RESET} "
                           f"{key[0]} → {key[1]}: +{st['count'] - 1} more suppressed at exit", bypass_pause=True)
    with _conn_lock:
        for key, st in _conn_state.items():
            if st["count"] > 1:
                proto, resp_h, resp_p, state = key
                domain = resolve_target(resp_h)
                safe_print(f"{C_TIME}[~]{C_RESET} {C_CONN}[CONN   ]{C_RESET} "
                           f"{proto} → {format_endpoint(resp_h, resp_p)} ({C_DOMAIN}{domain}{C_RESET}): "
                           f"+{st['count'] - 1} more suppressed at exit", bypass_pause=True)


def print_session_summary(live=False):
    """Print a compact session summary on exit or when 's' is pressed."""
    elapsed = max(0.1, time.time() - SESSION_START)
    if not live and elapsed < 0.5:
        return
    mins, secs = divmod(int(elapsed), 60)
    hrs, mins = divmod(mins, 60)
    if hrs:
        dur_str = f"{hrs}h {mins}m {secs}s"
    elif mins:
        dur_str = f"{mins}m {secs}s"
    else:
        dur_str = f"{secs}s"

    with SESSION_STATS_LOCK:
        stats = dict(SESSION_STATS)
        cats = dict(SESSION_CATEGORIES)
        apps = dict(SESSION_APPS)
        bytes_in = SESSION_BYTES_IN
        bytes_out = SESSION_BYTES_OUT
    with UNIQUE_HOSTS_LOCK:
        n_remote = len(UNIQUE_REMOTE_HOSTS)
    with NOVELTY_LOCK:
        new_doms = list(SESSION_NEW_DOMAINS)

    total_events = sum(stats.values())
    if total_events == 0 and not live:
        return

    title = "Live Snapshot" if live else "Session Summary"
    safe_print("", bypass_pause=True)
    safe_print(f"{C_CONN}=== {title} ({dur_str}) ==={C_RESET}", bypass_pause=True)
    safe_print(f"{C_META}  Unique remote hosts:  {C_RESET}{n_remote}   "
               f"{C_META}Data:{C_RESET} ↑{format_bytes(str(bytes_out))} sent, ↓{format_bytes(str(bytes_in))} received", bypass_pause=True)

    with TOP_DEST_LOCK:
        sorted_dests = sorted(TOP_DESTINATIONS.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
        uploads = list(HEAVY_UPLOADS)
    if sorted_dests:
        parts = [f"{d} ({format_bytes(e['bytes'])}, {e['conns']}c)" for d, e in sorted_dests]
        safe_print(f"{C_META}  Top destinations:    {C_RESET}{', '.join(parts)}", bypass_pause=True)

    if apps:
        top_apps = [f"{k}({v})" for k, v in sorted(apps.items(), key=lambda x: -x[1])[:6]]
        safe_print(f"{C_META}  Active local apps:   {C_RESET}{', '.join(top_apps)}", bypass_pause=True)

    proto_parts = [f"{k.upper()}({v})" for k, v in sorted(stats.items(), key=lambda x: -x[1]) if v > 0]
    if proto_parts:
        safe_print(f"{C_META}  Events by type:      {C_RESET}{', '.join(proto_parts[:10])}", bypass_pause=True)

    if cats:
        cat_parts = [f"{k}({v})" for k, v in sorted(cats.items(), key=lambda x: -x[1])]
        safe_print(f"{C_META}  Traffic categories:  {C_RESET}{', '.join(cat_parts)}", bypass_pause=True)

    if new_doms:
        shown_new = ", ".join(new_doms[:6]) + (f" (+{len(new_doms) - 6} more)" if len(new_doms) > 6 else "")
        safe_print(f"{C_META}  New domains ({len(new_doms)}):     {C_RESET}{C_NEW}{shown_new}{C_RESET}", bypass_pause=True)

    if uploads:
        up_parts = [f"{d} (↑{format_bytes(b)} at {t})" for d, b, t in uploads[:4]]
        safe_print(f"{C_META}  Heavy uploads:       {C_RESET}{C_WEIRD}{', '.join(up_parts)}{C_RESET}", bypass_pause=True)

    notice_count = stats.get("notice", 0)
    weird_count = stats.get("weird", 0)
    if notice_count:
        safe_print(f"{C_META}  Alerts/Notices:      {C_RESET}{C_NOTICE}{notice_count}{C_RESET}", bypass_pause=True)
    if weird_count:
        safe_print(f"{C_META}  Weird events:        {C_RESET}{weird_count}", bypass_pause=True)

    with BEACON_LOCK:
        n_beacons = len(BEACON_ALERTED)
    if n_beacons:
        safe_print(f"{C_META}  Beaconing suspects:  {C_RESET}{C_NOTICE}{n_beacons}{C_RESET}", bypass_pause=True)

    safe_print("", bypass_pause=True)


def periodic_stats_worker():
    """Background thread: emits a one-line summary every STATS_INTERVAL seconds."""
    last_stats = defaultdict(int)
    last_bytes_in = 0
    last_bytes_out = 0
    while True:
        time.sleep(STATS_INTERVAL)
        with SESSION_STATS_LOCK:
            current = dict(SESSION_STATS)
            cur_in = SESSION_BYTES_IN
            cur_out = SESSION_BYTES_OUT
        delta = {k: current.get(k, 0) - last_stats.get(k, 0) for k in current}
        d_in = cur_in - last_bytes_in
        d_out = cur_out - last_bytes_out
        last_stats = current.copy()
        last_bytes_in = cur_in
        last_bytes_out = cur_out
        total_delta = sum(delta.values())
        if total_delta == 0:
            continue
        parts = [f"{k}:{v}" for k, v in sorted(delta.items(), key=lambda x: -x[1]) if v > 0][:6]
        safe_print(
            f"{C_META}--- {STATS_INTERVAL}s: {total_delta} events | "
            f"{' | '.join(parts)} | "
            f"↑{format_bytes(str(d_out))} out, ↓{format_bytes(str(d_in))} in ---{C_RESET}"
        )


def handle_keypress(ch):
    """Process single-keystroke interactive commands during live monitoring."""
    global PAUSED, PAUSED_DROPPED, ONLY_NEW, HIDE_LAN
    global MARK_COUNT, MARK_TIME, MARK_EVENTS, MARK_BYTES_IN, MARK_BYTES_OUT

    if ch in (" ", "p", "P"):
        with PAUSE_LOCK:
            PAUSED = not PAUSED
            if PAUSED:
                safe_print(f"{C_WEIRD}⏸  PAUSED — press [Space] or [p] to resume (events continue buffering){C_RESET}", bypass_pause=True)
            else:
                buffered = list(PAUSED_BUFFER)
                dropped = PAUSED_DROPPED
                PAUSED_BUFFER.clear()
                PAUSED_DROPPED = 0
        if not PAUSED:
            if dropped:
                safe_print(f"{C_TIME}[~] ({dropped} older lines dropped while paused){C_RESET}", bypass_pause=True)
            for line in buffered:
                safe_print(line, bypass_pause=True)
            safe_print(f"{C_CONN}▶  RESUMED ({len(buffered)} buffered lines flushed){C_RESET}", bypass_pause=True)

    elif ch in ("\r", "\n", "m", "M"):
        now = time.time()
        with SESSION_STATS_LOCK:
            MARK_COUNT += 1
            mc = MARK_COUNT
            dt = now - (MARK_TIME or SESSION_START)
            me = MARK_EVENTS
            m_in = MARK_BYTES_IN
            m_out = MARK_BYTES_OUT
            MARK_TIME = now
            MARK_EVENTS = 0
            MARK_BYTES_IN = 0
            MARK_BYTES_OUT = 0
        ts_str = time.strftime("%H:%M:%S", time.localtime(now))
        safe_print(
            f"{C_NEW}━━━ MARK #{mc} at {ts_str} "
            f"(+{dt:.1f}s: {me} events, ↑{format_bytes(m_out)} ↓{format_bytes(m_in)}) ━━━{C_RESET}",
            bypass_pause=True,
        )

    elif ch in ("s", "S"):
        print_session_summary(live=True)

    elif ch in ("n", "N"):
        ONLY_NEW = not ONLY_NEW
        state = f"{C_CONN}ON{C_RESET}" if ONLY_NEW else f"{C_TIME}OFF{C_RESET}"
        safe_print(f"{C_META}[i] Toggled ONLY-NEW mode: {state} (show only ★ NEW domains & alerts){C_RESET}", bypass_pause=True)

    elif ch in ("l", "L"):
        HIDE_LAN = not HIDE_LAN
        state = f"{C_CONN}ON{C_RESET}" if HIDE_LAN else f"{C_TIME}OFF{C_RESET}"
        safe_print(f"{C_META}[i] Toggled HIDE-LAN mode: {state}{C_RESET}", bypass_pause=True)

    elif ch in ("h", "H", "?"):
        safe_print(
            f"{C_META}[Keys] [Space/p] Pause  [Enter/m] Mark  [s] Live Summary  "
            f"[n] Only-New  [l] Hide-LAN  [q/Ctrl+C] Quit{C_RESET}",
            bypass_pause=True,
        )

    elif ch in ("q", "Q"):
        raise KeyboardInterrupt()


def detect_default_interface():
    """Auto-detect active default network interface on macOS and Linux."""
    system = platform.system()
    if system == "Darwin":
        try:
            out = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=2)
            for line in out.stdout.splitlines():
                if "interface:" in line:
                    return line.split(":")[1].strip()
        except Exception:
            pass
        return "en0"
    elif system == "Linux":
        try:
            out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2)
            words = out.stdout.split()
            if "dev" in words:
                idx = words.index("dev")
                if idx + 1 < len(words):
                    return words[idx + 1]
        except Exception:
            pass
        if os.path.exists("/sys/class/net"):
            try:
                for iface in sorted(os.listdir("/sys/class/net")):
                    if iface != "lo" and not any(iface.startswith(p) for p in ("docker", "br-", "veth", "virbr")):
                        return iface
            except Exception:
                pass
        return "eth0"
    return "en0" if system == "Darwin" else "eth0"


# --- CLI & entry point ---

def parse_args():
    default_iface = detect_default_interface()
    p = argparse.ArgumentParser(
        prog="wirewatch",
        description="One-command Zeek network monitor: checks prerequisites, starts Zeek, "
                    "and streams enriched, color-coded protocol output.",
    )
    p.add_argument("-i", "--iface", default=default_iface,
                   help=f"Network interface to capture on (default: {default_iface})")
    p.add_argument("--dir", default=".", help="Directory to run Zeek in / watch for logs (default: current directory)")
    p.add_argument("--only", help="Comma-separated log types to show exclusively, e.g. dns,http,ssl")
    p.add_argument("--exclude", help="Comma-separated log types to hide, e.g. ntp,dhcp")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--pcap", help="Read from a pcap file instead of live capture (no sudo needed)")
    p.add_argument("--attach-only", action="store_true",
                   help="Don't launch Zeek — just watch --dir for logs from a Zeek process you start yourself")
    p.add_argument("--no-install", action="store_true", help="Don't auto-install Zeek if it's missing")
    p.add_argument("--match", help="Only show lines containing this substring (case-insensitive)")
    p.add_argument("--min-bytes", type=int, default=0, metavar="N",
                   help="Hide CONN rows with fewer than N bytes transferred (orig+resp)")
    p.add_argument("--min-duration", type=float, default=0.0, metavar="S",
                   help="Hide CONN rows shorter than S seconds")
    p.add_argument("--hide-lan", action="store_true",
                   help="Suppress unnamed LAN/mDNS/local traffic")
    p.add_argument("--only-new", action="store_true",
                   help="Only show newly seen domains (★ NEW), alerts, weird events, and heavy uploads")
    p.add_argument("--verbose", action="store_true",
                   help="Show all raw x509 certificate chain and SSL file entries without folding")
    p.add_argument("--no-procs", action="store_true",
                   help="Disable local process/app attribution lookup")
    p.add_argument("--watchlist", metavar="FILE",
                   help="Newline-delimited file of domains, IPs, and CIDRs to flag with [WATCH]")
    p.add_argument("--alert-on", metavar="PATTERN",
                   help="Regex pattern — matching lines get a [!] highlight prefix (doesn't filter)")
    p.add_argument("--stats-interval", type=int, default=0, metavar="SEC",
                   help="Print a one-line event/traffic summary every SEC seconds (0 = disabled)")
    p.add_argument("--save-pcap", metavar="FILE",
                   help="Also save raw packets to this pcap file (adds -w to Zeek)")
    return p.parse_args()


class _ShutdownSignal(Exception):
    """Raised from the SIGTERM handler so `kill`, `timeout`, process
    supervisors, etc. trigger the same graceful shutdown (stopping Zeek)
    as an interactive Ctrl+C."""


def _handle_sigterm(signum, frame):
    raise _ShutdownSignal()


def main():
    global SESSION_START, ATTACH_ONLY_MODE, PCAP_MODE, MARK_TIME
    signal.signal(signal.SIGTERM, _handle_sigterm)
    args = parse_args()
    configure_colors(resolve_color_setting(args.no_color))
    apply_filters(args.only, args.exclude, verbose=args.verbose)
    apply_display_filters(args)

    SESSION_START = time.time()
    MARK_TIME = SESSION_START
    ATTACH_ONLY_MODE = bool(args.attach_only)
    PCAP_MODE = bool(args.pcap)

    if getattr(args, "watchlist", None):
        load_watchlist(args.watchlist)

    work_dir = os.path.abspath(os.path.expanduser(args.dir))
    os.makedirs(work_dir, exist_ok=True)
    load_known_domains(work_dir)

    # Record any pre-existing logs before Zeek starts so tail_file knows which are old
    os.chdir(work_dir)
    pre_existing_logs = {p for p in glob.glob("*.log") if os.path.basename(p) != "zeek-console.log"}

    # Detect local IPs up front so self-IP formatting works immediately
    ip_addr, iface_desc = get_interface_info(args.iface)

    if PROCS_ENABLED:
        _scan_local_processes()
        proc_thread = threading.Thread(target=proc_scanner_worker, daemon=True)
        proc_thread.start()

    zeek_proc = None
    used_sudo = not args.pcap
    if not args.attach_only:
        if not ensure_zeek(no_install=args.no_install):
            sys.exit(1)
        zeek_proc = launch_zeek(args, work_dir)
        if zeek_proc is None:
            sys.exit(1)

    print(f"\n{C_CONN}=== Wirewatch — Zeek Omni-Monitor ==={C_RESET}")
    safe_print(f"{C_META}Watching directory: {work_dir}{C_RESET}")
    if zeek_proc is not None:
        if args.pcap:
            label = f"pcap {args.pcap}"
        else:
            desc_str = f", {iface_desc}" if iface_desc else ""
            label = f"interface {args.iface}{desc_str}, {ip_addr}"
        print(f"{C_CONN}[+] Zeek capture started (pid {zeek_proc.pid}, {label}){C_RESET}")
        if getattr(args, "save_pcap", None):
            print(f"{C_CONN}[+] Also saving raw packets to: {args.save_pcap}{C_RESET}")
        if sys.stdin.isatty() and not args.pcap:
            print(f"{C_TIME}[i] Hotkeys: [Space] Pause  [Enter] Mark  [s] Summary  [n] Only-New  [l] Hide-LAN  [?] Help{C_RESET}")
        print()
    else:
        print(f"{C_META}[i] Attach-only mode — expecting Zeek logs to appear in this directory.{C_RESET}\n")

    if pre_existing_logs:
        safe_print(f"{C_META}Found existing logs: {', '.join(sorted(pre_existing_logs))}{C_RESET}\n")

    # Pre-warm enrichment caches from any files already on disk (e.g. fast pcap or existing logs)
    prewarm_enrichment_logs()

    watcher_thread = threading.Thread(target=log_watcher, args=(pre_existing_logs,), daemon=True)
    watcher_thread.start()

    if STATS_INTERVAL > 0:
        stats_thread = threading.Thread(target=periodic_stats_worker, daemon=True)
        stats_thread.start()

    old_tty_attrs = None
    tty_fd = None
    if HAS_TERMIOS and sys.stdin.isatty() and not args.pcap:
        try:
            tty_fd = sys.stdin.fileno()
            old_tty_attrs = termios.tcgetattr(tty_fd)
            tty.setcbreak(tty_fd)
        except Exception:
            old_tty_attrs = None

    try:
        while True:
            if zeek_proc is not None:
                rc = zeek_proc.poll()
                if rc is not None:
                    if args.pcap:
                        # Give watcher_thread & tail_file threads time to flush all pcap logs
                        time.sleep(1.2)
                        safe_print(f"{C_CONN}[+] Finished reading pcap (exit {rc}).{C_RESET}", bypass_pause=True)
                    else:
                        safe_print(f"{C_NOTICE}[!] Zeek exited (code {rc}). Capture has stopped.{C_RESET}", bypass_pause=True)
                    break

            if old_tty_attrs is not None and tty_fd is not None:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.25)
                if rlist:
                    ch = sys.stdin.read(1)
                    if ch:
                        handle_keypress(ch)
            else:
                time.sleep(0.5)
    except (KeyboardInterrupt, _ShutdownSignal):
        pass
    finally:
        if old_tty_attrs is not None and tty_fd is not None:
            try:
                termios.tcsetattr(tty_fd, termios.TCSADRAIN, old_tty_attrs)
            except Exception:
                pass
        if zeek_proc is not None and zeek_proc.poll() is None:
            stop_zeek(zeek_proc, used_sudo)
        save_known_domains(work_dir)
        flush_dedup_state()
        print_dropped_summary()
        print_session_summary()
        print(f"{C_META}Exiting Wirewatch.{C_RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C_META}Exiting Wirewatch.{C_RESET}")
