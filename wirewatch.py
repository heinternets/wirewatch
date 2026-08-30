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
import os
import platform
import re
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

# --- ANSI Terminal Color Palette ---
C_TIME    = "\033[90m"        # Dark Gray
C_DNS     = "\033[1;36m"      # Bright Cyan
C_SSL     = "\033[1;35m"      # Bright Magenta
C_HTTP    = "\033[1;33m"      # Bright Yellow
C_CONN    = "\033[1;32m"      # Bright Green
C_NOTICE  = "\033[1;41;97m"   # White text on Red — reserved for Zeek notice.log + fatal errors
C_FILES   = "\033[1;34m"      # Bright Blue
C_WEIRD   = "\033[1;38;5;208m"# Bright Orange — weird.log + non-fatal warnings
C_NTP     = "\033[1;38;5;75m" # Sky Blue
C_SSH     = "\033[1;38;5;120m"# Mint Green
C_DHCP    = "\033[1;38;5;177m"# Lavender / Violet
C_SOFTWR  = "\033[1;38;5;153m"# Ice Blue
C_X509    = "\033[1;38;5;141m"# Light Purple
C_QUIC    = "\033[1;38;5;215m"# Light Orange — QUIC/HTTP3
C_DPD     = "\033[1;31m"      # Bright Red
C_KNOWN   = "\033[1;38;5;114m"# Soft Green
C_OTHER   = "\033[1;37m"      # Bright White
C_DOMAIN  = "\033[1;93m"      # Bold Yellow
C_META    = "\033[96m"        # Cyan — lifecycle/info messages
C_RESET   = "\033[0m"

# --- Human-readable Zeek connection states ---
CONN_STATE_LABELS = {
    "S0": "no reply", "S1": "established", "SF": "normal close",
    "REJ": "rejected", "S2": "resp→orig only", "S3": "orig→resp only",
    "RSTO": "reset(orig)", "RSTR": "reset(resp)",
    "RSTOS0": "reset(no resp)", "RSTRH": "reset(half)",
    "SH": "half-open", "SHR": "half-open(resp)", "OTH": "midstream",
}

CN_RE = re.compile(r"CN=([^,]+)")

socket.setdefaulttimeout(0.3)


def configure_colors(enabled):
    """Null out every color constant when colors are disabled (--no-color,
    NO_COLOR env var, or non-tty stdout) instead of threading a flag through
    every print call."""
    global C_TIME, C_DNS, C_SSL, C_HTTP, C_CONN, C_NOTICE, C_FILES, C_WEIRD
    global C_NTP, C_SSH, C_DHCP, C_SOFTWR, C_X509, C_QUIC, C_DPD, C_KNOWN, C_OTHER
    global C_DOMAIN, C_META, C_RESET
    if enabled:
        return
    (C_TIME, C_DNS, C_SSL, C_HTTP, C_CONN, C_NOTICE, C_FILES, C_WEIRD,
     C_NTP, C_SSH, C_DHCP, C_SOFTWR, C_X509, C_QUIC, C_DPD, C_KNOWN, C_OTHER,
     C_DOMAIN, C_META, C_RESET) = [""] * 20


def resolve_color_setting(cli_no_color):
    if cli_no_color:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


# --- Log type filtering (--only / --exclude) ---
ONLY_TYPES = None
EXCLUDE_TYPES = set()


def apply_filters(only_arg, exclude_arg):
    global ONLY_TYPES, EXCLUDE_TYPES
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


# --- Display filters (--match / --min-bytes / --min-duration / --hide-lan) ---
MATCH_TEXT = None    # case-insensitive substring every printed line must contain
MIN_BYTES = 0        # CONN rows below this total byte count are hidden
MIN_DURATION = 0.0   # CONN rows shorter than this many seconds are hidden
HIDE_LAN = False     # suppress unnamed local-network traffic

# --- Watchlist (--watchlist) ---
WATCHLIST_DOMAINS = set()
WATCHLIST_IPS = set()
WATCHLIST_CIDRS = []
WATCHLIST_LOADED = False

# --- Alert-on pattern (--alert-on) ---
ALERT_PATTERN = None  # compiled regex, applied to every printed line

# --- Periodic stats (--stats-interval) ---
STATS_INTERVAL = 0  # seconds between summary lines, 0 = disabled

# --- Session tracking (for exit summary) ---
SESSION_START = 0.0
SESSION_STATS = defaultdict(int)       # log_type -> event count
SESSION_BYTES_IN = 0
SESSION_BYTES_OUT = 0
SESSION_STATS_LOCK = threading.Lock()
UNIQUE_REMOTE_HOSTS = set()
UNIQUE_HOSTS_LOCK = threading.Lock()
TOP_DESTINATIONS = defaultdict(lambda: {"conns": 0, "bytes": 0})
TOP_DEST_LOCK = threading.Lock()

# --- Beaconing detection ---
BEACON_TIMESTAMPS = defaultdict(list)   # (src, dst, port) -> [wall-clock ts]
BEACON_LOCK = threading.Lock()
BEACON_ALERTED = set()                  # keys already flagged this session
BEACON_MIN_CONNS = 10                   # minimum sample size before checking
BEACON_MAX_COV = 0.15                   # coefficient-of-variation threshold


def apply_display_filters(args):
    global MATCH_TEXT, MIN_BYTES, MIN_DURATION, HIDE_LAN
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
    if getattr(args, 'alert_on', None):
        try:
            ALERT_PATTERN = re.compile(args.alert_on, re.IGNORECASE)
        except re.error as e:
            print(f"{C_NOTICE}[!] Invalid --alert-on pattern: {e}{C_RESET}")
    try:
        STATS_INTERVAL = int(getattr(args, 'stats_interval', 0) or 0)
    except (TypeError, ValueError):
        STATS_INTERVAL = 0


def is_unnamed_local(ip_str):
    """True for private/loopback/link-local/multicast IPs that have no cached
    name (no DNS/SNI/DHCP hostname seen for them yet)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast):
        return False
    return cache_get(ip_str) is None


# --- Watchlist loading & matching ---

def load_watchlist(filepath):
    """Load domains, IPs, and CIDRs from a newline-delimited text file.
    Lines starting with # are comments.  Entries can be:
      - bare domains (example.com) — also matches *.example.com
      - wildcard domains (*.evil.com) — same as bare
      - IP addresses (1.2.3.4)
      - CIDR ranges (185.220.0.0/16)
    """
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
    # IP check
    try:
        ip = ipaddress.ip_address(value)
        if value in WATCHLIST_IPS:
            return True
        for net in WATCHLIST_CIDRS:
            if ip in net:
                return True
    except ValueError:
        pass
    # Domain check (suffix match)
    domain = value.lower()
    for wd in WATCHLIST_DOMAINS:
        if domain == wd or domain.endswith("." + wd):
            return True
    return False


# --- Session statistics helpers ---

def record_stat(log_type):
    with SESSION_STATS_LOCK:
        SESSION_STATS[log_type] += 1


def record_bytes(orig, resp):
    global SESSION_BYTES_OUT, SESSION_BYTES_IN
    with SESSION_STATS_LOCK:
        SESSION_BYTES_OUT += orig
        SESSION_BYTES_IN += resp


def record_remote_host(ip_str):
    if not ip_str or ip_str == "-":
        return
    try:
        ip = ipaddress.ip_address(ip_str)
        if not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast):
            with UNIQUE_HOSTS_LOCK:
                UNIQUE_REMOTE_HOSTS.add(ip_str)
    except ValueError:
        pass


def record_destination(domain, byte_count):
    if not domain or domain in ("-", "LAN/Local"):
        return
    with TOP_DEST_LOCK:
        TOP_DESTINATIONS[domain]["conns"] += 1
        TOP_DESTINATIONS[domain]["bytes"] += byte_count


# --- Beaconing detection ---

def check_beaconing(src, dst, port):
    """Track connection timing and flag suspiciously regular intervals.
    Only alerts once per (src, dst, port) tuple per session."""
    key = (src, dst, port)
    now = time.time()
    with BEACON_LOCK:
        ts_list = BEACON_TIMESTAMPS[key]
        ts_list.append(now)
        # Keep only the last 60 entries to bound memory
        if len(ts_list) > 60:
            BEACON_TIMESTAMPS[key] = ts_list[-60:]
            ts_list = BEACON_TIMESTAMPS[key]
        if len(ts_list) < BEACON_MIN_CONNS or key in BEACON_ALERTED:
            return
    # Compute outside the lock to avoid holding it during math
    intervals = [ts_list[i + 1] - ts_list[i] for i in range(len(ts_list) - 1)]
    if not intervals:
        return
    mean = sum(intervals) / len(intervals)
    if mean < 1.0:  # sub-second bursts are normal
        return
    variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
    std_dev = variance ** 0.5
    cov = std_dev / mean if mean > 0 else float("inf")
    if cov < BEACON_MAX_COV:
        with BEACON_LOCK:
            if key in BEACON_ALERTED:
                return  # another thread got here first
            BEACON_ALERTED.add(key)
        domain = resolve_target(dst)
        ts_str = time.strftime("%H:%M:%S", time.localtime(now))
        window = int(ts_list[-1] - ts_list[0])
        safe_print(
            f"{C_TIME}{ts_str}{C_RESET} {C_NOTICE} [BEACON?] {C_RESET} "
            f"{src} -> {dst}:{port} ({C_DOMAIN}{domain}{C_RESET}) — "
            f"{len(ts_list)} conns in {window}s, interval ~{mean:.0f}s ±{std_dev:.0f}s"
        )


# --- DNS/SNI resolution cache (bounded, LRU) ---
DNS_CACHE = OrderedDict()
DNS_CACHE_MAX = 20000
CACHE_LOCK = threading.Lock()

RDNS_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="rdns")
RDNS_INFLIGHT = set()
RDNS_INFLIGHT_LOCK = threading.Lock()

PRINT_LOCK = threading.Lock()
ACTIVE_THREADS = set()
ACTIVE_THREADS_LOCK = threading.Lock()


def cache_put(ip, domain):
    if not ip or ip == "-" or not domain or domain == "-":
        return
    with CACHE_LOCK:
        if ip in DNS_CACHE:
            DNS_CACHE.move_to_end(ip)
        DNS_CACHE[ip] = domain
        while len(DNS_CACHE) > DNS_CACHE_MAX:
            DNS_CACHE.popitem(last=False)


def cache_get(ip):
    with CACHE_LOCK:
        domain = DNS_CACHE.get(ip)
        if domain is not None:
            DNS_CACHE.move_to_end(ip)
        return domain


# Leaf-certificate CN fallback keyed by cert fingerprint (bounded, LRU).
# Lets ssl.log rows without SNI show something real; best-effort by design.
X509_CN_BY_FP = OrderedDict()
X509_CN_MAX = 5000


def x509_cn_put(fp, cn):
    if not fp or fp == "-" or not cn or cn == "-":
        return
    with CACHE_LOCK:
        if fp in X509_CN_BY_FP:
            X509_CN_BY_FP.move_to_end(fp)
        X509_CN_BY_FP[fp] = cn
        while len(X509_CN_BY_FP) > X509_CN_MAX:
            X509_CN_BY_FP.popitem(last=False)


def x509_cn_get(fp):
    with CACHE_LOCK:
        cn = X509_CN_BY_FP.get(fp)
        if cn is not None:
            X509_CN_BY_FP.move_to_end(fp)
        return cn


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
                cache_put(ip_str, name)
        finally:
            with RDNS_INFLIGHT_LOCK:
                RDNS_INFLIGHT.discard(ip_str)

    RDNS_EXECUTOR.submit(_work)


def resolve_target(ip_str):
    """Non-blocking: DNS/SNI cache first, then a fast LAN check, then kick
    off a background rDNS lookup that fills the cache in for next time."""
    if not ip_str or ip_str == "-":
        return "-"

    cached = cache_get(ip_str)
    if cached:
        return cached

    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return "LAN/Local"
    except ValueError:
        pass

    _schedule_rdns(ip_str)
    return "-"


def get_time(ts_raw):
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts_raw)))
    except Exception:
        return "--:--:--"


def format_bytes(byte_str):
    try:
        b = float(byte_str)
        if b < 1024: return f"{b:.0f} B"
        if b < 1024**2: return f"{b/1024:.1f} KB"
        return f"{b/(1024**2):.1f} MB"
    except Exception:
        return "- B"


ANSI_RE = re.compile(r"\033\[[0-9;]*m")
# C0 controls except ESC (escape sequences are handled separately); a stray
# tab from log data would otherwise jump the cursor to the next tab stop.
CONTROL_RE = re.compile(r"[\x00-\x1a\x1c-\x1f\x7f]")


def _visible_len(msg):
    return len(ANSI_RE.sub("", msg))


def _clip_to_width(msg, max_cols):
    """Hard-cap a styled line to max_cols visible cells. Soft-wrapping long
    styled lines is what garbles alignment in macOS Terminal, so never emit
    a line wider than the window."""
    budget = max_cols - 1  # leave room for the ellipsis
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

def safe_print(msg):
    msg = CONTROL_RE.sub(" ", msg)
    cols = shutil.get_terminal_size((120, 24)).columns - 1
    with PRINT_LOCK:
        print(_clip_to_width(msg, cols))
        sys.stdout.flush()


def emit(log_type, msg):
    """Filtered print for parsed log rows: --only/--exclude gate visibility
    here instead of in process_row, so every row still reaches its parser
    and enrichment caches keep filling under any filter."""
    record_stat(log_type)
    if MATCH_TEXT is not None and MATCH_TEXT.lower() not in ANSI_RE.sub("", msg).lower():
        return
    if not type_allowed(log_type):
        return
    # Watchlist / alert-on prefixing
    plain = ANSI_RE.sub("", msg)
    prefix = ""
    if WATCHLIST_LOADED:
        for token in plain.split():
            cleaned = token.strip("()[]{},:/<>")
            if check_watchlist(cleaned):
                prefix = f"{C_NOTICE} [WATCH] {C_RESET} "
                break
    if not prefix and ALERT_PATTERN and ALERT_PATTERN.search(plain):
        prefix = f"{C_DPD}[!]{C_RESET} "
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

def _clean_answers(answers):
    """Split the answer vector, dropping record payloads (mDNS TXT blobs like
    'TXT 47 identifier=…' or SPF strings) and duplicates."""
    seen, clean = set(), []
    for ans in answers.split(","):
        ans = ans.strip()
        if ans and " " not in ans and ans not in seen:
            seen.add(ans)
            clean.append(ans)
    return clean


def parse_dns(row):
    query = row.get("query", "-")
    qtype = row.get("qtype_name", "-")
    answers = row.get("answers", "-")
    orig_h = row.get("id.orig_h", "-")

    if answers != "-" and query != "-":
        for ans in answers.split(","):
            ans = ans.strip()
            # Only real addresses belong in the IP->domain cache; mDNS TXT
            # payloads would churn the bounded LRU and evict useful entries.
            if ans and " " not in ans:
                try:
                    ipaddress.ip_address(ans)
                except ValueError:
                    continue
                cache_put(ans, query)
    # Under --hide-lan, mDNS (.local) queries are the dominant noise source:
    # keep feeding the answer->query cache above, but don't print the line.
    if HIDE_LAN and query != "-" and query.lower().endswith(".local"):
        return

    ts = get_time(row.get("ts"))

    if answers == "-":
        ans_str = "-"
    else:
        clean = _clean_answers(answers)
        if not clean:
            # Everything was record payload — the query name is the part that
            # tells you what's going on (e.g. an iPhone mDNS check).
            ans_str = f"({qtype} data)" if qtype != "-" else "(record data)"
        else:
            shown = clean[:3]
            more = len(clean) - len(shown)
            ans_str = ", ".join(shown) + (f" (+{more} more)" if more else "")

    emit("dns", f"{C_TIME}{ts}{C_RESET} {C_DNS}[DNS   ]{C_RESET} {orig_h:<15} asked [{C_META}{qtype:<4}{C_RESET}] {C_DOMAIN}{query:<35}{C_RESET} -> {ans_str}")

def parse_ssl(row):
    server = row.get("server_name", "-")
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "443")
    version = row.get("version", "-")

    if server != "-" and resp_h != "-":
        cache_put(resp_h, server)

    server_disp = server
    if server == "-":
        # No SNI (e.g. local/mDNS TLS): fall back to the leaf certificate CN
        # via x509.log, best-effort — that row may land after this one, in
        # which case the plain '-' stands (no retry/reprint).
        fps = row.get("cert_chain_fps", "") or ""
        fp = fps.split(",")[0].strip()
        cn = x509_cn_get(fp) if fp and fp != "-" else None
        if cn:
            server_disp = f"cert:{cn}"

    ts = get_time(row.get("ts"))
    emit("ssl", f"{C_TIME}{ts}{C_RESET} {C_SSL}[SSL/TLS]{C_RESET} {orig_h:<15} -> {resp_h}:{resp_p} ({C_DOMAIN}{server_disp:<30}{C_RESET}) [{C_META}{version}{C_RESET}]")


def parse_http(row):
    method = row.get("method", "-")
    host = row.get("host", "-")
    uri = row.get("uri", "-")
    status = row.get("status_code", "-")
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")

    if host != "-" and resp_h != "-":
        cache_put(resp_h, host)

    ts = get_time(row.get("ts"))
    emit("http", f"{C_TIME}{ts}{C_RESET} {C_HTTP}[HTTP  ]{C_RESET} {orig_h:<15} {C_META}{method:<5}{C_RESET} http://{host}{uri[:40]} [{status}]")

def parse_quic(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "443")
    version = row.get("version", "-")
    server = row.get("server_name", "-")
    client_protocol = row.get("client_protocol", "-")

    # QUIC carries most modern traffic; its SNI feeds the IP->domain cache,
    # which is what fixes bare-IP CONN rows on udp/443.
    if server != "-" and resp_h != "-":
        cache_put(resp_h, server)

    ts = get_time(row.get("ts"))
    src = f"{orig_h}:{orig_p}" if orig_p else orig_h
    emit("quic", f"{C_TIME}{ts}{C_RESET} {C_QUIC}[QUIC  ]{C_RESET} {src:<15} -> {resp_h}:{resp_p} ({C_DOMAIN}{server:<30}{C_RESET}) [{C_META}v{version} {client_protocol}{C_RESET}]")

# Repeated identical Weird events (same name + destination) within this
# window are folded into the next line's "+N more" note instead of
# flooding the terminal. Note: if a burst never recurs after the window
# closes, its final tally is never flushed — acceptable trade-off for a
# live monitor; a periodic flush thread would be needed to close that gap.
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

    key = (name, resp_h)
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

    dst_info = "-"
    if resp_h != "-":
        domain = resolve_target(resp_h)
        dst_info = f"{resp_h}:{resp_p} ({C_DOMAIN}{domain}{C_RESET})"

    ts = get_time(row.get("ts"))
    src_info = f"{orig_h}:{orig_p}" if orig_p else orig_h
    detail = f" | Detail: {addl}" if addl and addl != "-" else ""
    repeat_note = (f" {C_TIME}(+{prior_count - 1} more suppressed in prior {int(WEIRD_DEDUP_WINDOW)}s){C_RESET}"
                   if prior_count > 1 else "")
    emit("weird", f"{C_TIME}{ts}{C_RESET} {C_WEIRD}[WEIRD ]{C_RESET} {src_info} -> {dst_info} | {C_WEIRD}{name}{C_RESET}{detail}{repeat_note}")

def parse_ntp(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    version = row.get("version", "-")
    mode = row.get("mode", "-")
    stratum = row.get("stratum", "-")

    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    emit("ntp", f"{C_TIME}{ts}{C_RESET} {C_NTP}[NTP   ]{C_RESET} {orig_h:<15} -> {resp_h:<15} ({C_DOMAIN}{domain:<28}{C_RESET}) [v{version} Stratum:{stratum} Mode:{mode}]")

def parse_ssh(row):
    orig_h = row.get("id.orig_h", "-")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "22")
    auth_success = row.get("auth_success", "-")
    server = row.get("server", "-")

    domain = resolve_target(resp_h)
    auth_badge = f"{C_CONN}SUCCESS{C_RESET}" if auth_success == "T" else (f"{C_NOTICE}FAILED{C_RESET}" if auth_success == "F" else "-")

    ts = get_time(row.get("ts"))
    emit("ssh", f"{C_TIME}{ts}{C_RESET} {C_SSH}[SSH   ]{C_RESET} {orig_h}:{orig_p} -> {resp_h}:{resp_p} ({C_DOMAIN}{domain:<25}{C_RESET}) Auth:{auth_badge} | Srv: {server[:25]}")

def parse_dhcp(row):
    client_addr = row.get("client_addr", row.get("assigned_ip", "-"))
    mac = row.get("mac", "-")
    host_name = row.get("host_name", "-")
    server_addr = row.get("server_addr", "-")
    msg_types = row.get("msg_types", "-")

    # Lease table feeds the IP->domain cache so LAN peers stop collapsing
    # to the generic LAN/Local label (resolve_target checks the cache first).
    if host_name and host_name != "-" and client_addr and client_addr != "-":
        try:
            ipaddress.ip_address(client_addr)
            cache_put(client_addr, host_name)
        except ValueError:
            pass

    ts = get_time(row.get("ts"))
    emit("dhcp", f"{C_TIME}{ts}{C_RESET} {C_DHCP}[DHCP  ]{C_RESET} Host: {C_DOMAIN}{host_name}{C_RESET} ({mac}) | IP: {client_addr} | Srv: {server_addr} [{msg_types}]")


def parse_software(row):
    host = row.get("host", "-")
    software_type = row.get("software_type", "-")
    name = row.get("name", "-")
    version = row.get("unparsed_version", "-")
    domain = resolve_target(host)

    ts = get_time(row.get("ts"))
    emit("software", f"{C_TIME}{ts}{C_RESET} {C_SOFTWR}[SOFTWR]{C_RESET} Host: {host} ({C_DOMAIN}{domain}{C_RESET}) | {software_type}: {C_META}{name}{C_RESET} v{version}")

def parse_x509(row):
    subject = row.get("certificate.subject", "-")
    issuer = row.get("certificate.issuer", "-")
    san_dns = row.get("san.dns", "-")

    cn_match = CN_RE.search(subject)
    if cn_match:
        cn = cn_match.group(1)
    elif san_dns != "-":
        cn = san_dns.split(",")[0]
    else:
        cn = "-"
    if cn and cn not in ("-", "(empty)"):
        x509_cn_put(row.get("fingerprint", "-"), cn)
    ts = get_time(row.get("ts"))
    emit("x509", f"{C_TIME}{ts}{C_RESET} {C_X509}[X509  ]{C_RESET} Cert CN: {C_DOMAIN}{cn:<30}{C_RESET} | Issuer: {issuer[:35]}")

def parse_dpd(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    proto = row.get("proto", "-")
    analyzer = row.get("analyzer", "-")
    failure_reason = row.get("failure_reason", "-")
    domain = resolve_target(resp_h)

    ts = get_time(row.get("ts"))
    emit("dpd", f"{C_TIME}{ts}{C_RESET} {C_DPD}[DPD   ]{C_RESET} {orig_h} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | Proto: {proto}/{analyzer} | Fail: {failure_reason}")

def parse_known_services(row):
    host = row.get("host", "-")
    port_num = row.get("port_num", "-")
    port_proto = row.get("port_proto", "")
    svc = row.get("service", "-")
    domain = resolve_target(host)
    proto_str = f"/{port_proto}" if port_proto and port_proto != "-" else ""

    ts = get_time(row.get("ts"))
    emit("known_services", f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[KNOWN-SVC]{C_RESET} Host: {host:<15} ({C_DOMAIN}{domain:<28}{C_RESET}) | Service: {port_num}{proto_str}/{svc}")

def parse_known_certs(row):
    host = row.get("host", "-")
    port_num = row.get("port_num", "-")
    subject = row.get("subject", "-")
    issuer = row.get("issuer_subject", row.get("issuer", "-"))
    serial = row.get("serial", "-")
    domain = resolve_target(host)
    cn_match = CN_RE.search(subject)
    cn = cn_match.group(1) if cn_match else subject[:30]

    ts = get_time(row.get("ts"))
    emit("known_certs", f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[KNOWN-CRT]{C_RESET} Host: {host}:{port_num} ({C_DOMAIN}{domain}{C_RESET}) | CN: {C_DOMAIN}{cn}{C_RESET} | Issuer: {issuer[:35]} | Serial: {serial}")

def parse_known_hosts(row):
    host = row.get("host", "-")
    domain = resolve_target(host)
    ts = get_time(row.get("ts"))
    emit("known_hosts", f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[KNOWN-HOST]{C_RESET} {host:<15} ({C_DOMAIN}{domain}{C_RESET})")

def parse_known_generic(log_type, row):
    host = row.get("host", "-")
    domain = resolve_target(host)
    svc = row.get("service", "")
    port_num = row.get("port_num", "")
    detail = f"| Service: {port_num}/{svc}" if svc else ""

    ts = get_time(row.get("ts"))
    emit(log_type, f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[{log_type.upper():<10}]{C_RESET} Host: {host:<15} ({C_DOMAIN}{domain:<28}{C_RESET}) {detail}")

def parse_notice(row):
    note = row.get("note", "Notice")
    msg = row.get("msg", "-")
    src = row.get("src", "-")
    dst = row.get("dst", "-")
    dst_dom = resolve_target(dst) if dst != "-" else "-"
    dst_info = f"{dst} ({dst_dom})" if dst != "-" else "-"

    ts = get_time(row.get("ts"))
    emit("notice", f"{C_TIME}{ts}{C_RESET} {C_NOTICE} [ALERT] {C_RESET} {C_META}{note}{C_RESET} | Src: {src} -> Dst: {dst_info} | {msg}")

def parse_files(row):
    source = row.get("source", "-")
    mime = row.get("mime_type", "-")
    filename = row.get("filename", "-")
    total_bytes = row.get("total_bytes", row.get("seen_bytes", "-"))
    size_str = format_bytes(total_bytes)

    if "x509" in mime or source == "SSL":
        label = f"[SSL Certificate] ({mime})"
    elif filename != "-":
        label = f"'{filename}' ({mime})"
    else:
        label = f"({mime})"

    ts = get_time(row.get("ts"))
    emit("files", f"{C_TIME}{ts}{C_RESET} {C_FILES}[FILES ]{C_RESET} {C_META}{source:<5}{C_RESET} {label:<45} {size_str}")


def parse_smtp(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    mailfrom = row.get("mailfrom", row.get("from", "-"))
    rcptto = row.get("rcptto", row.get("to", "-"))
    subject = row.get("subject", "-")
    tls = row.get("tls", "-")
    helo = row.get("helo", "-")
    domain = resolve_target(resp_h)
    tls_badge = f"{C_CONN}TLS{C_RESET}" if tls == "T" else f"{C_WEIRD}plain{C_RESET}"
    ts = get_time(row.get("ts"))
    subj_str = f" | Subj: {subject[:40]}" if subject and subject != "-" else ""
    emit("smtp", f"{C_TIME}{ts}{C_RESET} {C_HTTP}[SMTP  ]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) [{tls_badge}] From: {mailfrom} To: {rcptto}{subj_str}")


def parse_ftp(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    user = row.get("user", "-")
    command = row.get("command", "-")
    arg = row.get("arg", "-")
    reply_code = row.get("reply_code", "-")
    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    arg_str = f" {arg[:50]}" if arg and arg != "-" else ""
    emit("ftp", f"{C_TIME}{ts}{C_RESET} {C_HTTP}[FTP   ]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | User: {user} | {command}{arg_str} [{reply_code}]")


def parse_smb_files(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    action = row.get("action", "-")
    name = row.get("name", "-")
    path = row.get("path", "-")
    size = row.get("size", "-")
    domain = resolve_target(resp_h)
    size_str = format_bytes(size)
    ts = get_time(row.get("ts"))
    file_path = f"{path}\\{name}" if path != "-" and name != "-" else (name if name != "-" else path)
    emit("smb_files", f"{C_TIME}{ts}{C_RESET} {C_DPD}[SMB-F ]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | {action} {file_path[:50]} ({size_str})")


def parse_smb_mapping(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    path = row.get("path", "-")
    share_type = row.get("share_type", "-")
    native_file_system = row.get("native_file_system", "-")
    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    emit("smb_mapping", f"{C_TIME}{ts}{C_RESET} {C_DPD}[SMB-M ]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | Share: {path} [{share_type}] FS: {native_file_system}")


def parse_rdp(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "3389")
    cookie = row.get("cookie", "-")
    security_protocol = row.get("security_protocol", "-")
    cert_subject = row.get("cert.subject", row.get("subject", "-"))
    result = row.get("result", "-")
    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    cookie_str = f" | Cookie: {cookie}" if cookie and cookie != "-" else ""
    result_str = f" | Result: {result}" if result and result != "-" else ""
    emit("rdp", f"{C_TIME}{ts}{C_RESET} {C_SSH}[RDP   ]{C_RESET} {orig_h:<15} -> {resp_h}:{resp_p} ({C_DOMAIN}{domain}{C_RESET}) [{security_protocol}]{cookie_str}{result_str}")


def parse_tunnel(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    tunnel_type = row.get("tunnel_type", "-")
    action = row.get("action", "-")
    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    emit("tunnel", f"{C_TIME}{ts}{C_RESET} {C_QUIC}[TUNNEL]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | {tunnel_type} [{action}]")


def parse_radius(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    username = row.get("username", "-")
    result = row.get("result", "-")
    mac = row.get("mac", "-")
    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    result_badge = f"{C_CONN}OK{C_RESET}" if result == "success" else (f"{C_NOTICE}FAIL{C_RESET}" if result == "failed" else result)
    emit("radius", f"{C_TIME}{ts}{C_RESET} {C_DHCP}[RADIUS]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | User: {username} | {result_badge} | MAC: {mac}")


def parse_sip(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    method = row.get("method", "-")
    uri = row.get("uri", "-")
    status_code = row.get("status_code", "-")
    request_from = row.get("request_from", row.get("from", "-"))
    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    emit("sip", f"{C_TIME}{ts}{C_RESET} {C_NTP}[SIP   ]{C_RESET} {orig_h:<15} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | {method} {uri[:40]} [{status_code}] From: {request_from}")


# Repeated identical CONN events (same proto + destination) within this
# window are folded into the next line's "+N more" note instead of
# flooding the terminal (mDNS/keepalive chatter). Same accepted trade-off
# as weird.log folding: a burst that never recurs leaves its tally unflushed.
CONN_DEDUP_WINDOW = 30.0
_conn_state = {}
_conn_lock = threading.Lock()

def parse_conn(row):
    proto = row.get("proto", "").upper()
    orig_h = row.get("id.orig_h", "")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "")
    resp_p = row.get("id.resp_p", "")
    service = row.get("service", "-")
    state = row.get("conn_state", "-")
    duration = row.get("duration", "-")

    # Avoid duplicating rows covered by specialized protocol listeners;
    # QUIC gets its own colored line from quic.log.
    if resp_p in ("53", "5353") or service in ("dns", "ntp") or "quic" in service:
        return

    # --min-bytes / --min-duration gate before fold bookkeeping so counters
    # only ever track rows that would have been printable.
    try:
        total_bytes = int(row.get("orig_bytes", "0")) + int(row.get("resp_bytes", "0"))
    except ValueError:
        total_bytes = 0
    try:
        dur_val = float(duration)
    except ValueError:
        dur_val = 0.0
    if total_bytes < MIN_BYTES or dur_val < MIN_DURATION:
        return

    key = (proto, resp_h, resp_p)
    now = time.time()
    prior_count = 0
    with _conn_lock:
        st = _conn_state.get(key)
        if st is not None and (now - st["start"]) < CONN_DEDUP_WINDOW:
            st["count"] += 1
            return
        if st is not None:
            prior_count = st["count"]
        _conn_state[key] = {"start": now, "count": 1}

    domain = resolve_target(resp_h)
    record_remote_host(resp_h)
    record_bytes(int(row.get("orig_bytes", "0") if row.get("orig_bytes", "-") != "-" else "0"),
                 int(row.get("resp_bytes", "0") if row.get("resp_bytes", "-") != "-" else "0"))
    record_destination(domain, total_bytes)
    check_beaconing(orig_h, resp_h, resp_p)
    ts = get_time(row.get("ts"))
    src = f"{orig_h}:{orig_p}"
    dst = f"{resp_h}:{resp_p}"
    svc = service if service != "-" else resp_p
    dur_str = f"{float(duration):.2f}s" if duration != "-" else "-"
    state_label = CONN_STATE_LABELS.get(state, "")
    state_disp = f"{state}({state_label})" if state_label else state
    repeat_note = (f" {C_TIME}(+{prior_count - 1} more suppressed in prior {int(CONN_DEDUP_WINDOW)}s){C_RESET}"
                   if prior_count > 1 else "")
    emit("conn", f"{C_TIME}{ts}{C_RESET} {C_CONN}[CONN  ]{C_RESET} {proto:<4} {src:<21} -> {dst:<21} ({C_DOMAIN}{domain:<30}{C_RESET}) [{C_META}{svc:<5}{C_RESET}] {state_disp:<18} {dur_str}{repeat_note}")


def parse_generic(log_type, row):
    # Enriched fallback for any unexpected Zeek log
    ts = get_time(row.get("ts"))

    resp = row.get("id.resp_h", row.get("host", ""))
    target_info = ""
    if resp:
        dom = resolve_target(resp)
        target_info = f"[{resp} ({dom})] "

    # uid-ish noise (ports, proto, tunnel bookkeeping) stays out of the
    # summary now that dedicated parsers cover it; values are capped so a
    # stray blob can't blow up the line.
    fields = [
        f"{k}={str(v)[:40]}"
        for k, v in row.items()
        if k not in ("ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "host", "proto")
        and v != "-"
        and not k.startswith("tunnel")
    ]
    summary = " | ".join(fields[:3])
    emit(log_type, f"{C_TIME}{ts}{C_RESET} {C_OTHER}[{log_type.upper():<6}]{C_RESET} {target_info}{summary}")

HIDE_LAN_DST_FIELDS = {
    # Rows whose DESTINATION being an unnamed local address makes them LAN
    # chatter under --hide-lan. Enrichment-source types (dns/ssl/http/quic/
    # dhcp/x509/known_*) are exempt so caches keep filling.
    "conn": "id.resp_h",
    "weird": "id.resp_h",
    "ntp": "id.resp_h",
    "ssh": "id.resp_h",
    "dpd": "id.resp_h",
    "notice": "dst",
}

def process_row(log_type, row):
    if HIDE_LAN:
        dst_field = HIDE_LAN_DST_FIELDS.get(log_type)
        if dst_field and is_unnamed_local(row.get(dst_field, "-")):
            return
    if log_type == "dns": parse_dns(row)
    elif log_type == "ssl": parse_ssl(row)
    elif log_type == "http": parse_http(row)
    elif log_type == "quic": parse_quic(row)
    elif log_type == "weird": parse_weird(row)
    elif log_type == "ntp": parse_ntp(row)
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
    elif log_type == "conn": parse_conn(row)
    else: parse_generic(log_type, row)


# --- Log File Tailing & Discovery ---

IDLE_EXIT_SECONDS = 30 * 60  # release a file that's had no new data in 30 min
                              # (also bounds thread growth from old rotated-away logs)


def _read_header_and_tail(f, tail_n=5):
    """Stream the file once, keeping only the #fields header and the last
    N data lines, instead of loading the whole file into memory."""
    fields = []
    tail = deque(maxlen=tail_n)
    for raw in f:
        line = raw.rstrip("\n")
        if not line:
            continue
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#"):
            continue
        tail.append(line)
    return fields, tail


def _file_ino(f):
    st = os.fstat(f.fileno())
    return (st.st_dev, st.st_ino)


def _was_rotated(f, filepath, ident):
    """True if the path now points at a different inode (renamed/rotated),
    or the file shrank out from under our current read position (truncated)."""
    try:
        new_stat = os.stat(filepath)
    except OSError:
        return True
    if (new_stat.st_dev, new_stat.st_ino) != ident:
        return True
    if new_stat.st_size < f.tell():
        return True
    return False


def tail_file(filepath):
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
        fields, tail = _read_header_and_tail(f)
        for line in tail:
            values = line.split("\t")
            if len(values) == len(fields):
                process_row(log_type, dict(zip(fields, values)))
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


def log_watcher():
    while True:
        for filepath in glob.glob("*.log"):
            if os.path.basename(filepath) == "zeek-console.log":
                continue  # our own capture of Zeek's stderr, not a Zeek log
            with ACTIVE_THREADS_LOCK:
                already = filepath in ACTIVE_THREADS
                if not already:
                    ACTIVE_THREADS.add(filepath)
            if not already:
                t = threading.Thread(target=tail_file, args=(filepath,), daemon=True)
                t.start()
        time.sleep(1.0)


# --- Prerequisites & Zeek process management ---
ZEEK_MODE = "native"  # "native" or "docker"
DOCKER_CONTAINER_NAME = None


def ensure_zeek(no_install=False):
    global ZEEK_MODE
    # 1. Check if native zeek is already available on PATH or in /opt
    if shutil.which("zeek"):
        ZEEK_MODE = "native"
        return True
    for candidate in ["/opt/zeek/bin/zeek", "/opt/zeek-8.0/bin/zeek", "/usr/local/zeek/bin/zeek"]:
        if os.path.exists(candidate):
            os.environ["PATH"] = os.path.dirname(candidate) + ":" + os.environ.get("PATH", "")
            ZEEK_MODE = "native"
            return True

    # 2. Check if docker is available
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
        # Check architecture: OBS repo only provides amd64 / x86_64 packages
        if arch in ("x86_64", "amd64") and shutil.which("apt-get"):
            print(f"{C_META}[*] Zeek not found — configuring official Zeek repository...{C_RESET}")
            prefix = [] if os.geteuid() == 0 else ["sudo"]
            try:
                dist = "xUbuntu_22.04"
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
                subprocess.run(prefix + ["apt-get", "install", "-y", "zeek-8.0"], check=True)
                for candidate in ["/opt/zeek/bin/zeek", "/opt/zeek-8.0/bin/zeek"]:
                    if os.path.exists(candidate):
                        os.environ["PATH"] = os.path.dirname(candidate) + ":" + os.environ.get("PATH", "")
                        ZEEK_MODE = "native"
                        print(f"{C_CONN}[+] Zeek installed successfully.{C_RESET}")
                        return True
            except Exception as e:
                print(f"{C_WEIRD}[!] Native Zeek installation failed ({e}). Falling back to Docker...{C_RESET}")

        # ARM64 or Docker fallback
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
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=3)
            return iface in out.stdout.split()
        return os.path.exists(f"/sys/class/net/{iface}")
    except Exception:
        return True  # don't block startup on an uncertain check

def launch_zeek(args, work_dir):
    global DOCKER_CONTAINER_NAME

    # Zeek buffers log writes by default (Log::flush_interval) which can delay
    # output by seconds to minutes depending on traffic volume.  Write a small
    # tuning script that flushes every 0.1 s for near-real-time tailing.
    tuning_path = os.path.join(work_dir, "wirewatch-tuning.zeek")
    try:
        with open(tuning_path, "w") as tf:
            tf.write("# Auto-generated by Wirewatch — safe to delete.\n")
            tf.write("redef Log::flush_interval = 0.1 secs;\n")
    except OSError:
        tuning_path = None  # non-fatal — Zeek still works, just with its default lag

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

        # Remove any preexisting container with the same name
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
            if getattr(args, 'save_pcap', None):
                cmd.extend(["-w", os.path.basename(args.save_pcap)])

        if tuning_path:
            cmd.append("wirewatch-tuning.zeek")

    else:
        zeek_bin = shutil.which("zeek")
        if args.pcap:
            cmd = [zeek_bin, "-r", args.pcap]
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
            if getattr(args, 'save_pcap', None):
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
    time.sleep(2.0)  # let a bad interface / failed sudo auth fail fast
    rc = proc.poll()
    if rc is not None:
        if args.pcap:
            if rc == 0:
                return proc  # small pcap finished before we even checked — not a failure
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


# --- Startup info, session summary, periodic stats ---

def get_interface_info(iface):
    """Best-effort local IP and description for the capture interface."""
    ip_addr = "?"
    desc = ""
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["ifconfig", iface], capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    ip_addr = line.split()[1]
                    break
            # Try to get the interface type from networksetup
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
        else:  # Linux
            out = subprocess.run(["ip", "-4", "addr", "show", iface],
                                capture_output=True, text=True, timeout=3)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    ip_addr = line.split()[1].split("/")[0]
                    break
    except Exception:
        pass
    return ip_addr, desc


def flush_dedup_state():
    """Emit any remaining suppressed counts from dedup windows at exit."""
    with _weird_lock:
        for key, st in _weird_state.items():
            if st["count"] > 1:
                safe_print(f"{C_TIME}[~]{C_RESET} {C_WEIRD}[WEIRD ]{C_RESET} "
                           f"{key[0]} -> {key[1]}: +{st['count'] - 1} more suppressed at exit")
    with _conn_lock:
        for key, st in _conn_state.items():
            if st["count"] > 1:
                proto, resp_h, resp_p = key
                domain = resolve_target(resp_h)
                safe_print(f"{C_TIME}[~]{C_RESET} {C_CONN}[CONN  ]{C_RESET} "
                           f"{proto} -> {resp_h}:{resp_p} ({C_DOMAIN}{domain}{C_RESET}): "
                           f"+{st['count'] - 1} more suppressed at exit")


def print_session_summary():
    """Print a compact session summary on exit."""
    elapsed = time.time() - SESSION_START
    if elapsed < 1:
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
        bytes_in = SESSION_BYTES_IN
        bytes_out = SESSION_BYTES_OUT
    with UNIQUE_HOSTS_LOCK:
        n_remote = len(UNIQUE_REMOTE_HOSTS)

    total_events = sum(stats.values())
    if total_events == 0:
        return

    safe_print(f"")
    safe_print(f"{C_CONN}=== Session Summary ({dur_str}) ==={C_RESET}")
    safe_print(f"{C_META}  Unique remote hosts:  {C_RESET}{n_remote}")

    # Top destinations
    with TOP_DEST_LOCK:
        sorted_dests = sorted(TOP_DESTINATIONS.items(), key=lambda x: x[1]["bytes"], reverse=True)[:5]
    if sorted_dests:
        parts = [f"{d} ({e['conns']} conns)" for d, e in sorted_dests]
        safe_print(f"{C_META}  Top destinations:    {C_RESET}{', '.join(parts)}")

    # Protocol breakdown
    proto_parts = [f"{k.upper()}({v})" for k, v in sorted(stats.items(), key=lambda x: -x[1]) if v > 0]
    if proto_parts:
        safe_print(f"{C_META}  Events by type:      {C_RESET}{', '.join(proto_parts[:10])}")

    # Data volume
    safe_print(f"{C_META}  Data volume:         {C_RESET}{format_bytes(str(bytes_out))} sent, {format_bytes(str(bytes_in))} received")

    # Alerts & weird
    notice_count = stats.get("notice", 0)
    weird_count = stats.get("weird", 0)
    if notice_count:
        safe_print(f"{C_META}  Alerts/Notices:      {C_RESET}{C_NOTICE}{notice_count}{C_RESET}")
    if weird_count:
        safe_print(f"{C_META}  Weird events:        {C_RESET}{weird_count}")

    # Beaconing alerts
    with BEACON_LOCK:
        n_beacons = len(BEACON_ALERTED)
    if n_beacons:
        safe_print(f"{C_META}  Beaconing suspects:  {C_RESET}{C_NOTICE}{n_beacons}{C_RESET}")

    safe_print(f"")


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
        # Compute deltas
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
            f"{format_bytes(str(d_out))} out, {format_bytes(str(d_in))} in ---{C_RESET}"
        )


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
    as an interactive Ctrl+C — Python's default SIGTERM handling skips
    `finally` blocks entirely, which would otherwise orphan a root-owned
    Zeek process."""


def _handle_sigterm(signum, frame):
    raise _ShutdownSignal()


def main():
    signal.signal(signal.SIGTERM, _handle_sigterm)
    args = parse_args()
    configure_colors(resolve_color_setting(args.no_color))
    apply_filters(args.only, args.exclude)
    apply_display_filters(args)
    global SESSION_START
    SESSION_START = time.time()
    if getattr(args, 'watchlist', None):
        load_watchlist(args.watchlist)

    work_dir = os.path.abspath(os.path.expanduser(args.dir))
    os.makedirs(work_dir, exist_ok=True)

    zeek_proc = None
    used_sudo = not args.pcap
    if not args.attach_only:
        if not ensure_zeek(no_install=args.no_install):
            sys.exit(1)
        zeek_proc = launch_zeek(args, work_dir)
        if zeek_proc is None:
            sys.exit(1)

    os.chdir(work_dir)

    print(f"\n{C_CONN}=== Wirewatch — Zeek Omni-Monitor ==={C_RESET}")
    safe_print(f"{C_META}Watching directory: {work_dir}{C_RESET}")
    if zeek_proc is not None:
        if args.pcap:
            label = f"pcap {args.pcap}"
        else:
            ip_addr, iface_desc = get_interface_info(args.iface)
            desc_str = f", {iface_desc}" if iface_desc else ""
            label = f"interface {args.iface}{desc_str}, {ip_addr}"
        print(f"{C_CONN}[+] Zeek capture started (pid {zeek_proc.pid}, {label}){C_RESET}")
        if getattr(args, 'save_pcap', None):
            print(f"{C_CONN}[+] Also saving raw packets to: {args.save_pcap}{C_RESET}")
        print()
    else:
        print(f"{C_META}[i] Attach-only mode — expecting Zeek logs to appear in this directory.{C_RESET}\n")

    existing = [p for p in glob.glob("*.log") if os.path.basename(p) != "zeek-console.log"]
    if existing:
        safe_print(f"{C_META}Found existing logs: {', '.join(existing)}{C_RESET}\n")

    watcher_thread = threading.Thread(target=log_watcher, daemon=True)
    watcher_thread.start()

    if STATS_INTERVAL > 0:
        stats_thread = threading.Thread(target=periodic_stats_worker, daemon=True)
        stats_thread.start()

    try:
        while True:
            if zeek_proc is not None:
                rc = zeek_proc.poll()
                if rc is not None:
                    if args.pcap:
                        safe_print(f"{C_CONN}[+] Finished reading pcap (exit {rc}).{C_RESET}")
                        time.sleep(2)
                    else:
                        safe_print(f"{C_NOTICE}[!] Zeek exited (code {rc}). Capture has stopped.{C_RESET}")
                    break
            time.sleep(1)
    except (KeyboardInterrupt, _ShutdownSignal):
        pass
    finally:
        if zeek_proc is not None and zeek_proc.poll() is None:
            stop_zeek(zeek_proc, used_sudo)
        flush_dedup_state()
        print_dropped_summary()
        print_session_summary()
        print(f"{C_META}Exiting Wirewatch.{C_RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C_META}Exiting Wirewatch.{C_RESET}")
