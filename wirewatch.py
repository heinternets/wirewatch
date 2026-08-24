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
C_DPD     = "\033[1;31m"      # Bright Red
C_KNOWN   = "\033[1;38;5;114m"# Soft Green
C_OTHER   = "\033[1;37m"      # Bright White
C_DOMAIN  = "\033[1;93m"      # Bold Yellow
C_META    = "\033[96m"        # Cyan — lifecycle/info messages
C_RESET   = "\033[0m"

CN_RE = re.compile(r"CN=([^,]+)")

socket.setdefaulttimeout(0.3)


def configure_colors(enabled):
    """Null out every color constant when colors are disabled (--no-color,
    NO_COLOR env var, or non-tty stdout) instead of threading a flag through
    every print call."""
    global C_TIME, C_DNS, C_SSL, C_HTTP, C_CONN, C_NOTICE, C_FILES, C_WEIRD
    global C_NTP, C_SSH, C_DHCP, C_SOFTWR, C_X509, C_DPD, C_KNOWN, C_OTHER
    global C_DOMAIN, C_META, C_RESET
    if enabled:
        return
    (C_TIME, C_DNS, C_SSL, C_HTTP, C_CONN, C_NOTICE, C_FILES, C_WEIRD,
     C_NTP, C_SSH, C_DHCP, C_SOFTWR, C_X509, C_DPD, C_KNOWN, C_OTHER,
     C_DOMAIN, C_META, C_RESET) = [""] * 19


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

    safe_print(f"{C_TIME}{ts}{C_RESET} {C_DNS}[DNS   ]{C_RESET} {orig_h:<15} asked [{C_META}{qtype:<4}{C_RESET}] {C_DOMAIN}{query:<35}{C_RESET} -> {ans_str}")

def parse_ssl(row):
    server = row.get("server_name", "-")
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    resp_p = row.get("id.resp_p", "443")
    version = row.get("version", "-")

    if server != "-" and resp_h != "-":
        cache_put(resp_h, server)

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_SSL}[SSL/TLS]{C_RESET} {orig_h:<15} -> {resp_h}:{resp_p} ({C_DOMAIN}{server:<30}{C_RESET}) [{C_META}{version}{C_RESET}]")

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
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_HTTP}[HTTP  ]{C_RESET} {orig_h:<15} {C_META}{method:<5}{C_RESET} http://{host}{uri[:40]} [{status}]")

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
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_WEIRD}[WEIRD ]{C_RESET} {src_info} -> {dst_info} | {C_WEIRD}{name}{C_RESET}{detail}{repeat_note}")

def parse_ntp(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    version = row.get("version", "-")
    mode = row.get("mode", "-")
    stratum = row.get("stratum", "-")

    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_NTP}[NTP   ]{C_RESET} {orig_h:<15} -> {resp_h:<15} ({C_DOMAIN}{domain:<28}{C_RESET}) [v{version} Stratum:{stratum} Mode:{mode}]")

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
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_SSH}[SSH   ]{C_RESET} {orig_h}:{orig_p} -> {resp_h}:{resp_p} ({C_DOMAIN}{domain:<25}{C_RESET}) Auth:{auth_badge} | Srv: {server[:25]}")

def parse_dhcp(row):
    client_addr = row.get("client_addr", row.get("assigned_ip", "-"))
    mac = row.get("mac", "-")
    host_name = row.get("host_name", "-")
    server_addr = row.get("server_addr", "-")
    msg_types = row.get("msg_types", "-")

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_DHCP}[DHCP  ]{C_RESET} Host: {C_DOMAIN}{host_name}{C_RESET} ({mac}) | IP: {client_addr} | Srv: {server_addr} [{msg_types}]")

def parse_software(row):
    host = row.get("host", "-")
    software_type = row.get("software_type", "-")
    name = row.get("name", "-")
    version = row.get("unparsed_version", "-")
    domain = resolve_target(host)

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_SOFTWR}[SOFTWR]{C_RESET} Host: {host} ({C_DOMAIN}{domain}{C_RESET}) | {software_type}: {C_META}{name}{C_RESET} v{version}")

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

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_X509}[X509  ]{C_RESET} Cert CN: {C_DOMAIN}{cn:<30}{C_RESET} | Issuer: {issuer[:35]}")

def parse_dpd(row):
    orig_h = row.get("id.orig_h", "-")
    resp_h = row.get("id.resp_h", "-")
    proto = row.get("proto", "-")
    analyzer = row.get("analyzer", "-")
    failure_reason = row.get("failure_reason", "-")
    domain = resolve_target(resp_h)

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_DPD}[DPD   ]{C_RESET} {orig_h} -> {resp_h} ({C_DOMAIN}{domain}{C_RESET}) | Proto: {proto}/{analyzer} | Fail: {failure_reason}")

def parse_known_services(row):
    host = row.get("host", "-")
    port_num = row.get("port_num", "-")
    port_proto = row.get("port_proto", "")
    svc = row.get("service", "-")
    domain = resolve_target(host)
    proto_str = f"/{port_proto}" if port_proto and port_proto != "-" else ""

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[KNOWN-SVC]{C_RESET} Host: {host:<15} ({C_DOMAIN}{domain:<28}{C_RESET}) | Service: {port_num}{proto_str}/{svc}")

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
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[KNOWN-CRT]{C_RESET} Host: {host}:{port_num} ({C_DOMAIN}{domain}{C_RESET}) | CN: {C_DOMAIN}{cn}{C_RESET} | Issuer: {issuer[:35]} | Serial: {serial}")

def parse_known_hosts(row):
    host = row.get("host", "-")
    domain = resolve_target(host)
    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[KNOWN-HOST]{C_RESET} {host:<15} ({C_DOMAIN}{domain}{C_RESET})")

def parse_known_generic(log_type, row):
    host = row.get("host", "-")
    domain = resolve_target(host)
    svc = row.get("service", "")
    port_num = row.get("port_num", "")
    detail = f"| Service: {port_num}/{svc}" if svc else ""

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_KNOWN}[{log_type.upper():<10}]{C_RESET} Host: {host:<15} ({C_DOMAIN}{domain:<28}{C_RESET}) {detail}")

def parse_notice(row):
    note = row.get("note", "Notice")
    msg = row.get("msg", "-")
    src = row.get("src", "-")
    dst = row.get("dst", "-")
    dst_dom = resolve_target(dst) if dst != "-" else "-"
    dst_info = f"{dst} ({dst_dom})" if dst != "-" else "-"

    ts = get_time(row.get("ts"))
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_NOTICE} [ALERT] {C_RESET} {C_META}{note}{C_RESET} | Src: {src} -> Dst: {dst_info} | {msg}")

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
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_FILES}[FILES ]{C_RESET} {C_META}{source:<5}{C_RESET} {label:<45} {size_str}")

def parse_conn(row):
    proto = row.get("proto", "").upper()
    orig_h = row.get("id.orig_h", "")
    orig_p = row.get("id.orig_p", "")
    resp_h = row.get("id.resp_h", "")
    resp_p = row.get("id.resp_p", "")
    service = row.get("service", "-")
    state = row.get("conn_state", "-")
    duration = row.get("duration", "-")

    # Avoid duplicating rows covered by specialized protocol listeners
    if resp_p in ("53", "5353") or service in ("dns", "ntp"):
        return

    domain = resolve_target(resp_h)
    ts = get_time(row.get("ts"))
    src = f"{orig_h}:{orig_p}"
    dst = f"{resp_h}:{resp_p}"
    svc = service if service != "-" else resp_p
    dur_str = f"{float(duration):.2f}s" if duration != "-" else "-"

    safe_print(f"{C_TIME}{ts}{C_RESET} {C_CONN}[CONN  ]{C_RESET} {proto:<4} {src:<21} -> {dst:<21} ({C_DOMAIN}{domain:<30}{C_RESET}) [{C_META}{svc:<5}{C_RESET}] {state:<5} {dur_str}")

def parse_generic(log_type, row):
    # Enriched fallback for any unexpected Zeek log
    ts = get_time(row.get("ts"))

    resp = row.get("id.resp_h", row.get("host", ""))
    target_info = ""
    if resp:
        dom = resolve_target(resp)
        target_info = f"[{resp} ({dom})] "

    summary = " | ".join([f"{k}={v}" for k, v in list(row.items())[:3] if k not in ("ts", "uid", "id.orig_h", "id.resp_h", "host") and v != "-"])
    safe_print(f"{C_TIME}{ts}{C_RESET} {C_OTHER}[{log_type.upper():<6}]{C_RESET} {target_info}{summary}")

def process_row(log_type, row):
    if not type_allowed(log_type):
        return
    if log_type == "dns": parse_dns(row)
    elif log_type == "ssl": parse_ssl(row)
    elif log_type == "http": parse_http(row)
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

def ensure_zeek(no_install=False):
    if shutil.which("zeek"):
        return True
    if no_install:
        print(f"{C_NOTICE}[!] Zeek not found on PATH (--no-install set).{C_RESET}")
        return False

    system = platform.system()
    if system == "Darwin":
        if not shutil.which("brew"):
            print(f"{C_NOTICE}[!] Zeek not found, and Homebrew isn't installed.{C_RESET}")
            print(f"    Install Homebrew first: {C_DOMAIN}https://brew.sh{C_RESET}, then re-run this script.")
            return False
        print(f"{C_META}[*] Zeek not found — installing with 'brew install zeek' (this can take a few minutes)...{C_RESET}")
        install_cmd = ["brew", "install", "zeek"]
    elif system == "Linux" and shutil.which("apt-get"):
        print(f"{C_META}[*] Zeek not found — installing with 'apt-get install zeek' (this can take a few minutes)...{C_RESET}")
        prefix = [] if os.geteuid() == 0 else ["sudo"]
        install_cmd = prefix + ["apt-get", "install", "-y", "zeek"]
    else:
        print(f"{C_NOTICE}[!] Zeek not found on PATH.{C_RESET} Automatic install currently supports "
              f"macOS (Homebrew) and Debian-family Linux (apt).")
        print(f"    See {C_DOMAIN}https://zeek.org/get-zeek/{C_RESET} for install instructions, then re-run.")
        return False

    try:
        subprocess.run(install_cmd, check=True)
    except subprocess.CalledProcessError:
        print(f"{C_NOTICE}[!] Zeek installation failed. Install it manually and re-run.{C_RESET}")
        return False

    # Debian/Ubuntu package Zeek under /opt/zeek/bin, wired into PATH only
    # for new login shells — extend it for this process.
    if not shutil.which("zeek") and os.path.exists("/opt/zeek/bin/zeek"):
        os.environ["PATH"] = "/opt/zeek/bin:" + os.environ.get("PATH", "")

    if not shutil.which("zeek"):
        print(f"{C_NOTICE}[!] Installation reported success but 'zeek' still isn't on PATH "
              f"(you may need to restart your shell).{C_RESET}")
        return False

    print(f"{C_CONN}[+] Zeek installed successfully.{C_RESET}")
    return True


def interface_looks_valid(iface):
    try:
        if platform.system() == "Darwin":
            out = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=3)
            return iface in out.stdout.split()
        return os.path.exists(f"/sys/class/net/{iface}")
    except Exception:
        return True  # don't block startup on an uncertain check

def launch_zeek(args, work_dir):
    # Resolve the absolute path once: `sudo` scrubs PATH down to its own
    # secure_path, which misses Homebrew cells and Ubuntu's /opt/zeek/bin.
    zeek_bin = shutil.which("zeek")
    if args.pcap:
        cmd = [zeek_bin, "-r", args.pcap]
    else:
        if not interface_looks_valid(args.iface):
            print(f"{C_WEIRD}[!] Interface '{args.iface}' wasn't found on this system — "
                  f"continuing anyway, Zeek will report an error if it's wrong.{C_RESET}")
        # Refresh sudo credentials up front with a short-lived interactive
        # `sudo -v`. The capture itself then starts non-interactively and —
        # critically — in its own session (setsid), so the zeek/sudo pair
        # has NO controlling terminal and cannot touch ours mid-run.
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
    print(f"{C_META}[*] Starting Zeek: {' '.join(cmd)}{C_RESET}")
    # Zeek must NOT be able to write to (or reconfigure) our terminal: all
    # of its stdio is redirected — stdin/stdout discarded, stderr captured
    # to a log file. `sudo -n` can never stop to prompt, so it never touches
    # termios either. We deliberately stay in our session: macOS sudo binds
    # credential tickets to the controlling tty, and a detached (setsid)
    # capture couldn't see the ticket validated by `sudo -v` above.
    console_path = os.path.join(work_dir, "zeek-console.log")
    try:
        proc = subprocess.Popen(cmd, cwd=work_dir, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=open(console_path, "w"))
    except FileNotFoundError:
        print(f"{C_NOTICE}[!] Couldn't find 'zeek' on PATH. Aborting.{C_RESET}")
        return None
    time.sleep(1.5)  # let a bad interface / failed sudo auth fail fast
    rc = proc.poll()
    if rc is not None:
        if args.pcap:
            if rc == 0:
                return proc  # small pcap finished before we even checked — not a failure
            print(f"{C_NOTICE}[!] Zeek exited immediately while reading the pcap (code {rc}). "
                  f"See zeek-console.log for Zeek's output.{C_RESET}")
        else:
            print(f"{C_NOTICE}[!] Zeek exited immediately (code {rc}). "
                  f"Check the interface name and sudo access — see zeek-console.log for details.{C_RESET}")
        return None
    return proc


def stop_zeek(proc, used_sudo):
    if used_sudo:
        print(f"{C_META}[*] Stopping Zeek (pid {proc.pid})... you may be asked for your sudo password again.{C_RESET}")
        kill_cmds = [["sudo", "kill", str(proc.pid)], ["sudo", "kill", "-9", str(proc.pid)]]
    else:
        print(f"{C_META}[*] Stopping Zeek (pid {proc.pid})...{C_RESET}")
        kill_cmds = [["kill", str(proc.pid)], ["kill", "-9", str(proc.pid)]]

    for cmd in kill_cmds:
        try:
            subprocess.run(cmd, timeout=10)
            proc.wait(timeout=5)
            return
        except Exception:
            continue


# --- CLI & entry point ---

def parse_args():
    p = argparse.ArgumentParser(
        prog="wirewatch",
        description="One-command Zeek network monitor: checks prerequisites, starts Zeek, "
                    "and streams enriched, color-coded protocol output.",
    )
    p.add_argument("-i", "--iface", default="en0", help="Network interface to capture on (default: en0)")
    p.add_argument("--dir", default=".", help="Directory to run Zeek in / watch for logs (default: current directory)")
    p.add_argument("--only", help="Comma-separated log types to show exclusively, e.g. dns,http,ssl")
    p.add_argument("--exclude", help="Comma-separated log types to hide, e.g. ntp,dhcp")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    p.add_argument("--pcap", help="Read from a pcap file instead of live capture (no sudo needed)")
    p.add_argument("--attach-only", action="store_true",
                    help="Don't launch Zeek — just watch --dir for logs from a Zeek process you start yourself")
    p.add_argument("--no-install", action="store_true", help="Don't auto-install Zeek if it's missing")
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
        label = f"pcap {args.pcap}" if args.pcap else f"interface {args.iface}"
        print(f"{C_CONN}[+] Zeek capture started (pid {zeek_proc.pid}, {label}){C_RESET}\n")
    else:
        print(f"{C_META}[i] Attach-only mode — expecting Zeek logs to appear in this directory.{C_RESET}\n")

    existing = [p for p in glob.glob("*.log") if os.path.basename(p) != "zeek-console.log"]
    if existing:
        safe_print(f"{C_META}Found existing logs: {', '.join(existing)}{C_RESET}\n")

    watcher_thread = threading.Thread(target=log_watcher, daemon=True)
    watcher_thread.start()

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
        print_dropped_summary()
        print(f"{C_META}Exiting Wirewatch.{C_RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C_META}Exiting Wirewatch.{C_RESET}")
