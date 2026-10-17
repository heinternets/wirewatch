# Wirewatch

**Real-time, human-readable network intelligence in your terminal — powered by Zeek.**

Wirewatch turns Zeek's raw protocol logs into a single live, color-coded, cross-referenced stream on **macOS** and **Linux**. Instead of scrolling through walls of bare IP addresses, you immediately see **which local app** is talking, the **actual domain** behind shared CDN IPs, **first-seen destinations (`★ NEW`)**, **encrypted-DNS bypasses (`[No-DNS/DoH]`)**, and **traffic intent (`[AI]`, `[TELEM]`, `[OS/SYNC]`)**.

---

## Quick Start

Run with a single command (detects macOS/Linux, installs Zeek if missing, auto-selects your active network interface, and starts monitoring):

```bash
curl -fsSL https://wirewatch.net/install.sh | bash
```

Or run directly from source (zero Python dependencies — stdlib Python 3 only):

```bash
python3 wirewatch.py
```

---

## Live Terminal Output

```text
09:43:12 [DNS   ] Brave    ↗ :53      api.openai.com             [A   ] → 104.18.1.2, 104.18.2.2 (18ms) ★ NEW [AI]
09:43:12 [DNS   ] Cursor   ↗ :53      events.data.microsoft.com  [AAAA] → 2620:1ec:c11::200 [slow:245ms] ★ NEW [TELEM]
09:43:13 [DNS   ] mDNS     ↗ :5353    _companion-link._tcp.local [PTR ] → (PTR data) [Apple Continuity]
09:43:13 [TLS   ] Cursor   ↗ :443     api.openai.com             [TLSv13] (Let's Encrypt) [AI] 104.18.1.2
09:43:14 [TLS   ] Brave    ↗ :443     secret-blog.example.com    [TLSv13] [No-DNS/DoH] ★ NEW 104.18.1.2
09:43:14 [TLS   ] curl     ↗ :443     cert:legacy.internal.corp  [TLSv11] [EXPIRED-CERT] [DIRECT-IP] 185.220.101.7
09:43:15 [QUIC  ] Cursor   ↗ :443     events.data.microsoft.com  [h3] [TELEM] 2620:1ec..:200
09:43:16 [CONN  ] Cursor   ↗ tcp/443  api.openai.com             ↑1.4KB  ↓47.1KB SF(ok)        4.2s [AI]
09:43:18 [CONN  ] Brave    ↗ tcp/443  secret-blog.example.com    ↑2.5MB  ↓13.7KB SF(ok)        12.8s [↑ UPLOAD 2.5MB]
09:43:19 [CONN  ] IN       ↙ tcp/22   45.33.32.156               0B              REJ(rejected) 0.0s [DIRECT-IP]
━━━ MARK #1 at 09:43:20 (+8.0s: 10 events, ↑2.5MB ↓60.8KB) ━━━
```

### Reading a Row

Every protocol log is aligned to the same 5-column grid:

| Column | Example | Meaning |
| :--- | :--- | :--- |
| **1. Time** | `09:43:14` | Event timestamp |
| **2. Protocol** | `[TLS   ]` | Protocol / analyzer (`DNS`, `TLS`, `QUIC`, `HTTP`, `CONN`, `SSH`, `FILES`, `ALERT`, `WEIRD`) |
| **3. App & Direction** | `Brave    ↗ :443` | Local process name + direction (`↗` outbound, `↙` unsolicited inbound, `→` LAN peer) |
| **4. Target** | `secret-blog.example.com` | Authoritative domain name (preserving root TLD when truncated) or remote IP |
| **5. Insights** | `[TLSv13] [No-DNS/DoH] ★ NEW` | Protocol telemetry, byte volumes (`↑sent ↓rcvd`), and automated insight badges |

---

## Key Insights & Features

- **Local Process Attribution**: Maps active TCP/UDP sockets to the local application (`Brave`, `Cursor`, `Opera`, `Safari`, `curl`, `iCloud`) via fast non-blocking socket table scans (`netstat -anv` on macOS, `ss -tupn` on Linux).
- **Per-Connection (`uid`) CDN Correlation**: Correlates `ssl.log`, `quic.log`, `http.log`, and `conn.log` using Zeek's connection `uid` first before falling back to IP caches — eliminating domain mix-ups when multiple sites share the same Cloudflare, Fastly, or Google anycast IP.
- **DNS-Bypass (`[No-DNS/DoH]`) & Direct-IP (`[DIRECT-IP]`) Badges**:
  - `[No-DNS/DoH]` flags TLS/QUIC connections whose SNI hostname was never preceded by a local plaintext DNS query (e.g. browser DNS-over-HTTPS or hardcoded resolvers).
  - `[DIRECT-IP]` flags connections to public IPs with neither prior DNS resolution nor TLS SNI.
- **First-Seen Domain Novelty (`★ NEW`)**: Persists seen registrable base domains across runs in `.wirewatch-known.json` and highlights brand-new destinations with `★ NEW`.
- **Traffic Intent & Bonjour/mDNS Translation**: Badges `[AI]`, `[TELEM]`, and `[OS/SYNC]` endpoints and decodes cryptic local mDNS queries (`_companion-link._tcp.local` → `[Apple Continuity]`, `_airplay._tcp` → `[AirPlay]`, `_hap._tcp` → `[HomeKit]`).
- **Transfer Volume & Upload Anomaly Detection**: Shows `↑sent ↓rcvd` byte counts on `[CONN]` rows, highlights failed connection states (`S0`, `REJ`, `RSTO`), and flags heavy outbound transfers (`[↑ UPLOAD 2.5MB]`).
- **Smart Noise Folding**: Prioritizes resolved IPs ahead of CNAME chains in DNS answers, folds routine X.509 certificate chains into `[TLS]` (showing `(Let's Encrypt)` or alerting on `[EXPIRED-CERT]` / `[SELF-SIGNED]`), and deduplicates parallel browser socket bursts.

---

## Live Interactive Hotkeys

Press single keys at any time during a live capture without stopping Zeek:

| Key | Action | Description |
| :---: | :--- | :--- |
| `Space` / `p` | **Pause / Resume** | Freeze terminal scrolling to inspect lines; new events buffer in the background and flush on resume |
| `Enter` / `m` | **Drop Bookmark** | Print a bright `━━━ MARK #N ━━━` divider with elapsed time, event count, and `↑sent ↓rcvd` byte deltas |
| `s` | **Live Snapshot** | Print an on-demand summary of top destinations, active local apps, new domains, and categories |
| `n` | **Toggle Only-New** | Filter live output on the fly to show only `★ NEW` domains, alerts, and anomalies |
| `l` | **Toggle Hide-LAN** | Toggle suppression of unnamed local/LAN/mDNS chatter |
| `?` / `h` | **Help** | Print the interactive hotkey bar |
| `q` / `Ctrl+C` | **Quit** | Stop Zeek cleanly and print the full session summary |

---

## CLI Options

```text
python3 wirewatch.py [options]

Capture & Input:
  -i, --iface IFACE     Network interface to capture on (default: auto-detected active route)
  --dir DIR             Directory to run Zeek in / watch for logs (default: current directory)
  --pcap FILE           Read from a pcap file instead of live capture (no sudo needed)
  --save-pcap FILE      Also save raw packets to this pcap file (adds -w to Zeek)
  --attach-only         Watch --dir for logs from an already-running Zeek process
  --no-install          Don't auto-install Zeek if missing

Filtering & Display:
  --only-new            Only show newly seen domains (★ NEW), alerts, weird events & heavy uploads
  --hide-lan            Suppress unnamed LAN/mDNS/local traffic
  --only TYPES          Comma-separated log types to show exclusively (e.g. dns,http,ssl,conn)
  --exclude TYPES       Comma-separated log types to hide (e.g. ntp,dhcp)
  --match TEXT          Only show lines containing this substring (case-insensitive)
  --min-bytes N         Hide CONN rows with fewer than N bytes transferred (orig+resp)
  --min-duration S      Hide CONN rows shorter than S seconds
  --verbose             Show all raw x509 cert rows, SSL file entries, and parallel handshakes
  --no-procs            Disable local process/app attribution lookup
  --no-color            Disable ANSI colors (also respects NO_COLOR)

Monitoring & Alerts:
  --watchlist FILE      Newline-delimited file of domains, IPs, and CIDRs to flag with [WATCH]
  --alert-on PATTERN    Regex pattern — matching lines get a [!] highlight prefix
  --stats-interval SEC  Print a periodic traffic summary line every SEC seconds
```

### Common Examples

```bash
python3 wirewatch.py                              # Live capture on default active interface
python3 wirewatch.py --only-new                   # Watch only first-seen domains, alerts & uploads
python3 wirewatch.py --hide-lan --min-bytes 5000  # Focus on substantive external traffic
python3 wirewatch.py --only dns,ssl,conn          # Web & connection activity only
python3 wirewatch.py --pcap sample.pcap           # Analyze an existing pcap file (no sudo needed)
python3 wirewatch.py --watchlist iocs.txt         # Highlight matches against a custom watchlist
```

---

## Architecture & Hosting Notes

- **Zero external Python dependencies**: `wirewatch.py` is a single self-contained Python 3 script using only the standard library.
- **Terminal-safe Zeek execution**: Refreshes `sudo -v` credentials up front, then launches Zeek non-interactively (`sudo -n`) with its output redirected to `zeek-console.log` and a `0.1s` log flush interval (`wirewatch-tuning.zeek`).
- **Static distribution**: Hosted on [wirewatch.net](https://wirewatch.net) (Azure Static Web Apps), serving `index.html`, `install.sh`, and `wirewatch.py` directly from `main`.

<details>
<summary>Deploying <code>wirewatch.net</code> (Azure Static Web Apps)</summary>

1. Push this repo to GitHub (`main` branch).
2. Create the Static Web App (Free plan):
   ```bash
   az group create -n rg-wirewatch -l eastus2
   az staticwebapp create -n wirewatch -g rg-wirewatch -s <org>/wirewatch -b main --sku Free
   ```
3. Add the deployment token as a repository secret if not linked automatically:
   ```bash
   az staticwebapp secrets list -n wirewatch -g rg-wirewatch \
     --query "properties.apiKey" -o tsv | gh secret set AZURE_STATIC_WEB_APPS_API_TOKEN -R <org>/wirewatch
   ```
4. Point `wirewatch.net` at the app:
   ```bash
   az staticwebapp hostname set -n wirewatch -g rg-wirewatch --hostname wirewatch.net
   ```
</details>
