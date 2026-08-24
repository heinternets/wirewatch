# Wirewatch — Zeek Omni-Monitor

A real-time, enriched, color-coded output monitor for Zeek, for macOS and Linux.

It cross-references DNS answers and TLS SNI names against every other log in real time, so
raw IPs in `conn.log`, `weird.log`, `known_services.log`, etc. show up labeled with the domain
that was actually seen talking to them — instead of a wall of bare IP addresses.

## Quick start

```
curl -fsSL https://wirewatch.net/install.sh | bash
```

That one command detects your OS, installs anything missing (Homebrew/apt,
Python 3, Zeek), downloads the latest Wirewatch, detects your active network
interface, and starts the capture.

Or run from source:

```
python3 wirewatch.py
```

From source, that one command:
1. Checks for Zeek and installs it via Homebrew/apt if it's missing.
2. Refreshes your sudo credentials (`sudo -v`, you'll be prompted for your password), then
   starts `zeek -i en0` non-interactively with all of its output redirected away from your
   terminal, so the capture can't interfere with the display.
3. Starts tailing and enriching every `*.log` file Zeek produces.

Press `Ctrl+C` to stop — Wirewatch will stop the Zeek capture for you (you may be asked for
your sudo password a second time to do that, unless it's still cached from step 2).



## Prerequisites

- None to speak of: `curl`, a terminal, and sudo access. The installer handles
  Homebrew/apt, Python 3, and Zeek automatically on macOS and Debian-family Linux.
- On other platforms, install Zeek yourself (see [zeek.org/get-zeek](https://zeek.org/get-zeek/))
  and either run it manually and use `--attach-only` below, or open an issue if you'd like
  native support for your platform.

## Usage

```
python3 wirewatch.py [options]

  -i, --iface IFACE   Network interface to capture on (default: en0)
  --dir DIR           Directory to run Zeek in / watch for logs (default: current directory)
  --only TYPES         Comma-separated log types to show exclusively, e.g. dns,http,ssl
  --exclude TYPES       Comma-separated log types to hide, e.g. ntp,dhcp
  --no-color            Disable ANSI colors (auto-disabled anyway when output isn't a terminal,
                        or when the NO_COLOR env var is set)
  --pcap FILE           Read from a pcap file instead of a live capture (no sudo needed)
  --attach-only         Don't launch Zeek — just watch --dir for logs from a Zeek process you
                        started yourself (this was the old default behavior)
  --no-install          Don't try to auto-install Zeek if it's missing
```

Examples:

```
python3 wirewatch.py -i en1                     # capture on a different interface
python3 wirewatch.py --only dns,http,ssl        # just web + DNS traffic
python3 wirewatch.py --exclude ntp,dhcp         # hide the noisy background chatter
python3 wirewatch.py --pcap sample.pcap         # analyze a capture file, no sudo required
python3 wirewatch.py --attach-only --dir ~/logs # tail logs from an existing zeekctl deployment
```

## Distribution & hosting notes

Wirewatch is distributed from [wirewatch.net](https://wirewatch.net), a static site on Azure
Static Web Apps that serves `index.html`, `install.sh`, and `wirewatch.py` straight out of this
repository (staged by `.github/workflows/deploy.yml` on every push to `main`). The scripts are
always the latest committed version — no manual uploads.

Why the one-liner is `curl ... | bash` rather than `curl ... | python3`: the installer script
reattaches stdin to `/dev/tty` before anything needs a password prompt, so `sudo` still talks to
your terminal even though bash itself was piped a network stream. Piping straight into a Python
interpreter would leave no terminal stdin at all for the same reason — which is why the installer
downloads `wirewatch.py` first and then runs it as its own process.

### Deploying the site

1. Push this repo to GitHub (`main` branch).
2. Create the Static Web App (Free plan):

```
az group create -n rg-wirewatch -l eastus2
az staticwebapp create -n wirewatch -g rg-wirewatch -s <org>/wirewatch -b main --sku Free
```

3. Add the deployment token as a repository secret if the app wasn't linked to the repo at
   creation time:

```
az staticwebapp secrets list -n wirewatch -g rg-wirewatch \
  --query "properties.apiKey" -o tsv | gh secret set AZURE_STATIC_WEB_APPS_API_TOKEN -R <org>/wirewatch
```

4. Point `wirewatch.net` at the app (Free plan allows 2 custom domains):

```
az staticwebapp hostname set -n wirewatch -g rg-wirewatch --hostname wirewatch.net
```

   then create the DNS record your registrar asks for (CNAME/ALIAS to the app's default
   `<name>.azurestaticapps.net` hostname, or a TXT validation record for an apex domain).
   TLS certificates are issued and renewed automatically.

## What's new since the original version

- Handles Zeek log rotation (reattaches automatically instead of going silent on a log type).
- Bounded, background (non-blocking) reverse-DNS resolution — the terminal never stalls waiting
  on a DNS lookup.
- `known_services.log`, `known_certs.log`, and `known_hosts.log` each get a dedicated, more
  useful format instead of being squeezed into one generic layout.
- Repeated identical `weird.log` events are collapsed with a "+N more suppressed" note instead
  of flooding the screen.
- Malformed/short lines are counted and flagged instead of silently vanishing.
- Every printed line is clamped to the terminal width (never soft-wraps), and mDNS/TXT
  record payloads are dropped from `dns.log` output — you see the query name, not
  hundreds of bytes of raw record data.
- Zeek is launched non-interactively (`sudo -n`, credentials refreshed up front via `sudo -v`)
  with all of its terminal streams redirected — it can neither write to your terminal nor
  change its settings while the capture runs, which is what caused randomly indented lines
  mid-session. Its stderr is captured to `zeek-console.log`.
