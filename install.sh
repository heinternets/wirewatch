#!/usr/bin/env bash
#
# Wirewatch bootstrap — https://wirewatch.net
#
# One-liner:
#   curl -fsSL https://wirewatch.net/install.sh | bash
#
# What it does:
#   1. Detects the OS (macOS / Debian-family Linux).
#   2. Installs prerequisites: Homebrew + Zeek + python3 (macOS) or
#      apt + Zeek + python3 (Ubuntu/Debian).
#   3. Downloads the latest wirewatch.py from this site.
#   4. Detects the active network interface and starts Wirewatch on it.
#
set -euo pipefail

BASE_URL="${WIREWATCH_BASE_URL:-https://wirewatch.net}"
INSTALL_DIR="${WIREWATCH_DIR:-$HOME/.wirewatch}"

log()  { printf '\033[96m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;38;5;208m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;41;97m[!] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null || die "curl is required but was not found."
command -v python3 >/dev/null || warn "python3 not found yet — will be installed with the prerequisites."


SUDO=""
if [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null; then
    SUDO="sudo"
fi

OS="$(uname -s)"
case "$OS" in
    Darwin)
        PKG="brew"
        ;;
    Linux)
        if [ -r /etc/os-release ]; then
            # shellcheck disable=SC1091
            . /etc/os-release
        fi
        case "${ID:-unknown}" in
            ubuntu|debian|linuxmint|pop|raspbian|kali)
                PKG="apt"
                ;;
            *)
                die "Unsupported Linux distribution '${PRETTY_NAME:-unknown}'.
    Wirewatch supports macOS (Homebrew) and Debian-family Linux (apt) automatically.
    For other platforms, install Zeek yourself (https://zeek.org/get-zeek/) and run:
      curl -fsSL ${BASE_URL}/wirewatch.py -o wirewatch.py && python3 wirewatch.py --attach-only"
                ;;
        esac
        ;;
    *)
        die "Unsupported operating system '$OS'. Wirewatch supports macOS and Debian-family Linux."
        ;;
esac

install_prereqs_brew() {
    if ! command -v brew >/dev/null; then
        log "Homebrew not found — installing (https://brew.sh)..."
        NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # New installs are not on PATH in the current shell yet.
        if [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"; fi
        if [ -x /usr/local/bin/brew ]; then eval "$(/usr/local/bin/brew shellenv)"; fi
        if [ -x /home/linuxbrew/.linuxbrew/bin/brew ]; then eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"; fi
    fi
    command -v brew >/dev/null || die "Homebrew installation failed — install it manually from https://brew.sh and re-run."

    if ! command -v python3 >/dev/null; then
        log "Installing python3 via Homebrew..."
        brew install python3
    fi

    if ! command -v zeek >/dev/null; then
        log "Installing Zeek via Homebrew (this can take a few minutes)..."
        brew install zeek
    fi
}

install_prereqs_apt() {
    export DEBIAN_FRONTEND=noninteractive
    log "Refreshing apt package lists..."
    $SUDO apt-get update -y

    ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
    case "$ARCH" in
        amd64|x86_64)
            # Zeek is not in Ubuntu's own archives. On amd64, use the Zeek
            # project's official OBS repository (per docs.zeek.org/install).
            local dist
            case "${ID:-}" in
                ubuntu|pop) dist="xUbuntu_${VERSION_ID}" ;;
                debian)     dist="Debian_${VERSION_ID%%.*}" ;;
                *) die "No Zeek apt repository for '${ID:-unknown}'. Install Zeek from https://zeek.org/get-zeek/ and re-run." ;;
            esac
            command -v gpg >/dev/null || $SUDO apt-get install -y gnupg
            log "Adding official Zeek package repository (${dist})..."
            echo "deb https://download.opensuse.org/repositories/security:/zeek/${dist}/ /" \
                | $SUDO tee /etc/apt/sources.list.d/security:zeek.list > /dev/null
            curl -fsSL "https://download.opensuse.org/repositories/security:zeek/${dist}/Release.key" \
                | gpg --dearmor | $SUDO tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
            $SUDO apt-get update -y
            log "Installing prerequisites: zeek-8.0, python3..."
            $SUDO apt-get install -y zeek-8.0 python3 ca-certificates curl
            # OBS packages install under /opt/zeek, on PATH only for new shells.
            if ! command -v zeek >/dev/null; then
                for d in /opt/zeek*/bin; do
                    if [ -x "$d/zeek" ]; then export PATH="$d:$PATH"; break; fi
                done
            fi
            command -v zeek >/dev/null || die "Zeek still not found after installation."
            ;;
        *)
            # The OBS repository publishes no arm64 packages. Use the official
            # multi-arch Zeek Docker image instead; Wirewatch runs in attach
            # mode tailing the container's logs (see run_docker_mode).
            if ! command -v docker >/dev/null; then
                log "Installing Docker (docker.io)..."
                $SUDO apt-get install -y docker.io
            fi
            docker info >/dev/null 2>&1 || { $SUDO systemctl start docker 2>/dev/null || true; }
            docker info >/dev/null 2>&1 || die "Docker is installed but not usable — ensure your user can run docker (e.g. 'sudo usermod -aG docker $USER', then log out and back in) and re-run."
            DOCKER_MODE=1
            log "Installing python3..."
            $SUDO apt-get install -y python3 ca-certificates curl
            ;;
    esac
}

run_docker_mode() {
    local logdir="$INSTALL_DIR/logs"
    mkdir -p "$logdir"
    docker rm -f wirewatch-zeek > /dev/null 2>&1 || true
    log "Pulling the official Zeek image (zeek/zeek:lts, first run only)..."
    docker run -d --name wirewatch-zeek --net=host \
        --cap-add=NET_RAW --cap-add=NET_ADMIN \
        -v "$logdir":/workdir -w /workdir \
        zeek/zeek:lts zeek -i "$IFACE" > /dev/null \
        || die "Couldn't start the Zeek container."
    trap 'docker rm -f wirewatch-zeek > /dev/null 2>&1' EXIT
    if [ -t 1 ]; then
        exec python3 "$INSTALL_DIR/wirewatch.py" --attach-only --dir "$logdir" "$@" < /dev/tty
    fi
    exec python3 "$INSTALL_DIR/wirewatch.py" --attach-only --dir "$logdir" "$@"
}

DOCKER_MODE=0

log "Detected OS: $OS ($PKG packaging)"

case "$PKG" in
    brew) install_prereqs_brew ;;
    apt)  install_prereqs_apt  ;;
esac
ok "Prerequisites ready."

detect_iface() {
    local iface=""
    case "$OS" in
        Darwin)
            iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
            [ -z "$iface" ] && iface="en0"
            ;;
        Linux)
            if command -v ip >/dev/null; then
                iface="$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')"
            fi
            if [ -z "$iface" ] && [ -d /sys/class/net ]; then
                for d in /sys/class/net/*; do
                    b="$(basename "$d")"
                    if [ "$b" != "lo" ]; then iface="$b"; break; fi
                done
            fi
            [ -z "$iface" ] && iface="eth0"
            ;;
    esac
    printf '%s' "$iface"
}

mkdir -p "$INSTALL_DIR"
log "Downloading latest wirewatch.py from ${BASE_URL}..."
curl -fsSL "$BASE_URL/wirewatch.py" -o "$INSTALL_DIR/wirewatch.py"

IFACE="$(detect_iface)"
ok "Active network interface detected: $IFACE"

if [ "$DOCKER_MODE" = "1" ]; then
    log "Starting Wirewatch in Docker mode — Zeek runs in a container, Wirewatch tails its logs. Press Ctrl+C to stop."
    run_docker_mode "$@"
fi

log "Starting Wirewatch on '$IFACE' — press Ctrl+C to stop. You may be prompted for your sudo password."

# The final launch gets terminal stdin explicitly. When piped
# (`curl ... | bash`), the script's stdin is the network stream, and sudo
# inside wirewatch.py prompts on /dev/tty regardless — but Python's stdin
# should be your terminal so Ctrl+C and any interactive prompt behave.
if [ -t 1 ]; then
    exec python3 "$INSTALL_DIR/wirewatch.py" -i "$IFACE" "$@" < /dev/tty
else
    exec python3 "$INSTALL_DIR/wirewatch.py" -i "$IFACE" "$@"
fi
