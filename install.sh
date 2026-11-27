#!/usr/bin/env bash
# install.sh - install everything vuln-scanner needs, then start the portal.
#
# Default (no options): install Rust, rustscan, vuls, nuclei + templates WITHOUT asking,
# put the tools on PATH (this session and ~/.bashrc / ~/.zshrc), build, and run the server.
#
# Usage: ./install.sh [options]
#   --scope VALUE    SCOPE for the server: "any", or e.g. "127.0.0.0/8,192.168.1.0/24"
#                    (default: $SCOPE if set, otherwise "any" = scan any target; use --scope "127.0.0.0/8,::1" to restrict)
#   --no-run         install only, do not start the portal
#   --ask            ask for confirmation before each install step
#   --check          only report what is installed / missing, change nothing
#   --dry-run        print what would be done, change nothing
#   --prefix DIR     where to put downloaded binaries (default: ~/.local/bin)
#   --no-rust        skip the Rust toolchain
#   --with-nmap      also install nmap (optional; the built-in Rust portscan is the default)
#   --no-rustscan    skip RustScan (the default port scanner)
#   --no-vuls        skip Vuls (deep scan over SSH; its ~15 GB vulnerability DB downloads on first use)
#   --no-nuclei      skip nuclei and its templates
#   -y, --yes        accepted for compatibility (already the default)
#   -h, --help       show this help
#
# System packages (nmap, curl, a C compiler, ...) are installed with your package manager via sudo.
# Rust goes to ~/.cargo (rustup), nuclei goes to --prefix; neither needs root.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PREFIX="${HOME}/.local/bin"
CHECK=0 DRY=0 YES=1 DO_RUST=1 DO_NMAP=0 DO_RUSTSCAN=1 DO_VULS=1 DO_NUCLEI=1 DO_RUN=1
SCOPE_ARG="${SCOPE:-any}"
NUCLEI_REPO="projectdiscovery/nuclei"
VULS_REPO="future-architect/vuls"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- output helpers ----------
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; N=$'\033[0m'; else B= G= R= Y= N=; fi
info() { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
bad()  { printf '  %s✘%s %s\n' "$R" "$N" "$*"; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1 ;;
    --dry-run) DRY=1 ;;
    -y|--yes) YES=1 ;;
    --ask) YES=0 ;;
    --no-run) DO_RUN=0 ;;
    --scope) [ $# -ge 2 ] || die "--scope needs a value"; SCOPE_ARG="$2"; shift ;;
    --prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; PREFIX="$2"; shift ;;
    --no-rust) DO_RUST=0 ;;
    --with-nmap) DO_NMAP=1 ;;
    --no-nmap) DO_NMAP=0 ;;
    --no-rustscan) DO_RUSTSCAN=0 ;;
    --no-vuls) DO_VULS=0 ;;
    --no-nuclei) DO_NUCLEI=0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# ---------- environment detection ----------
OS="$(uname -s)"
ARCH_RAW="$(uname -m)"
case "$OS" in
  Linux)  NUCLEI_OS=linux;  VULS_OS=linux ;;
  Darwin) NUCLEI_OS=macOS;  VULS_OS=darwin ;;
  *) die "unsupported OS: $OS (Linux and macOS only)" ;;
esac
case "$ARCH_RAW" in
  x86_64|amd64)  NUCLEI_ARCH=amd64 ;;
  aarch64|arm64) NUCLEI_ARCH=arm64 ;;
  armv7l|armv6l) NUCLEI_ARCH=arm ;;
  i386|i686)     NUCLEI_ARCH=386 ;;
  *) die "unsupported CPU architecture: $ARCH_RAW" ;;
esac

PM=""
for p in apt-get dnf yum pacman zypper apk brew; do
  if command -v "$p" >/dev/null 2>&1; then PM="$p"; break; fi
done

SUDO=""
if [ "$(id -u)" -ne 0 ] && [ "$PM" != "brew" ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
fi

have() { command -v "$1" >/dev/null 2>&1; }
# `cargo` may live in ~/.cargo/bin without being on PATH yet.
CARGO_ENV="${CARGO_HOME:-${HOME}/.cargo}/env"
[ -f "$CARGO_ENV" ] && . "$CARGO_ENV" || true
export PATH="${PREFIX}:${PATH}"

run() {
  if [ "$DRY" -eq 1 ]; then printf '  [dry-run] %s\n' "$*"; return 0; fi
  "$@"
}

confirm() {
  [ "$YES" -eq 1 ] || [ "$DRY" -eq 1 ] && return 0
  [ -t 0 ] || die "not a terminal; re-run with --yes to proceed non-interactively"
  read -r -p "  $1 [y/N] " a
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

pkg_install() { # pkg_install <pkg>...  (names are for the detected package manager)
  [ -n "$PM" ] || die "no supported package manager found; install manually: $*"
  if [ "$PM" != "brew" ] && [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
    die "need root to install packages ($*) but sudo is not available"
  fi
  case "$PM" in
    apt-get) run $SUDO apt-get update -qq; run $SUDO apt-get install -y "$@" ;;
    dnf)     run $SUDO dnf install -y "$@" ;;
    yum)     run $SUDO yum install -y "$@" ;;
    pacman)  run $SUDO pacman -S --needed --noconfirm "$@" ;;
    zypper)  run $SUDO zypper --non-interactive install "$@" ;;
    apk)     run $SUDO apk add "$@" ;;
    brew)    run brew install "$@" ;;
  esac
}

# ---------- status ----------
print_status() {
  info "Status"
  local missing=0
  for t in curl cc; do
    if have "$t"; then ok "$t"; else bad "$t (missing)"; missing=1; fi
  done
  if have unzip || have python3; then ok "unzip/python3"; else bad "unzip or python3 (missing)"; missing=1; fi
  if [ "$DO_RUST" -eq 1 ]; then
    if have cargo; then ok "cargo: $(cargo --version)"; else bad "cargo (missing)"; missing=1; fi
  fi
  if [ "$DO_NMAP" -eq 1 ]; then
    if have nmap; then ok "nmap: $(nmap --version | head -1)"; else bad "nmap (missing)"; missing=1; fi
  fi
  if [ "$DO_RUSTSCAN" -eq 1 ]; then
    if have rustscan; then ok "rustscan: $(rustscan --version 2>&1 | head -1)"; else bad "rustscan (missing)"; missing=1; fi
  fi
  if [ "$DO_VULS" -eq 1 ]; then
    if have vuls; then ok "vuls: $(vuls -v 2>&1 | head -1 | cut -c1-40)"; else bad "vuls (missing)"; missing=1; fi
    if have ssh && have ssh-keyscan && have ssh-keygen; then ok "openssh client (needed by deep scan)"; else bad "openssh client: ssh, ssh-keyscan, ssh-keygen (missing)"; missing=1; fi
  fi
  if [ "$DO_NUCLEI" -eq 1 ]; then
    if have nuclei; then
      ok "nuclei: $(nuclei -version 2>&1 | grep -io 'v[0-9][0-9.]*' | head -1)"
      if [ -d "${HOME}/nuclei-templates" ] || [ -d "${HOME}/.local/nuclei-templates" ]; then ok "nuclei templates"; else bad "nuclei templates (missing)"; missing=1; fi
    else
      bad "nuclei (missing)"; missing=1
    fi
  fi
  return "$missing"
}

if [ "$CHECK" -eq 1 ]; then
  if print_status; then exit 0; else exit 1; fi
fi

extract_zip() { # extract_zip <zip> <dir>
  if have unzip; then unzip -q -o "$1" -d "$2"
  elif have python3; then python3 -m zipfile -e "$1" "$2"
  else die "need unzip or python3 to extract $1"; fi
}

# ---------- installers ----------
install_base() {
  local need=()
  have curl || need+=(curl)
  have unzip || have python3 || need+=(unzip)
  have cc || need+=("$(case "$PM" in apt-get) echo build-essential ;; dnf|yum) echo gcc ;; pacman) echo base-devel ;; zypper) echo gcc ;; apk) echo build-base ;; brew) echo "" ;; esac)")
  # drop empty entries (brew: Xcode CLT provides cc)
  local pk=(); for x in "${need[@]:-}"; do [ -n "$x" ] && pk+=("$x"); done
  if [ "${#pk[@]}" -gt 0 ]; then
    info "Installing base packages: ${pk[*]}"
    confirm "Install ${pk[*]} with $PM?" || die "base packages are required"
    pkg_install "${pk[@]}"
  fi
  have cc || [ "$DRY" -eq 1 ] || [ "$PM" != "brew" ] || warn "no C compiler: run 'xcode-select --install'"
}

install_rust() {
  if have cargo; then ok "Rust already installed ($(cargo --version))"; return; fi
  info "Installing Rust via rustup (to ~/.cargo, no root)"
  confirm "Download and run the official rustup installer from sh.rustup.rs?" || { warn "skipped Rust"; return; }
  if [ "$DRY" -eq 1 ]; then echo "  [dry-run] curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal -c clippy"; return; fi
  local tmp; tmp="$(mktemp)"
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$tmp"
  sh "$tmp" -y --profile minimal -c clippy
  rm -f "$tmp"
  CARGO_ENV="${CARGO_HOME:-${HOME}/.cargo}/env"
  . "$CARGO_ENV"
  ok "Rust installed: $(cargo --version)"
}

install_nmap() {
  if have nmap; then ok "nmap already installed"; return; fi
  info "Installing nmap"
  confirm "Install nmap with $PM?" || { warn "skipped nmap"; return; }
  pkg_install nmap
}

install_rustscan() {
  info "Installing rustscan"
  if have rustscan; then ok "rustscan already installed"; return; fi
  have cargo || { warn "rustscan needs cargo (do not pass --no-rust)"; return; }
  confirm "Install rustscan with cargo (into ~/.cargo/bin)?" || { warn "skipped rustscan"; return; }
  run cargo install rustscan
}

install_vuls() {
  info "Installing vuls"
  if have vuls; then ok "vuls already installed"; return; fi
  confirm "Download vuls from github.com/${VULS_REPO} into ${PREFIX}?" || { warn "skipped vuls"; return; }
  if [ "$DRY" -eq 1 ]; then
    echo "  [dry-run] resolve latest release of ${VULS_REPO}, download vuls_<ver>_${VULS_OS}_${NUCLEI_ARCH}.tar.gz, verify sha256, install to ${PREFIX}"
    return
  fi
  case "$NUCLEI_ARCH" in amd64|arm64) ;; *) warn "no prebuilt vuls for ${ARCH_RAW}; skipped"; return ;; esac
  local tag ver tmp tgz sums want got
  tag="$(curl -fsSL "https://api.github.com/repos/${VULS_REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$tag" ] || die "could not determine the latest vuls release (GitHub API rate limit?)"
  ver="${tag#v}"
  tgz="vuls_${ver}_${VULS_OS}_${NUCLEI_ARCH}.tar.gz"
  sums="vuls_${ver}_checksums.txt"
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/${tgz}" "https://github.com/${VULS_REPO}/releases/download/${tag}/${tgz}"
  curl -fsSL -o "${tmp}/${sums}" "https://github.com/${VULS_REPO}/releases/download/${tag}/${sums}"
  want="$(awk -v f="$tgz" '$2==f {print $1}' "${tmp}/${sums}")"
  [ -n "$want" ] || die "no checksum for ${tgz} in ${sums}"
  if have sha256sum; then got="$(sha256sum "${tmp}/${tgz}" | awk '{print $1}')"; else got="$(shasum -a 256 "${tmp}/${tgz}" | awk '{print $1}')"; fi
  [ "$want" = "$got" ] || die "checksum mismatch for ${tgz} (expected ${want}, got ${got})"
  ok "checksum verified"
  mkdir -p "$PREFIX"
  tar -xzf "${tmp}/${tgz}" -C "$tmp" vuls
  install -m 0755 "${tmp}/vuls" "${PREFIX}/vuls"
  rm -rf "$tmp"
  ok "vuls ${ver} installed to ${PREFIX}/vuls"
  warn "the vulnerability DB (~15 GB) is downloaded by the first deep scan into ~/.local/share/vuln-scanner/vuls.db"
}

install_nuclei() {
  info "Installing nuclei"
  if have nuclei; then
    ok "nuclei already installed"
  else
    confirm "Download nuclei from github.com/${NUCLEI_REPO} into ${PREFIX}?" || { warn "skipped nuclei"; return; }
    if [ "$DRY" -eq 1 ]; then
      echo "  [dry-run] resolve latest release of ${NUCLEI_REPO}, download nuclei_<ver>_${NUCLEI_OS}_${NUCLEI_ARCH}.zip, verify sha256, install to ${PREFIX}"
      return
    fi
    local tag ver tmp zip sums want got
    tag="$(curl -fsSL "https://api.github.com/repos/${NUCLEI_REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$tag" ] || die "could not determine the latest nuclei release (GitHub API rate limit?)"
    ver="${tag#v}"
    zip="nuclei_${ver}_${NUCLEI_OS}_${NUCLEI_ARCH}.zip"
    sums="nuclei_${ver}_checksums.txt"
    tmp="$(mktemp -d)"
    curl -fsSL -o "${tmp}/${zip}" "https://github.com/${NUCLEI_REPO}/releases/download/${tag}/${zip}"
    curl -fsSL -o "${tmp}/${sums}" "https://github.com/${NUCLEI_REPO}/releases/download/${tag}/${sums}"
    want="$(awk -v f="$zip" '$2==f {print $1}' "${tmp}/${sums}")"
    [ -n "$want" ] || die "no checksum for ${zip} in ${sums}"
    if have sha256sum; then got="$(sha256sum "${tmp}/${zip}" | awk '{print $1}')"; else got="$(shasum -a 256 "${tmp}/${zip}" | awk '{print $1}')"; fi
    [ "$want" = "$got" ] || die "checksum mismatch for ${zip} (expected ${want}, got ${got})"
    ok "checksum verified"
    mkdir -p "$PREFIX"
    extract_zip "${tmp}/${zip}" "$tmp"
    install -m 0755 "${tmp}/nuclei" "${PREFIX}/nuclei"
    rm -rf "$tmp"
    ok "nuclei ${ver} installed to ${PREFIX}/nuclei"
  fi
  if [ "$DRY" -eq 1 ]; then echo "  [dry-run] nuclei -update-templates"; return; fi
  if have nuclei; then
    info "Updating nuclei templates"
    nuclei -update-templates -silent || warn "template update failed; run 'nuclei -update-templates' later"
  fi
}

# ---------- main ----------
info "vuln-scanner installer  (os=${OS} arch=${ARCH_RAW} pkg-manager=${PM:-none} prefix=${PREFIX})"
[ "$DRY" -eq 1 ] && warn "dry-run: nothing will be changed"

install_base
[ "$DO_RUST" -eq 1 ] && install_rust
[ "$DO_NMAP" -eq 1 ] && install_nmap
[ "$DO_RUSTSCAN" -eq 1 ] && install_rustscan
[ "$DO_VULS" -eq 1 ] && install_vuls
[ "$DO_NUCLEI" -eq 1 ] && install_nuclei

# Make the tools available to this script, to the server we are about to start, and to future shells.
export PATH="${PREFIX}:${HOME}/.cargo/bin:${PATH}"

persist_path() {
  local rc="${HOME}/.bashrc"
  case "${SHELL:-}" in *zsh) rc="${HOME}/.zshrc" ;; esac
  local marker="# added by vuln-scanner install.sh"
  if [ -f "$rc" ] && grep -qF "$marker" "$rc"; then
    ok "PATH already configured in $rc"
    return
  fi
  if [ "$DRY" -eq 1 ]; then echo "  [dry-run] append PATH export to $rc"; return; fi
  printf '\n%s\nexport PATH="%s:$HOME/.cargo/bin:$PATH"\n' "$marker" "$PREFIX" >> "$rc"
  ok "PATH added to $rc (open a new terminal, or run: source $rc)"
}

echo
info "Configuring PATH"
persist_path

if [ "$DRY" -eq 1 ]; then
  info "Would build and start the portal (cargo run --release -p vs-server)"
  exit 0
fi

echo
STATUS_OK=0
print_status || STATUS_OK=1

if [ "$DO_RUN" -eq 0 ]; then
  echo
  echo "Run later with:  cd ${PROJECT_DIR} && cargo run --release -p vs-server"
  exit "$STATUS_OK"
fi
if [ "$STATUS_OK" -ne 0 ]; then
  warn "some components are missing (see above); not starting the portal"
  exit 1
fi

echo
info "Building and starting the portal"
cd "$PROJECT_DIR"
if [ -n "$SCOPE_ARG" ]; then
  export SCOPE="$SCOPE_ARG"
  info "scope: $SCOPE"
  [ "$SCOPE" = "any" ] && warn "scope=any: the portal will accept ANY target. Only scan systems you are authorised to test; restrict with --scope \"127.0.0.0/8,::1,<your CIDR>\""
else
  warn "scope: loopback only (default). To scan other targets: ./install.sh --scope any   (or SCOPE=\"192.168.1.0/24\")"
fi
echo "  Portal: http://${BIND:-127.0.0.1:8080}   (Ctrl+C to stop)"
exec cargo run --release -p vs-server
