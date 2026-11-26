#!/usr/bin/env bash
# install.sh - install everything vuln-scanner needs (Rust toolchain, nmap, nuclei + templates).
#
# Usage: ./install.sh [options]
#   --check          only report what is installed / missing, change nothing
#   --dry-run        print what would be done, change nothing
#   -y, --yes        do not ask for confirmation
#   --prefix DIR     where to put downloaded binaries (default: ~/.local/bin)
#   --no-rust        skip the Rust toolchain
#   --no-nmap        skip nmap
#   --no-nuclei      skip nuclei and its templates
#   --build          run `cargo build --release` at the end
#   -h, --help       show this help
#
# System packages (nmap, curl, a C compiler, ...) are installed with your package manager via sudo.
# Rust goes to ~/.cargo (rustup), nuclei goes to --prefix; neither needs root.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PREFIX="${HOME}/.local/bin"
CHECK=0 DRY=0 YES=0 DO_RUST=1 DO_NMAP=1 DO_NUCLEI=1 DO_BUILD=0
NUCLEI_REPO="projectdiscovery/nuclei"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- output helpers ----------
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; N=$'\033[0m'; else B= G= R= Y= N=; fi
info() { printf '%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*" >&2; }
bad()  { printf '  %s✘%s %s\n' "$R" "$N" "$*"; }
die()  { printf '%serror:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1 ;;
    --dry-run) DRY=1 ;;
    -y|--yes) YES=1 ;;
    --prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; PREFIX="$2"; shift ;;
    --no-rust) DO_RUST=0 ;;
    --no-nmap) DO_NMAP=0 ;;
    --no-nuclei) DO_NUCLEI=0 ;;
    --build) DO_BUILD=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

# ---------- environment detection ----------
OS="$(uname -s)"
ARCH_RAW="$(uname -m)"
case "$OS" in
  Linux)  NUCLEI_OS=linux ;;
  Darwin) NUCLEI_OS=macOS ;;
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
[ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env" || true
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
  . "${HOME}/.cargo/env"
  ok "Rust installed: $(cargo --version)"
}

install_nmap() {
  if have nmap; then ok "nmap already installed"; return; fi
  info "Installing nmap"
  confirm "Install nmap with $PM?" || { warn "skipped nmap"; return; }
  pkg_install nmap
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
[ "$DO_NUCLEI" -eq 1 ] && install_nuclei

if [ "$DO_BUILD" -eq 1 ]; then
  info "Building vuln-scanner (release)"
  have cargo || [ "$DRY" -eq 1 ] || die "cargo not found"
  (cd "$PROJECT_DIR" && run cargo build --release)
fi

echo
if [ "$DRY" -eq 0 ]; then
  print_status || warn "some components are still missing (see above)"
  echo
  echo "Add to your shell profile if needed:"
  echo "  export PATH=\"${PREFIX}:\$HOME/.cargo/bin:\$PATH\""
  echo
  echo "Run the scanner:  cd ${PROJECT_DIR} && cargo run --release -p vs-server   (http://127.0.0.1:8080)"
  echo "Scan targets outside loopback only after adding them to SCOPE, e.g. SCOPE=\"127.0.0.0/8,192.168.56.0/24\""
fi
