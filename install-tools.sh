#!/usr/bin/env bash
#
# install-tools.sh — installa i tool esterni elencati in tools.txt.
#
# Pensato per Kali / Debian / Ubuntu (apt). Idempotente: salta cio' che e'
# gia' nel PATH. Fa il bootstrap di Go se serve a installare i tool Go.
#
#   ./install-tools.sh            installa la categoria 'core'
#   ./install-tools.sh --all      core + docker + optional
#   ./install-tools.sh --docker   solo scanner per docker-configuration
#   ./install-tools.sh --optional solo i tool suggeriti (es. nuclei)
#   ./install-tools.sh --list     elenca lo stato (presente/mancante), non installa
#   ./install-tools.sh --help
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="$HERE/tools.txt"

# Categorie richieste (default: core)
WANT_CORE=1 WANT_DOCKER=0 WANT_OPTIONAL=0 LIST_ONLY=0

usage() { sed -n '3,17p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

for arg in "$@"; do
  case "$arg" in
    --all)      WANT_CORE=1; WANT_DOCKER=1; WANT_OPTIONAL=1 ;;
    --core)     WANT_CORE=1 ;;
    --docker)   WANT_CORE=0; WANT_DOCKER=1 ;;
    --optional) WANT_CORE=0; WANT_OPTIONAL=1 ;;
    --list|-l)  LIST_ONLY=1 ;;
    --help|-h)  usage 0 ;;
    *) echo "Argomento sconosciuto: $arg" >&2; usage 1 ;;
  esac
done

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
info() { echo "${c_dim}·${c_rst} $*"; }
ok()   { echo "${c_grn}✓${c_rst} $*"; }
warn() { echo "${c_yel}!${c_rst} $*" >&2; }
err()  { echo "${c_red}✗${c_rst} $*" >&2; }

[ -f "$MANIFEST" ] || { err "manifest non trovato: $MANIFEST"; exit 1; }

# --- sudo helper (no-op se gia' root) -------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    warn "non sei root e manca sudo: le install via apt potrebbero fallire."
  fi
fi

APT_UPDATED=0
apt_install() {
  command -v apt-get >/dev/null 2>&1 || { err "apt-get assente: installa '$1' a mano."; return 1; }
  if [ "$APT_UPDATED" -eq 0 ]; then $SUDO apt-get update -qq && APT_UPDATED=1; fi
  $SUDO apt-get install -y -qq "$1"
}

# --- Go: bootstrap on demand ----------------------------------------------
gopath_bin() {
  local gp=""
  command -v go >/dev/null 2>&1 && gp="$(go env GOPATH 2>/dev/null || true)"
  echo "${gp:-$HOME/go}/bin"
}
GOBIN_DIR="$(gopath_bin)"
ensure_go() {
  if command -v go >/dev/null 2>&1; then return 0; fi
  warn "Go non trovato: lo installo via apt (golang-go)."
  apt_install golang-go || { err "impossibile installare Go. Vedi https://go.dev/dl/"; return 1; }
  GOBIN_DIR="$(gopath_bin)"
}

# Dipendenze di sistema note per alcuni tool Go/apt (naabu e masscan usano libpcap)
ensure_build_deps() {
  case "$1" in
    naabu|masscan)
      dpkg -s libpcap-dev >/dev/null 2>&1 || { info "libpcap-dev (necessaria a $1)"; apt_install libpcap-dev || true; } ;;
    amass|jsluice|*) : ;;
  esac
}

install_go_tool() { ensure_go || return 1; info "go install $1"; GOBIN="$GOBIN_DIR" go install "$1"; }

install_script_tool() {
  # $1 = nome, $2 = spec
  case "$2" in
    release-binary:hadolint/hadolint)
      ensure_go >/dev/null 2>&1 || true
      local ver bin arch url
      ver="v2.12.0"
      case "$(uname -m)" in x86_64) arch="x86_64" ;; aarch64|arm64) arch="arm64" ;; *) arch="x86_64" ;; esac
      url="https://github.com/hadolint/hadolint/releases/download/${ver}/hadolint-$(uname -s)-${arch}"
      info "scarico hadolint ${ver}"
      curl -fsSL "$url" -o /tmp/hadolint && chmod +x /tmp/hadolint && $SUDO mv /tmp/hadolint /usr/local/bin/hadolint ;;
    aquasecurity-install-script)
      info "trivy via script ufficiale aquasecurity"
      curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | $SUDO sh -s -- -b /usr/local/bin ;;
    anchore-install-script)
      info "grype via script ufficiale anchore"
      curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | $SUDO sh -s -- -b /usr/local/bin ;;
    *) err "script di install sconosciuto per $1 ($2)"; return 1 ;;
  esac
}

want_category() {
  case "$1" in
    core)     [ "$WANT_CORE" -eq 1 ] ;;
    docker)   [ "$WANT_DOCKER" -eq 1 ] ;;
    optional) [ "$WANT_OPTIONAL" -eq 1 ] ;;
    *) return 1 ;;
  esac
}

installed=0 skipped=0 failed=0 missing=0

while IFS= read -r line; do
  line="${line%%#*}"                      # rimuove commenti
  line="$(echo "$line" | sed 's/[[:space:]]*$//')"
  [ -z "${line// }" ] && continue
  IFS='|' read -r name cat method spec <<<"$line"
  name="$(echo "$name" | xargs)"; cat="$(echo "$cat" | xargs)"
  method="$(echo "$method" | xargs)"; spec="$(echo "$spec" | xargs)"
  [ -z "$name" ] && continue
  want_category "$cat" || continue

  if command -v "$name" >/dev/null 2>&1; then
    ok "$name gia' presente"; skipped=$((skipped+1)); continue
  fi

  if [ "$LIST_ONLY" -eq 1 ]; then
    warn "$name MANCANTE  [$cat/$method]  ($spec)"; missing=$((missing+1)); continue
  fi

  info "installo $name  [$cat/$method]"
  ensure_build_deps "$name"
  set +e
  case "$method" in
    apt)    apt_install "$spec" ;;
    go)     install_go_tool "$spec" ;;
    script) install_script_tool "$name" "$spec" ;;
    manual) warn "$name richiede install manuale: $spec"; set -e; continue ;;
    *)      err "metodo sconosciuto '$method' per $name" ;;
  esac
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] && command -v "$name" >/dev/null 2>&1; then
    ok "$name installato"; installed=$((installed+1))
  elif [ "$rc" -eq 0 ]; then
    ok "$name installato (potrebbe servire riaprire la shell per il PATH)"; installed=$((installed+1))
  else
    err "$name: installazione fallita"; failed=$((failed+1))
  fi
done < "$MANIFEST"

echo
if [ "$LIST_ONLY" -eq 1 ]; then
  echo "Riepilogo: $skipped presenti, $missing mancanti."
else
  echo "Riepilogo: $installed installati, $skipped gia' presenti, $failed falliti."
  if printf '%s' "$PATH" | grep -q "$GOBIN_DIR"; then :; else
    [ -d "$GOBIN_DIR" ] && warn "aggiungi i tool Go al PATH:  export PATH=\"\$PATH:$GOBIN_DIR\"  (mettilo in ~/.bashrc / ~/.zshrc)"
  fi
fi
[ "${failed:-0}" -eq 0 ]
