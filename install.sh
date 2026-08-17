#!/usr/bin/env bash
# =============================================================================
# ReconPilot — installer for Kali / Debian / Ubuntu
# =============================================================================
# Run from the project directory:
#   chmod +x install.sh
#   ./install.sh
#
# The script is re-runnable. It installs Python dependencies from
# requirements.txt, installs the external tools used by the current modules,
# adds common user/Go binary directories to PATH, and verifies the result.
# =============================================================================

set -uo pipefail

# ── Colour helpers ───────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YLW=$'\033[0;33m'
    BLU=$'\033[0;34m'; BLD=$'\033[1m'; RST=$'\033[0m'
else
    RED=''; GRN=''; YLW=''; BLU=''; BLD=''; RST=''
fi

ok()   { printf "%s✔%s %s\n" "$GRN" "$RST" "$*"; }
warn() { printf "%s⚠%s %s\n" "$YLW" "$RST" "$*"; }
err()  { printf "%s✘%s %s\n" "$RED" "$RST" "$*"; }
info() { printf "%sℹ%s %s\n" "$BLU" "$RST" "$*"; }
hdr()  { printf "\n%s═══ %s ═══%s\n" "$BLD" "$*" "$RST"; }

OK_COUNT=0
FAIL_LIST=()
WARN_LIST=()

step_ok()   { ok "$*"; OK_COUNT=$((OK_COUNT + 1)); }
step_fail() { err "$*"; FAIL_LIST+=("$*"); }
step_warn() { warn "$*"; WARN_LIST+=("$*"); }

# ── Utilities ────────────────────────────────────────────────────────────────
command_exists() { command -v "$1" >/dev/null 2>&1; }

# Use sudo only when needed.
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
elif command_exists sudo; then
    SUDO=(sudo)
else
    SUDO=()
fi

path_contains() {
    local dir="$1"
    [[ ":$PATH:" == *":$dir:"* ]]
}

prepend_path_now() {
    local dir="$1"
    mkdir -p "$dir"
    if ! path_contains "$dir"; then
        export PATH="$dir:$PATH"
    fi
}

refresh_hash() { hash -r 2>/dev/null || true; }

detect_go_paths() {
    GOPATH_DIR="${GOPATH:-}"
    if [[ -z "$GOPATH_DIR" ]] && command_exists go; then
        GOPATH_DIR="$(go env GOPATH 2>/dev/null || true)"
    fi
    [[ -n "$GOPATH_DIR" ]] || GOPATH_DIR="$HOME/go"
    GO_BIN="${GOBIN:-$GOPATH_DIR/bin}"
}

write_reconpilot_path_block() {
    local rc_file="$1"
    local local_bin="$2"
    local go_bin="$3"

    mkdir -p "$(dirname "$rc_file")"
    touch "$rc_file"

    if grep -q '# >>> ReconPilot PATH >>>' "$rc_file" 2>/dev/null; then
        sed -i '/# >>> ReconPilot PATH >>>/,/# <<< ReconPilot PATH <<</d' "$rc_file"
    fi

    cat >> "$rc_file" <<PATH_EOF

# >>> ReconPilot PATH >>>
# Added by ReconPilot installer for user-installed Python and Go CLI tools.
export PATH="$local_bin:$go_bin:\$PATH"
# <<< ReconPilot PATH <<<
PATH_EOF
}

persist_reconpilot_path() {
    hdr "Updating PATH"
    prepend_path_now "$LOCAL_BIN"
    prepend_path_now "$GO_BIN"
    refresh_hash

    local rc
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
        if write_reconpilot_path_block "$rc" "$LOCAL_BIN" "$GO_BIN"; then
            step_ok "PATH block written to $rc"
        else
            step_warn "Could not update $rc"
        fi
    done
}

apt_install_if_missing() {
    local command_name="$1"
    local package_name="$2"

    if command_exists "$command_name"; then
        step_ok "$command_name (already installed)"
        return 0
    fi

    if [[ "$PKG" != "apt" ]]; then
        step_warn "$command_name missing; automatic package install requires apt"
        return 1
    fi

    if "${SUDO[@]}" apt-get install -y "$package_name" >/dev/null 2>&1; then
        refresh_hash
        if command_exists "$command_name"; then
            step_ok "$command_name installed via apt package $package_name"
            return 0
        fi
        # Some packages (notably wordlists) intentionally do not provide a
        # command with the package name. Treat a successful apt install as OK.
        if [[ "$command_name" == "__package_only__" ]]; then
            step_ok "$package_name installed"
            return 0
        fi
    fi

    step_warn "apt package $package_name did not provide $command_name"
    return 1
}

ensure_package_only() {
    local package_name="$1"
    if [[ "$PKG" != "apt" ]]; then
        step_warn "$package_name not installed automatically (apt unavailable)"
        return 1
    fi
    if dpkg -s "$package_name" >/dev/null 2>&1; then
        step_ok "$package_name (already installed)"
        return 0
    fi
    if "${SUDO[@]}" apt-get install -y "$package_name" >/dev/null 2>&1; then
        step_ok "$package_name installed"
        return 0
    fi
    step_warn "apt install $package_name failed"
    return 1
}

ensure_go() {
    if command_exists go; then
        return 0
    fi
    if [[ "$PKG" == "apt" ]] && "${SUDO[@]}" apt-get install -y golang-go >/dev/null 2>&1; then
        refresh_hash
        if command_exists go; then
            step_ok "Go installed: $(command -v go)"
            detect_go_paths
            mkdir -p "$GO_BIN"
            prepend_path_now "$GO_BIN"
            return 0
        fi
    fi
    step_warn "Go is unavailable; Go-based fallback installs will be skipped"
    return 1
}

install_go_tool() {
    local binary="$1"
    local module="$2"

    if command_exists "$binary"; then
        step_ok "$binary (already installed)"
        return 0
    fi
    ensure_go || return 1
    detect_go_paths
    mkdir -p "$GO_BIN"
    prepend_path_now "$GO_BIN"

    info "Installing $binary with go install …"
    if env GOBIN="$GO_BIN" go install "$module" >/tmp/reconpilot_go_install.log 2>&1; then
        refresh_hash
        if [[ -x "$GO_BIN/$binary" ]] || command_exists "$binary"; then
            step_ok "$binary installed with Go"
            return 0
        fi
    fi
    step_warn "go install for $binary failed (see /tmp/reconpilot_go_install.log)"
    return 1
}

# ── Sanity checks ────────────────────────────────────────────────────────────
cd "$(dirname "$0")"

hdr "ReconPilot Installer"
info "Working directory: $(pwd)"

if [[ ! -f main.py || ! -f requirements.txt || ! -d modules || ! -d ui ]]; then
    err "Run this script from the ReconPilot project directory."
    err "Expected main.py, requirements.txt, modules/, and ui/."
    exit 1
fi

if ! command_exists python3; then
    if command_exists apt-get; then
        info "python3 is missing; attempting to install it."
        "${SUDO[@]}" apt-get update -qq >/dev/null 2>&1 || true
        "${SUDO[@]}" apt-get install -y python3 python3-pip >/dev/null 2>&1 || true
    fi
fi
if ! command_exists python3; then
    err "python3 is required (ReconPilot needs Python 3.10+)."
    exit 1
fi

PY="$(command -v python3)"
if ! "$PY" - <<'PYEOF' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PYEOF
then
    err "ReconPilot requires Python 3.10 or newer. Found: $($PY --version 2>&1)"
    exit 1
fi
step_ok "Python: $($PY --version 2>&1)"

if command_exists apt-get; then
    if [[ ${EUID:-$(id -u)} -eq 0 || ${#SUDO[@]} -gt 0 ]]; then
        PKG=apt
        step_ok "Package manager: apt"
    else
        PKG=unknown
        step_warn "apt is available but root/sudo access is not; system-package installation will be skipped"
    fi
else
    PKG=unknown
    step_warn "Non-apt system detected; only Python/Go installs will be attempted"
fi

if ! "$PY" -m pip --version >/dev/null 2>&1; then
    if [[ "$PKG" == "apt" ]]; then
        "${SUDO[@]}" apt-get install -y python3-pip >/dev/null 2>&1 || true
    fi
fi
if ! "$PY" -m pip --version >/dev/null 2>&1; then
    err "pip for python3 is required."
    exit 1
fi
step_ok "pip: $($PY -m pip --version 2>/dev/null | cut -d' ' -f1-2)"

LOCAL_BIN="$HOME/.local/bin"
detect_go_paths
mkdir -p "$LOCAL_BIN" "$GO_BIN"
prepend_path_now "$LOCAL_BIN"
prepend_path_now "$GO_BIN"
refresh_hash

# ── Python dependencies ──────────────────────────────────────────────────────
hdr "Installing Python dependencies"
PIP_LOG=/tmp/reconpilot_pip_install.log
PIP_FLAGS=(install --user --upgrade --break-system-packages -r requirements.txt)

if "$PY" -m pip "${PIP_FLAGS[@]}" >"$PIP_LOG" 2>&1; then
    step_ok "Python dependencies installed from requirements.txt"
else
    step_fail "pip install -r requirements.txt failed (see $PIP_LOG)"
fi

# Kali/Debian can occasionally leave an incompatible split Qt/shiboken setup.
# Only force-reinstall PySide6 when the import is actually broken.
if ! "$PY" -c 'from PySide6.QtWidgets import QApplication' >/dev/null 2>&1; then
    info "PySide6 import failed; attempting a clean user-site reinstall."
    if "$PY" -m pip install --user --upgrade --force-reinstall --break-system-packages PySide6 >>"$PIP_LOG" 2>&1 \
       && "$PY" -c 'from PySide6.QtWidgets import QApplication' >/dev/null 2>&1; then
        step_ok "PySide6 repaired"
    else
        step_fail "PySide6 is still not importable (see $PIP_LOG)"
    fi
else
    step_ok "PySide6 import check passed"
fi

# ── System and CLI dependencies ──────────────────────────────────────────────
if [[ "$PKG" == "apt" ]]; then
    hdr "Installing system and CLI dependencies"
    info "System package installation may prompt for your sudo password."
    "${SUDO[@]}" apt-get update -qq >/dev/null 2>&1 || step_warn "apt-get update failed; continuing with existing package metadata"

    # Live-host check on Linux uses the system ping command.
    apt_install_if_missing ping iputils-ping || true

    # Native/system tools. Some are available mainly on Kali; missing tools are
    # retried below with Go/pip fallbacks where a reliable fallback exists.
    apt_install_if_missing nmap nmap || true
    apt_install_if_missing subfinder subfinder || true
    apt_install_if_missing httpx-toolkit httpx-toolkit || true
    apt_install_if_missing whatweb whatweb || true
    apt_install_if_missing wafw00f wafw00f || true
    apt_install_if_missing nuclei nuclei || true
    apt_install_if_missing gospider gospider || true
    apt_install_if_missing feroxbuster feroxbuster || true
    apt_install_if_missing ffuf ffuf || true
    ensure_package_only seclists || true
fi

# Go fallbacks make the installer useful on Debian/Ubuntu repositories that do
# not carry all of Kali's security-tool packages.
hdr "Checking Go-based tools and URL-harvest boosters"

command_exists subfinder || install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
command_exists nuclei    || install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
command_exists gospider  || install_go_tool gospider github.com/jaeles-project/gospider@latest || true
command_exists ffuf      || install_go_tool ffuf github.com/ffuf/ffuf/v2@latest || true

# ReconPilot deliberately calls the Kali binary name `httpx-toolkit`. If apt
# did not provide it, install upstream httpx and expose a local compatibility
# symlink with the expected name.
if ! command_exists httpx-toolkit; then
    if ensure_go; then
        detect_go_paths
        mkdir -p "$GO_BIN"
        prepend_path_now "$GO_BIN"
        info "Installing upstream ProjectDiscovery httpx for httpx-toolkit compatibility …"
        if env GOBIN="$GO_BIN" go install github.com/projectdiscovery/httpx/cmd/httpx@latest >/tmp/reconpilot_go_install.log 2>&1 \
           && [[ -x "$GO_BIN/httpx" ]]; then
            ln -sf "$GO_BIN/httpx" "$LOCAL_BIN/httpx-toolkit"
            refresh_hash
            command_exists httpx-toolkit \
                && step_ok "httpx-toolkit compatibility link created at $LOCAL_BIN/httpx-toolkit" \
                || step_warn "Could not create httpx-toolkit compatibility link"
        else
            step_warn "ProjectDiscovery httpx install failed (see /tmp/reconpilot_go_install.log)"
        fi
    fi
fi

# wafw00f is a Python CLI; use pip only when the distro package was unavailable.
if ! command_exists wafw00f; then
    if "$PY" -m pip install --user --upgrade --break-system-packages wafw00f >>"$PIP_LOG" 2>&1; then
        refresh_hash
        command_exists wafw00f && step_ok "wafw00f installed with pip" || step_warn "wafw00f pip install completed but command is not on PATH"
    else
        step_warn "wafw00f install failed (see $PIP_LOG)"
    fi
fi

# Optional passive URL-harvest boosters. ReconPilot still has built-in Wayback,
# urlscan.io, and OTX collectors if these are unavailable.
install_go_tool gau github.com/lc/gau/v2/cmd/gau@latest || true
install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest || true

# feroxbuster has no Go fallback. Keep the absence visible rather than silently
# installing an unrelated package manager/toolchain.
if ! command_exists feroxbuster; then
    step_warn "feroxbuster is missing; Controlled/CTF Directory Enumeration will be unavailable"
fi

# SecLists is required for ffuf subdomain/vhost fuzzing. Check the actual paths
# used by modules/subdomain_fuzz.py, not just package-manager state.
if [[ ! -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
   && ! -f /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
   && ! -f /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt ]]; then
    step_warn "No supported SecLists DNS wordlist found; CTF Subdomain Bruteforce will be unavailable"
else
    step_ok "SecLists DNS wordlist found"
fi

# The preferred feroxbuster wordlist is DirBuster medium; SecLists provides the
# fallback path used by the code when the DirBuster package is absent.
if [[ -f /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
   || -f /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
   || -f /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt ]]; then
    step_ok "Directory-enumeration wordlist found"
else
    step_warn "No preferred directory wordlist found; feroxbuster will fall back to its own defaults"
fi

persist_reconpilot_path

# ── Nuclei templates ─────────────────────────────────────────────────────────
if command_exists nuclei; then
    hdr "Updating Nuclei templates"
    if nuclei -update-templates -silent >/dev/null 2>&1; then
        step_ok "Nuclei templates updated"
    else
        step_warn "Nuclei template update failed; run 'nuclei -update-templates' manually"
    fi
fi

# ── Final verification ───────────────────────────────────────────────────────
hdr "Final verification"

"$PY" - <<'PYEOF'
import importlib
import sys

required = [
    ("PySide6.QtCore", "PySide6.QtCore"),
    ("PySide6.QtGui", "PySide6.QtGui"),
    ("PySide6.QtWidgets", "PySide6.QtWidgets"),
    ("requests", "requests"),
    ("urllib3", "urllib3"),
    ("bs4", "beautifulsoup4"),
    ("dns.asyncresolver", "dnspython"),
    ("cryptography.x509", "cryptography"),
]

failed = 0
for module, label in required:
    try:
        importlib.import_module(module)
        print(f"  OK    {label}")
    except Exception as exc:
        print(f"  FAIL  {label}: {exc}")
        failed += 1
sys.exit(1 if failed else 0)
PYEOF
PY_RC=$?

refresh_hash
printf "\nExternal tools used by the current code:\n"
REQUIRED_TOOLS=(ping nmap subfinder httpx-toolkit whatweb wafw00f nuclei gospider feroxbuster ffuf)
OPTIONAL_TOOLS=(gau waybackurls)
TOOL_FAIL=0
for tool in "${REQUIRED_TOOLS[@]}"; do
    if command_exists "$tool"; then
        printf "  %sOK%s    %-14s %s\n" "$GRN" "$RST" "$tool" "$(command -v "$tool")"
    else
        printf "  %sMISS%s  %-14s\n" "$YLW" "$RST" "$tool"
        TOOL_FAIL=$((TOOL_FAIL + 1))
    fi
done
for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command_exists "$tool"; then
        printf "  %sOK%s    %-14s %s  (optional)\n" "$GRN" "$RST" "$tool" "$(command -v "$tool")"
    else
        printf "  %sSKIP%s  %-14s optional booster\n" "$YLW" "$RST" "$tool"
    fi
done

# ── Summary ──────────────────────────────────────────────────────────────────
hdr "Summary"
ok "Successful steps: $OK_COUNT"

if [[ ${#WARN_LIST[@]} -gt 0 ]]; then
    warn "Warnings: ${#WARN_LIST[@]}"
    for item in "${WARN_LIST[@]}"; do printf "    • %s\n" "$item"; done
fi

if [[ ${#FAIL_LIST[@]} -gt 0 ]]; then
    err "Failed steps: ${#FAIL_LIST[@]}"
    for item in "${FAIL_LIST[@]}"; do printf "    • %s\n" "$item"; done
fi

echo
if [[ $PY_RC -eq 0 ]]; then
    ok "Python runtime is ready. Launch ReconPilot with:"
    echo "    python3 main.py"
    echo
    info "If a newly installed command is not visible in your current terminal, reload your shell:"
    echo "    source ~/.zshrc   # Kali default"
    echo "    source ~/.bashrc  # bash"
    echo
    if [[ $TOOL_FAIL -gt 0 ]]; then
        warn "$TOOL_FAIL external tool(s) are still missing; only their corresponding modules will be unavailable."
    fi
    info "AI Advisor is optional and requires a separately running Ollama server/model."
    exit 0
else
    err "One or more required Python imports failed. See $PIP_LOG."
    exit 1
fi
