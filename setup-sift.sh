#!/usr/bin/env bash
# setup-sift.sh — CaseFile installer for SIFT Workstation (Ubuntu 22.04)
#
# Installs all dependencies and configures CaseFile for autonomous DFIR.
#
# Usage:
#   git clone https://github.com/nurusyda/casefile.git && cd casefile
#   bash setup-sift.sh
#
# After install, run an investigation:
#   export CASEFILE_CASE_ROOT=~/cases/SRL-2018
#   export CASEFILE_CASE_DIR=~/cases/SRL-2018
#   export CASEFILE_EXAMINER=yourname
#   bash ralph.sh
#
set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[casefile]${NC} $*"; }
warn()  { echo -e "${YELLOW}[casefile]${NC} $*"; }
die()   { echo -e "${RED}[casefile] FATAL:${NC} $*" >&2; exit 1; }
check() { command -v "$1" &>/dev/null; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZIMM_DIR="/opt/zimmermantools"
ZIMM_URL="https://download.ericzimmermanstools.com/net9"

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Python 3.10+
# ─────────────────────────────────────────────────────────────────────────────
info "Checking Python..."
PYTHON=$(command -v python3.11 || command -v python3.10 || command -v python3)
PYVER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
info "Found Python $PYVER at $PYTHON"
[[ "$PYVER" < "3.10" ]] && die "Python 3.10+ required. Found $PYVER."

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — .NET 9 SDK (via Microsoft apt repo)
# ─────────────────────────────────────────────────────────────────────────────
if check dotnet && dotnet --version | grep -q "^9\."; then
    info ".NET 9 already installed ($(dotnet --version))"
else
    info "Installing .NET 9 SDK via Microsoft apt repo..."
    # Add Microsoft package repository
    wget -q https://packages.microsoft.com/config/ubuntu/22.04/packages-microsoft-prod.deb \
        -O /tmp/packages-microsoft-prod.deb
    sudo dpkg -i /tmp/packages-microsoft-prod.deb
    rm /tmp/packages-microsoft-prod.deb
    sudo apt-get update -qq
    sudo apt-get install -y dotnet-sdk-9.0
    info ".NET 9 SDK installed: $(dotnet --version)"
fi

# Add dotnet to PATH if needed
if ! check dotnet; then
    export PATH="$PATH:$HOME/.dotnet"
    echo 'export PATH="$PATH:$HOME/.dotnet"' >> ~/.bashrc
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — EZ Tools (net9 builds)
# ─────────────────────────────────────────────────────────────────────────────
EZ_TOOLS=(
    "AmcacheParser.dll"
    "AppCompatCacheParser.dll"
    "MFTECmd.dll"
    "PECmd.dll"
)
# Subdirectory tools
EZ_SUBDIRS=(
    "EvtxeCmd"
    "RECmd"
)

if [[ -f "$ZIMM_DIR/AmcacheParser.dll" ]]; then
    info "EZ Tools already present at $ZIMM_DIR"
else
    info "Installing EZ Tools to $ZIMM_DIR..."
    sudo mkdir -p "$ZIMM_DIR"

    for tool in "${EZ_TOOLS[@]}"; do
        info "  Downloading $tool..."
        sudo wget -q "$ZIMM_URL/$tool" -O "$ZIMM_DIR/$tool" || \
            warn "  Failed to download $tool — check network connectivity"
    done

    for subdir in "${EZ_SUBDIRS[@]}"; do
        info "  Downloading $subdir..."
        sudo mkdir -p "$ZIMM_DIR/$subdir"
        # Download zip and extract
        sudo wget -q "$ZIMM_URL/${subdir}.zip" -O "/tmp/${subdir}.zip" && \
            sudo unzip -q -o "/tmp/${subdir}.zip" -d "$ZIMM_DIR/$subdir/" && \
            sudo rm "/tmp/${subdir}.zip" || \
            warn "  Failed to download $subdir — check network connectivity"
    done

    info "EZ Tools installed at $ZIMM_DIR"
fi

# Verify critical tools
for dll in AmcacheParser.dll AppCompatCacheParser.dll MFTECmd.dll PECmd.dll; do
    if [[ ! -f "$ZIMM_DIR/$dll" ]]; then
        warn "Missing: $ZIMM_DIR/$dll — EZ Tools install may be incomplete"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Step 4 — Volatility 3
# ─────────────────────────────────────────────────────────────────────────────
if check vol; then
    info "Volatility 3 found at $(which vol)"
elif check vol.py; then
    info "Volatility 3 found at $(which vol.py)"
else
    warn "Volatility 3 not found. On SIFT it should be at /usr/local/bin/vol"
    warn "Install via: sudo cast install teamdfir/sift-saltstack"
    warn "Or: pip install volatility3"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Step 5 — CaseFile Python package
# ─────────────────────────────────────────────────────────────────────────────
info "Setting up CaseFile Python environment..."
cd "$REPO_DIR"

if [[ ! -d "venv" ]]; then
    info "Creating virtual environment..."
    "$PYTHON" -m venv venv
fi

info "Installing CaseFile and dependencies..."
# shellcheck source=/dev/null
source venv/bin/activate
pip install --upgrade pip -q
pip install -e ".[dev]" -q
info "CaseFile installed: $(pip show casefile 2>/dev/null | grep Version)"

# ─────────────────────────────────────────────────────────────────────────────
# Step 6 — Verify installation
# ─────────────────────────────────────────────────────────────────────────────
info "Running test suite..."
pytest tests/ -q 2>&1 | tail -3

# ─────────────────────────────────────────────────────────────────────────────
# Step 7 — Environment setup
# ─────────────────────────────────────────────────────────────────────────────
EXAMINER="${USER:-analyst}"
CASES_DIR="$HOME/cases"

info "Creating cases directory at $CASES_DIR..."
mkdir -p "$CASES_DIR"

# Add env vars to .bashrc if not already there
if ! grep -q "CASEFILE_EXAMINER" ~/.bashrc; then
    cat >> ~/.bashrc << EOF

# CaseFile — DFIR MCP Server
export CASEFILE_EXAMINER="${EXAMINER}"
# Set these before each investigation:
# export CASEFILE_CASE_ROOT=~/cases/<case-id>
# export CASEFILE_CASE_DIR=~/cases/<case-id>
EOF
    info "Environment variables added to ~/.bashrc"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}CaseFile installed successfully.${NC}"
echo ""
echo "Next steps:"
echo "  1. Place your case evidence in ~/cases/<case-id>/evidence/"
echo "  2. Create a prd.json in ~/cases/<case-id>/ (see docs/getting-started.md)"
echo "  3. Run an investigation:"
echo ""
echo "     source ~/casefile/venv/bin/activate"
echo "     export CASEFILE_CASE_ROOT=~/cases/<case-id>"
echo "     export CASEFILE_CASE_DIR=~/cases/<case-id>"
echo "     export CASEFILE_EXAMINER=${EXAMINER}"
echo "     cd ~/casefile && bash ralph.sh"
echo ""
echo "  Full docs: https://github.com/nurusyda/casefile"
