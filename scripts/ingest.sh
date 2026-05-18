#!/usr/bin/env bash
# ingest.sh — Mount a Windows disk image and extract forensic artifacts for CaseFile
#
# Usage:
#   bash scripts/ingest.sh <evidence.E01> <case_name>
#
# Example:
#   bash scripts/ingest.sh /path/to/suspect.E01 INCIDENT-2026-001

set -euo pipefail

# ── Args ─────────────────────────────────────────────────────────────────────
if [ "$#" -ne 2 ]; then
    echo "Usage: bash scripts/ingest.sh <evidence.E01> <case_name>"
    echo "Example: bash scripts/ingest.sh /evidence/suspect.E01 INCIDENT-001"
    exit 1
fi

E01_PATH="$(realpath "$1")"
CASE_NAME="$2"

# Blocker fix 1: validate case name — no path traversal
if ! [[ "${CASE_NAME}" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "ERROR: case name must contain only alphanumerics, dots, hyphens, underscores"
    echo "       Got: ${CASE_NAME}"
    exit 1
fi

CASE_DIR="${HOME}/cases/${CASE_NAME}"
# Extractions go to analysis/ — NOT evidence/ to avoid Law 1 conflict
ANALYSIS_DIR="${CASE_DIR}/analysis"
REPORTS_DIR="${CASE_DIR}/reports"
AUDIT_DIR="${CASE_DIR}/audit"
EWF_MOUNT="/tmp/ewf_${CASE_NAME}"
FS_MOUNT="/tmp/fs_${CASE_NAME}"

# ── Sanity checks ────────────────────────────────────────────────────────────
if [ ! -f "${E01_PATH}" ]; then
    echo "ERROR: Evidence file not found: ${E01_PATH}"
    exit 1
fi

for cmd in ewfmount mount sudo find cp; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "ERROR: Required command not found: ${cmd}"
        exit 1
    fi
done

echo "=== CaseFile Ingest ==="
echo "Evidence : ${E01_PATH}"
echo "Case     : ${CASE_NAME}"
echo "Case dir : ${CASE_DIR}"
echo ""

# ── Create case directory structure ──────────────────────────────────────────
mkdir -p "${ANALYSIS_DIR}" "${REPORTS_DIR}" "${AUDIT_DIR}"
echo "[+] Case directory created: ${CASE_DIR}"

# Record evidence provenance (path + hash) — but do NOT copy the E01
echo "${E01_PATH}" > "${CASE_DIR}/source.txt"
echo "[*] Computing SHA-256 (may take several minutes on large images)..."
sha256sum "${E01_PATH}" > "${CASE_DIR}/source.sha256" 2>/dev/null || echo "[!] SHA-256 skipped"

# ── Mount E01 ────────────────────────────────────────────────────────────────
mkdir -p "${EWF_MOUNT}" "${FS_MOUNT}"

if ! sudo -n true 2>/dev/null; then
    echo "[!] WARNING: sudo may require a password for mount/umount"
fi
echo "[*] Mounting E01 with ewfmount..."
if ! ewfmount "${E01_PATH}" "${EWF_MOUNT}" 2>/dev/null; then
    echo "ERROR: ewfmount failed. Is the file a valid E01?"
    rmdir "${EWF_MOUNT}" "${FS_MOUNT}" 2>/dev/null || true
    exit 1
fi
echo "[+] E01 mounted at ${EWF_MOUNT}"

# ── Detect partition layout ───────────────────────────────────────────────────
echo "[*] Detecting partition layout..."
BYTE_OFFSET=0

if command -v mmls &>/dev/null; then
    SECTOR=$(mmls "${EWF_MOUNT}/ewf1" 2>/dev/null \
        | grep -i "NTFS\|Basic data" \
        | awk '{print $3}' \
        | sort -n | head -1 || true)
    if [ -n "${SECTOR}" ]; then
        BYTE_OFFSET=$(( SECTOR * 512 ))
        echo "[+] Partition at sector ${SECTOR} (offset ${BYTE_OFFSET} bytes)"
    else
        echo "[!] No partition table — using offset=0 (MBR/corrupted fallback)"
    fi
else
    echo "[!] mmls not found — using offset=0"
fi

echo "[*] Mounting filesystem at ${FS_MOUNT}..."
if ! sudo mount -o ro,loop,offset=${BYTE_OFFSET},noatime \
        "${EWF_MOUNT}/ewf1" "${FS_MOUNT}" 2>/dev/null; then
    echo "ERROR: Failed to mount filesystem."
    echo "Try: sudo mount -o ro,loop,offset=<bytes> ${EWF_MOUNT}/ewf1 ${FS_MOUNT}"
    fusermount -u "${EWF_MOUNT}" 2>/dev/null || true
    exit 1
fi
echo "[+] Filesystem mounted at ${FS_MOUNT}"

# ── Case-insensitive file extraction helpers ──────────────────────────────────
# Blocker fix 2: use find -iname for case-insensitive matching on NTFS mounts

extract_iname() {
    # extract_iname <search_dir> <filename_pattern> <destination> <label>
    local src_dir="$1" pattern="$2" dst="$3" label="$4"
    local found
    found=$(find "${src_dir}" -maxdepth 1 -iname "${pattern}" -print -quit 2>/dev/null || true)
    if [ -n "${found}" ]; then
        cp "${found}" "${dst}" 2>/dev/null && echo "[+] ${label}"
    else
        echo "[!] Not found: ${label}"
    fi
}


# ── Extract artifacts ─────────────────────────────────────────────────────────
echo ""
echo "[*] Extracting artifacts..."

# Locate Windows directory (case-insensitive)
WIN=$(find "${FS_MOUNT}" -maxdepth 1 -iname "Windows" -type d -print -quit 2>/dev/null || true)
if [ -z "${WIN}" ]; then
    echo "ERROR: Windows directory not found on mounted filesystem"
    sudo umount "${FS_MOUNT}" 2>/dev/null || true
    fusermount -u "${EWF_MOUNT}" 2>/dev/null || true
    exit 1
fi

SYS32=$(find "${WIN}" -maxdepth 1 -iname "System32" -type d -print -quit 2>/dev/null || true)
CONFIG=$(find "${SYS32}" -maxdepth 1 -iname "config" -type d -print -quit 2>/dev/null || true)

# Registry hives
if [ -n "${CONFIG}" ]; then
    for hive in SYSTEM SOFTWARE SECURITY SAM; do
        extract_iname "${CONFIG}" "${hive}" "${ANALYSIS_DIR}/${hive}" "${hive} hive"
    done
else
    echo "[!] Registry config directory not found"
fi

# Amcache
APPCOMPAT=$(find "${WIN}" -maxdepth 3 -iname "Programs" -path "*/AppCompat/*" \
    -type d -print -quit 2>/dev/null || true)
if [ -n "${APPCOMPAT}" ]; then
    extract_iname "${APPCOMPAT}" "Amcache.hve"      "${ANALYSIS_DIR}/Amcache.hve"      "Amcache.hve"
    extract_iname "${APPCOMPAT}" "Amcache.hve.LOG1" "${ANALYSIS_DIR}/Amcache.hve.LOG1" "Amcache.hve.LOG1"
    extract_iname "${APPCOMPAT}" "Amcache.hve.LOG2" "${ANALYSIS_DIR}/Amcache.hve.LOG2" "Amcache.hve.LOG2"
else
    echo "[!] AppCompat directory not found"
fi

# Prefetch
mkdir -p "${ANALYSIS_DIR}/Prefetch"
PREFETCH_DIR=$(find "${WIN}" -maxdepth 1 -iname "Prefetch" -type d -print -quit 2>/dev/null || true)
if [ -n "${PREFETCH_DIR}" ]; then
    find "${PREFETCH_DIR}" -maxdepth 1 -iname "*.pf" -exec cp '{}' "${ANALYSIS_DIR}/Prefetch/" \; 2>/dev/null
    echo "[+] Prefetch ($(ls "${ANALYSIS_DIR}/Prefetch/" | wc -l) .pf files)"
else
    echo "[!] Prefetch directory not found"
fi

# Event logs
mkdir -p "${ANALYSIS_DIR}/evtx"
EVTX_DIR=$(find "${SYS32}" -maxdepth 3 -iname "Logs" -path "*/winevt/*" \
    -type d -print -quit 2>/dev/null || true)
if [ -n "${EVTX_DIR}" ]; then
    find "${EVTX_DIR}" -maxdepth 1 -iname "*.evtx" -exec cp '{}' "${ANALYSIS_DIR}/evtx/" \; 2>/dev/null
    echo "[+] Event logs ($(ls "${ANALYSIS_DIR}/evtx/" | wc -l) .evtx files)"
else
    echo "[!] Event logs directory not found"
fi

# MFT
MFT_SRC=$(find "${FS_MOUNT}" -maxdepth 1 -name '$MFT' -print -quit 2>/dev/null || true)
if [ -n "${MFT_SRC}" ]; then
    sudo cp --no-preserve=ownership "${MFT_SRC}" "${ANALYSIS_DIR}/MFT" 2>/dev/null
    sudo chmod a+r "${ANALYSIS_DIR}/MFT"
    echo "[+] MFT ($(du -sh "${ANALYSIS_DIR}/MFT" | cut -f1))"
else
    echo "[!] \$MFT not found"
fi

# ── Unmount ───────────────────────────────────────────────────────────────────
echo ""
echo "[*] Unmounting..."
sudo umount "${FS_MOUNT}" 2>/dev/null && echo "[+] Filesystem unmounted"
fusermount -u "${EWF_MOUNT}" 2>/dev/null && echo "[+] E01 unmounted"
rmdir "${EWF_MOUNT}" "${FS_MOUNT}" 2>/dev/null || true

# ── Initialize case files ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

[ ! -f "${CASE_DIR}/prd.json" ] && [ -f "${REPO_ROOT}/prd.json" ] && \
    cp "${REPO_ROOT}/prd.json" "${CASE_DIR}/prd.json" && echo "[+] prd.json copied"
[ ! -f "${CASE_DIR}/findings.json" ] && echo '{"findings":[]}' > "${CASE_DIR}/findings.json"
[ ! -f "${CASE_DIR}/timeline.json" ] && echo '[]' > "${CASE_DIR}/timeline.json"

# ── Ready ─────────────────────────────────────────────────────────────────────
echo ""
echo "=== Ingest Complete ==="
echo ""
echo "Run the investigation:"
echo ""
echo "  export CASEFILE_CASE_ROOT=${CASE_DIR}"
echo "  export CASEFILE_CASE_DIR=${CASE_DIR}"
echo "  export CASEFILE_EXAMINER=\$(whoami)"
echo "  bash ${REPO_ROOT}/ralph.sh ${CASE_DIR}"
echo ""
