#!/bin/bash
# Shared environment for all Shadow experiments.
# Source this at the top of every run_experiment.sh:
#
#     source "$(dirname "${BASH_SOURCE[0]}")/../../simenv.sh"
#
# Every value can be overridden from the caller's environment, so a new
# machine only needs the overrides it actually differs on.

# --- Repo and interpreter ---------------------------------------------------
# Resolve the repo root from this file's location rather than hardcoding it.
SIM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${TRANSPEER_DIR:=$(cd "$SIM_DIR/.." && pwd)}"

# The system python3 on this box is 3.8; transpeer needs 3.10+ syntax.
# The venv is created by the bootstrap (uv venv --python 3.12 .venv).
: "${TRANSPEER_PYTHON:=$TRANSPEER_DIR/.venv/bin/python3.12}"

# --- Shadow -----------------------------------------------------------------
: "${SHADOW_BIN:=$HOME/.local/bin/shadow}"

# --- Storage ----------------------------------------------------------------
# Shadow writes one stderr file per simulated host, so a large run is many
# thousands of small files. That is the Optane volume's job, not home's.
#   /fast    - Optane, low latency, many small files. NOT redundant, NOT backed up.
#   /spinny  - redundant array. Finished results get archived here.
# Home holds only code, configs and the committed CSV summaries.
# NOTE: this account cannot create directories at the top level of /fast,
# /scratch or /spinny. /fast/tmp is world-writable and sticky (the MOTD
# recommends it), so the sim data root lives under it. If an admin creates
# /fast/transpeer-sim owned by this account, point SIM_DATA_ROOT there.
: "${SIM_DATA_ROOT:=/fast/tmp/transpeer-sim}"
# Archive target on the redundant array. Not writable by this account yet -
# an admin needs to create it. Until then archiving is skipped.
: "${SIM_ARCHIVE_ROOT:=/spinny/readfrom/transpeer-sim-archive}"
: "${TMPDIR:=/fast/tmp}"

# --- Parallelism ------------------------------------------------------------
# Shadow's worker thread count. The box has 64 threads; leave a few for the
# rest of the system. Override with SIM_PARALLELISM for smaller runs.
: "${SIM_PARALLELISM:=60}"

export TRANSPEER_DIR TRANSPEER_PYTHON SHADOW_BIN
export SIM_DATA_ROOT SIM_ARCHIVE_ROOT TMPDIR SIM_PARALLELISM

# --- Sanity checks ----------------------------------------------------------
simenv_check() {
    local ok=0
    if [ ! -x "$SHADOW_BIN" ]; then
        echo "simenv: shadow binary not found or not executable: $SHADOW_BIN" >&2
        ok=1
    fi
    if [ ! -x "$TRANSPEER_PYTHON" ]; then
        echo "simenv: python not found or not executable: $TRANSPEER_PYTHON" >&2
        ok=1
    fi
    if ! "$TRANSPEER_PYTHON" -c 'import aiohttp, yaml' 2>/dev/null; then
        echo "simenv: $TRANSPEER_PYTHON is missing aiohttp/pyyaml" >&2
        ok=1
    fi
    mkdir -p "$SIM_DATA_ROOT" "$TMPDIR" 2>/dev/null
    if [ ! -d "$SIM_DATA_ROOT" ]; then
        echo "simenv: cannot create SIM_DATA_ROOT: $SIM_DATA_ROOT" >&2
        ok=1
    fi
    return $ok
}

# Warn early when the work volume is filling up. /fast is small and shared.
simenv_check_space() {
    local pct
    pct=$(df --output=pcent "$SIM_DATA_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9')
    if [ -n "$pct" ] && [ "$pct" -ge 85 ]; then
        echo "simenv: WARNING $SIM_DATA_ROOT is ${pct}% full - archive or clean before a big run" >&2
    fi
}
