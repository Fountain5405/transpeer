#!/bin/bash
# scale_baseline — find the practical host-count ceiling on this machine.
#
# The previous machine (31 GB) topped out near 700 hosts and was memory-bound.
# This box has 251 GB of RAM plus 128 GB of Optane swap, so memory is no
# longer the limit; wall-clock from N^2 gossip is expected to bind first.
# This test measures both so we can size bootstrap_eclipse and long_running.
#
# All honest, no attackers: we want the cost of the protocol itself, not of
# an attack. Results append to results.txt after every scenario, so a partial
# run is still useful if a later scenario is aborted.

set -u

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../simenv.sh"
simenv_check || exit 1
simenv_check_space

TEST_DIR="$TRANSPEER_DIR/sim/tests/scale_baseline"
RESULTS="$TEST_DIR/results.txt"
DATA_ROOT="$SIM_DATA_ROOT/scale_baseline"
STOP_TIME="${STOP_TIME:-900}"       # 15 min simulated, matches attacker_ratio
SEED="${SEED:-42}"
HOST_COUNTS="${HOST_COUNTS:-700 1500 3000 5000}"

# Guards. /fast/tmp is shared with other users, so stop well short of full.
MIN_FREE_DISK_GB="${MIN_FREE_DISK_GB:-80}"
MEM_PER_HOST_MB="${MEM_PER_HOST_MB:-40}"   # measured on the previous machine
# Fraction of available memory a scenario may be projected to need.
MEM_HEADROOM_PCT="${MEM_HEADROOM_PCT:-85}"
# Compress each scenario's host logs once metrics are extracted. Set
# KEEP_RAW=1 to leave the raw tree in place instead.
KEEP_RAW="${KEEP_RAW:-0}"

mkdir -p "$DATA_ROOT" "$TEST_DIR/configs"

if [ ! -f "$RESULTS" ]; then
    {
        echo "# Transpeer scale_baseline experiment"
        echo "# Machine: $(nproc) threads, $(free -g | awk '/^Mem:/{print $2}') GB RAM"
        echo "# Shadow: $("$SHADOW_BIN" --version 2>/dev/null | head -1)"
        echo "# Simulated time: ${STOP_TIME}s, seed: $SEED, parallelism: $SIM_PARALLELISM"
        echo "# Started: $(date)"
        echo ""
        echo "hosts,real_time_sec,sim_advance_ratio,run_mem_mb,abs_peak_mem_mb,peak_swap_mb,data_size_mb,honest1_discovered,status"
    } > "$RESULTS"
fi

free_disk_gb() { df -BG --output=avail "$DATA_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9'; }
avail_mem_mb()  { awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo; }
used_mem_mb()   { awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{print int((t-a)/1024)}' /proc/meminfo; }
used_swap_mb()  { awk '/^SwapTotal:/{t=$2} /^SwapFree:/{f=$2} END{print int((t-f)/1024)}' /proc/meminfo; }

for HOSTS in $HOST_COUNTS; do
    echo ""
    echo "=========================================="
    echo "Scenario: $HOSTS hosts (started $(date +%H:%M:%S))"
    echo "=========================================="

    # --- Guards before committing to a long run --------------------------
    FREE_GB=$(free_disk_gb)
    if [ "${FREE_GB:-0}" -lt "$MIN_FREE_DISK_GB" ]; then
        echo "ABORT: only ${FREE_GB}GB free on $DATA_ROOT, need ${MIN_FREE_DISK_GB}GB"
        echo "$HOSTS,0,0,0,0,0,0,0,aborted_disk" >> "$RESULTS"
        break
    fi
    PROJECTED_MB=$(( HOSTS * MEM_PER_HOST_MB ))
    BUDGET_MB=$(( $(avail_mem_mb) * MEM_HEADROOM_PCT / 100 ))
    if [ "$PROJECTED_MB" -gt "$BUDGET_MB" ]; then
        echo "ABORT: $HOSTS hosts projected at ${PROJECTED_MB}MB exceeds ${BUDGET_MB}MB budget"
        echo "$HOSTS,0,0,0,0,0,0,0,aborted_memory" >> "$RESULTS"
        break
    fi
    echo "  projected ${PROJECTED_MB}MB of ${BUDGET_MB}MB budget, ${FREE_GB}GB disk free"

    CONFIG="$TEST_DIR/configs/hosts_${HOSTS}.yaml"
    DATA_DIR="$DATA_ROOT/hosts_${HOSTS}"
    rm -rf "$DATA_DIR"

    "$TRANSPEER_PYTHON" "$TRANSPEER_DIR/sim/gen_scale_test.py" \
        --honest "$HOSTS" --attackers 0 \
        --stop-time "$STOP_TIME" --seed "$SEED" \
        --output "$CONFIG" || { echo "config generation failed"; break; }

    # --- Run, sampling memory as we go -----------------------------------
    # Other work runs on this box, so record the delta this run adds as
    # well as the absolute system peak.
    BASE_MEM=$(used_mem_mb)
    START=$(date +%s)
    "$SHADOW_BIN" -d "$DATA_DIR" "$CONFIG" > "$DATA_DIR.log" 2>&1 &
    SHADOW_PID=$!

    PEAK_MEM=0; PEAK_SWAP=0
    while kill -0 $SHADOW_PID 2>/dev/null; do
        M=$(used_mem_mb); S=$(used_swap_mb)
        [ "${M:-0}" -gt "$PEAK_MEM" ] && PEAK_MEM=$M
        [ "${S:-0}" -gt "$PEAK_SWAP" ] && PEAK_SWAP=$S
        sleep 15
    done
    wait $SHADOW_PID
    SHADOW_RC=$?
    END=$(date +%s)
    ELAPSED=$((END - START))

    STATUS="ok"
    [ "$SHADOW_RC" -ne 0 ] && STATUS="shadow_rc_${SHADOW_RC}"
    grep -q "Shadow completed successfully" "$DATA_DIR.log" 2>/dev/null || STATUS="incomplete"

    # Simulated seconds per real second. Higher is better.
    RATIO=$(awk -v s="$STOP_TIME" -v e="$ELAPSED" 'BEGIN{printf "%.3f", (e>0? s/e : 0)}')

    HONEST1_LOG="$DATA_DIR/hosts/honest1/python3.12.1000.stderr"
    DISCOVERED=0
    if [ -f "$HONEST1_LOG" ]; then
        DISCOVERED=$(grep "Discovered transpeer" "$HONEST1_LOG" 2>/dev/null | \
            awk -F"at " '{print $2}' | awk '{print $1}' | sort -u | wc -l)
    fi

    DATA_MB=$(du -sm "$DATA_DIR" 2>/dev/null | cut -f1)

    RUN_MEM=$(( PEAK_MEM - BASE_MEM )); [ "$RUN_MEM" -lt 0 ] && RUN_MEM=0
    echo "$HOSTS,$ELAPSED,$RATIO,$RUN_MEM,$PEAK_MEM,$PEAK_SWAP,${DATA_MB:-0},$DISCOVERED,$STATUS" >> "$RESULTS"
    echo "Done: $HOSTS hosts, ${ELAPSED}s real, ratio=${RATIO}x, run_mem=${RUN_MEM}MB (abs ${PEAK_MEM}MB), swap=${PEAK_SWAP}MB, data=${DATA_MB}MB, discovered=$DISCOVERED, $STATUS"

    # --- Reclaim space on the shared volume ------------------------------
    # Metrics are already extracted; keep everything, just compressed.
    if [ "$KEEP_RAW" != "1" ] && [ "$STATUS" = "ok" ] && [ -d "$DATA_DIR/hosts" ]; then
        echo "  compressing host logs..."
        if command -v pigz >/dev/null 2>&1; then
            tar -C "$DATA_DIR" -cf - hosts | pigz -1 > "$DATA_DIR/hosts.tar.gz"
        else
            tar -C "$DATA_DIR" -cf - hosts | gzip -1 > "$DATA_DIR/hosts.tar.gz"
        fi
        if [ -s "$DATA_DIR/hosts.tar.gz" ]; then
            rm -rf "$DATA_DIR/hosts"
            echo "  archived to hosts.tar.gz ($(du -sm "$DATA_DIR" | cut -f1)MB)"
        else
            echo "  compression failed, keeping raw tree"
        fi
    fi

    if [ "$STATUS" != "ok" ]; then
        echo "Stopping ramp: last scenario ended '$STATUS'"
        break
    fi
done

echo ""
echo "=========================================="
cat "$RESULTS"
