#!/bin/bash
# bootstrap_eclipse — attacker IP count x attacker subnet count x policy.
# See README.md for the design and hypothesis.
#
# Grid (cells where an integer subnet count exceeds the attacker count are
# skipped):
#   attackers:  50 150 500 1500
#   subnets:    concentrated 25 100 spread
#   policy:     current bucketed
#
# Small cells run first so early rows are useful while the big ones grind.
# Results append after every scenario.

set -u

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../simenv.sh"
simenv_check || exit 1
simenv_check_space

TEST_DIR="$TRANSPEER_DIR/sim/tests/bootstrap_eclipse"
# Override RESULTS_FILE to keep a rerun's rows apart from the main grid.
RESULTS="${RESULTS_FILE:-$TEST_DIR/results.txt}"
DATA_ROOT="$SIM_DATA_ROOT/bootstrap_eclipse"

HONEST="${HONEST:-50}"
# The fresh node queries every 300s, so a 900s stop gives it one query
# cycle of 20. Run to 1200s for three cycles: enough queries to make
# query_attacker_pct a real number.
STOP_TIME="${STOP_TIME:-1200}"
FRESH_START="${FRESH_START:-300}"
SEED="${SEED:-42}"
ATTACKER_COUNTS="${ATTACKER_COUNTS:-50 150 500 1500}"
SUBNET_LEVELS="${SUBNET_LEVELS:-concentrated 25 100 spread}"
POLICIES="${POLICIES:-current bucketed}"
# independent: each attacker serves random fakes for a random network.
# coordinated: all attackers serve one shared fake set for the fresh
# node's network, so each fake gets one voucher per attacker subnet.
ATTACKER_MODE="${ATTACKER_MODE:-independent}"

MIN_FREE_DISK_GB="${MIN_FREE_DISK_GB:-80}"
MEM_PER_HOST_MB="${MEM_PER_HOST_MB:-40}"
MEM_HEADROOM_PCT="${MEM_HEADROOM_PCT:-85}"
KEEP_RAW="${KEEP_RAW:-0}"

mkdir -p "$DATA_ROOT" "$TEST_DIR/configs"

if [ ! -f "$RESULTS" ]; then
    {
        echo "# Transpeer bootstrap_eclipse experiment"
        echo "# Honest: $HONEST, fresh node starts at ${FRESH_START}s, simulated time: ${STOP_TIME}s, seed: $SEED"
        echo "# Attacker mode: $ATTACKER_MODE"
        echo "# Machine: $(nproc) threads, $(free -g | awk '/^Mem:/{print $2}') GB RAM, parallelism: $SIM_PARALLELISM"
        echo "# Started: $(date)"
        echo ""
        echo "scenario,attackers,attacker_subnets,policy,real_time_sec,run_mem_mb,store_total,store_attacker_pct,honest_known,buckets,queries_total,query_attacker_pct,peers_total,peer_attacker_pct,multi_voucher_pct,daemon_attacker_pct,top20_honest_max_vouchers,top20_attacker_min_vouchers,snapshots,status"
    } > "$RESULTS"
fi

free_disk_gb() { df -BG --output=avail "$DATA_ROOT" 2>/dev/null | tail -1 | tr -dc '0-9'; }
avail_mem_mb()  { awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo; }
used_mem_mb()   { awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{print int((t-a)/1024)}' /proc/meminfo; }

run_scenario() {
    local A="$1" S="$2" POLICY="$3"
    local NAME="A${A}_S${S}_${POLICY}"
    local MODE_FLAGS=""
    if [ "$ATTACKER_MODE" = "coordinated" ]; then
        NAME="${NAME}_coord"
        MODE_FLAGS="--coordinated"
    fi
    local TOTAL=$((HONEST + 1 + A))

    echo ""
    echo "=========================================="
    echo "Scenario: $NAME ($TOTAL hosts, started $(date +%H:%M:%S))"
    echo "=========================================="

    local FREE_GB; FREE_GB=$(free_disk_gb)
    if [ "${FREE_GB:-0}" -lt "$MIN_FREE_DISK_GB" ]; then
        echo "ABORT: only ${FREE_GB}GB free on $DATA_ROOT"
        echo "$NAME,$A,$S,$POLICY,0,0,0,0.0,0,0,0,0.0,0,0.0,0.0,0.0,0,0,0,aborted_disk" >> "$RESULTS"
        return 1
    fi
    local PROJECTED=$((TOTAL * MEM_PER_HOST_MB))
    local BUDGET=$(( $(avail_mem_mb) * MEM_HEADROOM_PCT / 100 ))
    if [ "$PROJECTED" -gt "$BUDGET" ]; then
        echo "ABORT: projected ${PROJECTED}MB exceeds ${BUDGET}MB budget"
        echo "$NAME,$A,$S,$POLICY,0,0,0,0.0,0,0,0,0.0,0,0.0,0.0,0.0,0,0,0,aborted_memory" >> "$RESULTS"
        return 1
    fi

    local CONFIG="$TEST_DIR/configs/${NAME}.yaml"
    local DATA_DIR="$DATA_ROOT/$NAME"
    rm -rf "$DATA_DIR"

    local POLICY_FLAGS=""
    case "$POLICY" in
        current) ;;
        bucketed) POLICY_FLAGS="--bucketed" ;;
        bucketed_vouchers) POLICY_FLAGS="--bucketed --vouchers" ;;
        *) echo "unknown policy: $POLICY"; return 1 ;;
    esac

    local GEN_OUT
    GEN_OUT=$("$TRANSPEER_PYTHON" "$TEST_DIR/gen_config.py" \
        --honest "$HONEST" --attackers "$A" --attacker-subnets "$S" $POLICY_FLAGS $MODE_FLAGS \
        --stop-time "$STOP_TIME" --fresh-start "$FRESH_START" --seed "$SEED" \
        --output "$CONFIG") || { echo "config generation failed"; return 1; }
    echo "$GEN_OUT" | grep -v ECLIPSE_LAYOUT
    local LAYOUT; LAYOUT=$(echo "$GEN_OUT" | grep ECLIPSE_LAYOUT)
    local S_ACTUAL FIRST_ATT FRESH_B
    S_ACTUAL=$(echo "$LAYOUT" | grep -oP 'attacker_subnets=\K\d+')
    FIRST_ATT=$(echo "$LAYOUT" | grep -oP 'first_attacker_bucket=\K\d+')
    FRESH_B=$(echo "$LAYOUT" | grep -oP 'fresh_bucket=\K\d+')

    local BASE_MEM; BASE_MEM=$(used_mem_mb)
    local START; START=$(date +%s)
    "$SHADOW_BIN" -d "$DATA_DIR" "$CONFIG" > "$DATA_DIR.log" 2>&1 &
    local PID=$!
    local PEAK_MEM=0 M
    while kill -0 $PID 2>/dev/null; do
        M=$(used_mem_mb)
        [ "${M:-0}" -gt "$PEAK_MEM" ] && PEAK_MEM=$M
        sleep 15
    done
    wait $PID
    local RC=$?
    local ELAPSED=$(( $(date +%s) - START ))
    local RUN_MEM=$(( PEAK_MEM - BASE_MEM )); [ "$RUN_MEM" -lt 0 ] && RUN_MEM=0

    local STATUS="ok"
    [ "$RC" -ne 0 ] && STATUS="shadow_rc_${RC}"
    grep -q "Shadow completed successfully" "$DATA_DIR.log" 2>/dev/null || STATUS="incomplete"

    local METRICS
    METRICS=$("$TRANSPEER_PYTHON" "$TEST_DIR/parse_fresh.py" \
        "$DATA_DIR/hosts/fresh/python3.12.1000.stderr" \
        --honest "$HONEST" --fresh-bucket "$FRESH_B" --first-attacker-bucket "$FIRST_ATT")

    echo "$NAME,$A,$S_ACTUAL,$POLICY,$ELAPSED,$RUN_MEM,$METRICS,$STATUS" >> "$RESULTS"
    echo "Done: $NAME elapsed=${ELAPSED}s mem=${RUN_MEM}MB metrics=[$METRICS] $STATUS"

    if [ "$KEEP_RAW" != "1" ] && [ "$STATUS" = "ok" ] && [ -d "$DATA_DIR/hosts" ]; then
        # Keep the fresh node's log uncompressed: it is the one we re-read.
        cp "$DATA_DIR/hosts/fresh/python3.12.1000.stderr" "$DATA_DIR/fresh.stderr" 2>/dev/null
        if command -v pigz >/dev/null 2>&1; then
            tar -C "$DATA_DIR" -cf - hosts | pigz -1 > "$DATA_DIR/hosts.tar.gz"
        else
            tar -C "$DATA_DIR" -cf - hosts | gzip -1 > "$DATA_DIR/hosts.tar.gz"
        fi
        [ -s "$DATA_DIR/hosts.tar.gz" ] && rm -rf "$DATA_DIR/hosts"
    fi
    [ "$STATUS" = "ok" ]
}

for A in $ATTACKER_COUNTS; do
    for S in $SUBNET_LEVELS; do
        case "$S" in
            ''|*[!0-9]*) ;;                       # named level, always valid
            *) [ "$S" -gt "$A" ] && { echo "skip A=$A S=$S"; continue; } ;;
        esac
        for POLICY in $POLICIES; do
            run_scenario "$A" "$S" "$POLICY" || {
                # A resource abort stops the ramp; a failed sim moves on.
                tail -1 "$RESULTS" | grep -q aborted && exit 1
            }
        done
    done
done

echo ""
echo "=========================================="
cat "$RESULTS"
