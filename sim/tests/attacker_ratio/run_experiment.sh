#!/bin/bash
# Run the attacker-ratio experiment across varying attacker percentages.
#
# For each trial: 600 total hosts, varying attacker percentage.
# Each trial gets its own config and data directory.
# Results summary saved to results.txt.

set -u

TOTAL=600
STOP_TIME=900  # 15 minutes simulated — gives 3 query cycles
SEED=42
# Machine-specific paths (shadow binary, interpreter, storage) live in
# sim/simenv.sh. Override any of them from the environment.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../simenv.sh"
simenv_check || exit 1
simenv_check_space
TEST_DIR="$TRANSPEER_DIR/sim/tests/attacker_ratio"
RESULTS="$TEST_DIR/results.txt"

# Attacker percentages to test
PERCENTAGES=(10 25 50)

echo "# Transpeer attacker-ratio experiment" > "$RESULTS"
echo "# Total hosts: $TOTAL, simulated time: ${STOP_TIME}s, seed: $SEED" >> "$RESULTS"
echo "# Started: $(date)" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "pct,honest,attackers,real_time_sec,peak_mem_mb,honest1_discovered,honest1_peer_store_final" >> "$RESULTS"

cd "$TEST_DIR"

for pct in "${PERCENTAGES[@]}"; do
    echo ""
    echo "=========================================="
    echo "Trial: ${pct}% attackers (started $(date +%H:%M:%S))"
    echo "=========================================="

    CONFIG="configs/shadow_pct_$(printf '%02d' $pct).yaml"
    DATA_DIR="$SIM_DATA_ROOT/attacker_ratio/pct_$(printf '%02d' $pct)"
    mkdir -p "$(dirname "$DATA_DIR")"

    # Generate config
    "$TRANSPEER_PYTHON" "$TRANSPEER_DIR/sim/gen_scale_test.py" \
        --total "$TOTAL" --attacker-pct "$pct" \
        --stop-time "$STOP_TIME" --seed "$SEED" \
        --output "$CONFIG"

    # Clean previous data and run
    rm -rf "$DATA_DIR"

    START=$(date +%s)

    # Run Shadow with data dir pointed at our test folder
    cd "$TEST_DIR"
    "$SHADOW_BIN" -d "$DATA_DIR" "$CONFIG" > "$DATA_DIR.log" 2>&1 &
    SHADOW_PID=$!

    # Monitor peak memory during run
    PEAK_MEM=0
    while kill -0 $SHADOW_PID 2>/dev/null; do
        CUR_MEM=$(ps -o rss= -p $SHADOW_PID 2>/dev/null | tr -d ' ')
        TOTAL_MEM=$(ps -e -o rss= 2>/dev/null | awk '{s+=$1} END {print s}')
        if [ "${TOTAL_MEM:-0}" -gt "$PEAK_MEM" ]; then
            PEAK_MEM=$TOTAL_MEM
        fi
        sleep 15
    done

    wait $SHADOW_PID
    END=$(date +%s)
    ELAPSED=$((END - START))
    PEAK_MEM_MB=$((PEAK_MEM / 1024))


    # Parse results from honest1
    HONEST1_LOG="$DATA_DIR/hosts/honest1/python3.12.1000.stderr"
    DISCOVERED=0
    PEERS_TOTAL=0
    PEERS_FROM_ATTACKER=0
    if [ -f "$HONEST1_LOG" ]; then
        DISCOVERED=$(grep "Discovered transpeer" "$HONEST1_LOG" 2>/dev/null | \
            awk -F"at " '{print $2}' | awk '{print $1}' | sort -u | wc -l)
        PEERS_TOTAL=$(grep -oP 'Got \K\d+' "$HONEST1_LOG" | awk '{s+=$1} END {print s+0}')
    fi

    ATTACKERS=$(echo "scale=0; $TOTAL * $pct / 100" | bc)
    HONEST=$((TOTAL - ATTACKERS))

    echo "$pct,$HONEST,$ATTACKERS,$ELAPSED,$PEAK_MEM_MB,$DISCOVERED,$PEERS_TOTAL" >> "$RESULTS"
    echo "Trial done: ${pct}%, elapsed=${ELAPSED}s, discovered=$DISCOVERED, peers_received=$PEERS_TOTAL"
done

echo ""
echo "=========================================="
echo "All trials complete. Results:"
echo "=========================================="
cat "$RESULTS"
