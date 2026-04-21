#!/bin/bash
# Run handshake-PoW experiment across scenarios.
#
# Scenarios:
#   A. baseline:     no flooders
#   B. low_flood:    5 flooders @ 2 req/s, don't solve PoW (attacker is blocked)
#   C. medium_flood: 10 flooders @ 5 req/s, don't solve PoW
#   D. solving:      10 flooders @ 5 req/s, DO solve PoW (measure attacker cost)
#   E. heavy_flood:  20 flooders @ 10 req/s, solving

set -u

HONEST=20
STOP_TIME=900  # 15 min simulated
TRANSPEER_DIR="/home/lever65/transpeer"
SHADOW_BIN="/home/lever65/monerosim_dev/shadowformonero/build/src/main/shadow"
TEST_DIR="$TRANSPEER_DIR/sim/tests/handshake_pow"
RESULTS="$TEST_DIR/results.txt"

# Each flooder stays UNDER per-IP rate limit (1 req/s) to actually exercise
# the handshake PoW layer. Aggregate volume comes from scaling flooder count.
declare -A SCENARIOS=(
    [A_baseline]="--flooders 0 --flood-rate 0"
    [B_distributed_low]="--flooders 30 --flood-rate 0.8"
    [C_distributed_med]="--flooders 60 --flood-rate 0.8"
    [D_distributed_high]="--flooders 100 --flood-rate 0.8"
    [E_dist_high_solving]="--flooders 100 --flood-rate 0.8 --solve-pow"
)

ORDER=(A_baseline B_distributed_low C_distributed_med D_distributed_high E_dist_high_solving)

echo "# Transpeer handshake-PoW experiment" > "$RESULTS"
echo "# Honest: $HONEST, simulated time: ${STOP_TIME}s" >> "$RESULTS"
echo "# Started: $(date)" >> "$RESULTS"
echo "" >> "$RESULTS"
echo "scenario,real_time_sec,victim_peak_difficulty,flooder_total_200,flooder_total_402,flooder_total_429,flooder_pow_solves,flooder_pow_time" >> "$RESULTS"

cd "$TEST_DIR"

for name in "${ORDER[@]}"; do
    echo ""
    echo "=========================================="
    echo "Scenario: $name (started $(date +%H:%M:%S))"
    echo "=========================================="

    CONFIG="configs/${name}.yaml"
    DATA_DIR="data/${name}"
    LOG="data/${name}.log"

    rm -rf "$DATA_DIR" "$TEST_DIR/shadow.data"

    # Generate config
    python3 "$TEST_DIR/gen_config.py" \
        --honest "$HONEST" \
        --stop-time "$STOP_TIME" \
        --name "$name" \
        --output "$CONFIG" \
        ${SCENARIOS[$name]}

    START=$(date +%s)
    "$SHADOW_BIN" "$CONFIG" > "$LOG" 2>&1
    END=$(date +%s)
    ELAPSED=$((END - START))

    # Move data dir
    if [ -d "$TEST_DIR/shadow.data" ]; then
        mv "$TEST_DIR/shadow.data" "$DATA_DIR"
    fi

    # Parse victim's peak difficulty
    VICTIM_LOG="$DATA_DIR/hosts/victim/python3.12.1000.stderr"
    PEAK_DIFFICULTY=0
    if [ -f "$VICTIM_LOG" ]; then
        PEAK_DIFFICULTY=$(grep -oP 'HANDSHAKE_DIFFICULTY: \d+ -> \K\d+' "$VICTIM_LOG" | sort -n | tail -1)
        PEAK_DIFFICULTY=${PEAK_DIFFICULTY:-0}
    fi

    # Parse flooder stats (sum across all flooders)
    F200=0; F402=0; F429=0; FSOLVES=0; FTIME=0
    for flooder_dir in "$DATA_DIR"/hosts/flooder*; do
        if [ -d "$flooder_dir" ]; then
            FLOG="$flooder_dir/python3.12.1000.stderr"
            [ -f "$FLOG" ] || continue
            # Last FLOODER STATS line has cumulative counts
            last=$(grep "FLOODER STATS:" "$FLOG" | tail -1)
            if [ -n "$last" ]; then
                n200=$(echo "$last" | grep -oP '200=\K\d+')
                n402=$(echo "$last" | grep -oP '402=\K\d+')
                n429=$(echo "$last" | grep -oP '429=\K\d+')
                nsolves=$(echo "$last" | grep -oP 'pow_solves=\K\d+')
                ntime=$(echo "$last" | grep -oP 'pow_time=\K[0-9.]+')
                F200=$((F200 + ${n200:-0}))
                F402=$((F402 + ${n402:-0}))
                F429=$((F429 + ${n429:-0}))
                FSOLVES=$((FSOLVES + ${nsolves:-0}))
                FTIME=$(echo "$FTIME + ${ntime:-0}" | bc)
            fi
        fi
    done

    echo "$name,$ELAPSED,$PEAK_DIFFICULTY,$F200,$F402,$F429,$FSOLVES,$FTIME" >> "$RESULTS"
    echo "Done: ${name}, elapsed=${ELAPSED}s, peak_diff=$PEAK_DIFFICULTY, 200=$F200 402=$F402 429=$F429 solves=$FSOLVES"
done

echo ""
echo "=========================================="
echo "All scenarios complete."
echo "=========================================="
cat "$RESULTS"
