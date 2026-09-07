#!/bin/bash
# Four follow-up experiments, run back to back. Each writes its own results
# file so headers (which record stop time and honest count) stay truthful.
#
#   1. crossover_seeds  five replicas per cell around the crossover
#   2. uptime_<stop>    depth against the fresh node's window, 15 to 120 min
#   3. h200_<stop>      200 honest transpeers, 15 and 60 min windows
#   4. tried_late       late attackers against an established node, with
#                       and without the tried table
#
# All coordinated, 500 attackers unless stated, bucketed_vouchers unless
# the policy is the variable.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../../.." || exit 1
export TMPDIR=/fast/tmp
R=sim/tests/bootstrap_eclipse

run() {
    local name="$1"; shift
    echo "=== $name start $(date +%H:%M:%S) ==="
    rm -f "$R/results_${name}.txt"
    env RESULTS_FILE="$R/results_${name}.txt" "$@" "./$R/run_experiment.sh" \
        > "/fast/tmp/eclipse_${name}.log" 2>&1
    echo "=== $name done $(date +%H:%M:%S) rc=$? cells=$(grep -c '^Done:' "/fast/tmp/eclipse_${name}.log") ==="
}

# 1. Replicas. Both the generator and Shadow take the seed, so each replica
#    is a different honest layout and different node randomness.
run crossover_seeds ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
    SUBNET_LEVELS="3 4 5 6 8" POLICIES=bucketed_vouchers SEEDS="1 2 3 4 5"

# 2. Depth against uptime. Fresh node starts at 300 s; windows of 15, 30,
#    60 and 120 simulated minutes. Subnet counts either side of the crossover.
for stop in 1200 2100 3900 7500; do
    run "uptime_${stop}" ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
        SUBNET_LEVELS="4 6" POLICIES=bucketed_vouchers STOP_TIME="$stop" SEEDS="1"
done

# 3. 200 honest. The fresh node's 60 queries in 15 minutes cover a quarter
#    of 200 honest transpeers, so run a 60-minute window as well. Subnet
#    levels bracket the predicted crossover (about a fifth of the ~120
#    honest transpeers on the primary network).
for stop in 1200 3900; do
    run "h200_${stop}" HONEST=200 ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
        SUBNET_LEVELS="8 16 24 32 48" POLICIES=bucketed_vouchers STOP_TIME="$stop" SEEDS="1"
done

# 4. Tried table. Attackers start at 1500 s, by which time the fresh node
#    (up since 300 s) has completed four query cycles and its honest
#    transpeers have answered at least twice. Attack runs to 3000 s.
run tried_late ATTACKER_MODE=coordinated ATTACKER_COUNTS=1500 \
    SUBNET_LEVELS="6 spread" \
    POLICIES="current current_tried bucketed_vouchers bucketed_vouchers_tried" \
    ATTACKER_START=1500 STOP_TIME=3000 SEEDS="1"

echo "=== all follow-ups finished $(date) ==="
