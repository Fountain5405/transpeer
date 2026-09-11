#!/bin/bash
# Five-seed replicas of the single-seed follow-ups in run_followups.sh:
# depth against uptime, 200 honest transpeers, and the tried table. Each
# run writes results_<name>_seeds.txt. Seed 1 is re-run on purpose so every
# file is self-contained and its seed-1 rows can be checked against the
# single-seed files (Shadow is deterministic per general.seed).
#
# Two chains run in parallel with SIM_PARALLELISM workers each (default 30,
# half the box). Data directories are keyed by scenario name, which carries
# attacker count, subnet level, policy and seed but not stop time or honest
# count, so the chains are built to be name-disjoint: chain A is A500 with
# S in {8,16,24,32,48}; chain B is A500 with S in {4,6}, then A1500. Within
# a chain the stop times run one after another.
#
#   ./run_replicas.sh        both chains in parallel, logs in /fast/tmp
#   ./run_replicas.sh a|b    one chain in the foreground

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../../.." || exit 1
export TMPDIR=/fast/tmp
export SIM_PARALLELISM="${SIM_PARALLELISM:-30}"
R=sim/tests/bootstrap_eclipse
SEEDS="${SEEDS:-1 2 3 4 5}"

run() {
    local name="$1"; shift
    echo "=== $name start $(date +%H:%M:%S) ==="
    rm -f "$R/results_${name}_seeds.txt"
    env RESULTS_FILE="$R/results_${name}_seeds.txt" "$@" "./$R/run_experiment.sh" \
        > "/fast/tmp/eclipse_${name}_seeds.log" 2>&1
    echo "=== $name done $(date +%H:%M:%S) rc=$? cells=$(grep -c '^Done:' "/fast/tmp/eclipse_${name}_seeds.log") ==="
}

# Chain A: 200 honest. The 60-minute window carries the headline claim
# (crossover between 24 and 32 prefixes), so it runs first.
chain_a() {
    for stop in 3900 1200; do
        run "h200_${stop}" HONEST=200 ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
            SUBNET_LEVELS="8 16 24 32 48" POLICIES=bucketed_vouchers \
            STOP_TIME="$stop" SEEDS="$SEEDS"
    done
}

# Chain B: depth against uptime (15, 30, 60, 120 simulated minutes), then
# late attackers against an established node with and without the tried
# table.
chain_b() {
    for stop in 1200 2100 3900 7500; do
        run "uptime_${stop}" ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
            SUBNET_LEVELS="4 6" POLICIES=bucketed_vouchers \
            STOP_TIME="$stop" SEEDS="$SEEDS"
    done
    run tried_late ATTACKER_MODE=coordinated ATTACKER_COUNTS=1500 \
        SUBNET_LEVELS="6 spread" \
        POLICIES="current current_tried bucketed_vouchers bucketed_vouchers_tried" \
        ATTACKER_START=1500 STOP_TIME=3000 SEEDS="$SEEDS"
}

case "${1:-both}" in
    a) chain_a ;;
    b) chain_b ;;
    both)
        chain_a > /fast/tmp/eclipse_replicas_a.log 2>&1 &
        chain_b > /fast/tmp/eclipse_replicas_b.log 2>&1 &
        wait
        ;;
    *) echo "usage: $0 [a|b|both]" >&2; exit 2 ;;
esac
echo "=== replicas finished $(date) ==="
