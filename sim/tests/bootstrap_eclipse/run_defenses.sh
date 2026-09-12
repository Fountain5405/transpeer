#!/bin/bash
# Two defenses against a colluding reporter majority, measured separately.
#
#   reserve   Hand-off reserve (--handoff-reserve K): the last K of the
#             daemon's 20 slots go to peers vouched by reporter buckets that
#             vouched for nothing in the ranked head. Against a corral
#             (attacker prefixes >> honest reporters) this is the only way an
#             honest peer reaches the daemon at all. Measured at K=5 and
#             K=10 across attacker prefix counts from below the crossover to
#             the spread case where voucher ranking alone gives 100 %.
#             The 200-honest cells measure the cost side: the foothold a
#             small attacker gets from the reserve where rank gave it none.
#
#   native    Native vouchers (--native-vouchers): a report counts first by
#             vouchers from transpeers whose host answers on the network's
#             daemon port. A cheap attacker (announce-only, no daemon) has
#             zero native vouchers; a full attacker (--attacker-native, one
#             listener per address) is unaffected. The experiment measures
#             both, so the defense's effect is stated as a cost transfer,
#             not a bound.
#
# Both chains run in parallel at 30 workers. Scenario names are disjoint
# (A1500 vs A500). Five seeds per cell, 15-minute window.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/../../.." || exit 1
export TMPDIR=/fast/tmp
export SIM_PARALLELISM="${SIM_PARALLELISM:-30}"
R=sim/tests/bootstrap_eclipse
SEEDS="${SEEDS:-1 2 3 4 5}"

run() {
    local name="$1"; shift
    echo "=== $name start $(date +%H:%M:%S) ==="
    rm -f "$R/results_${name}.txt"
    env RESULTS_FILE="$R/results_${name}.txt" "$@" "./$R/run_experiment.sh" \
        > "/fast/tmp/eclipse_${name}.log" 2>&1
    echo "=== $name done $(date +%H:%M:%S) rc=$? cells=$(grep -c '^Done:' "/fast/tmp/eclipse_${name}.log") ==="
}

chain_reserve() {
    for k in 5 10; do
        run "reserve${k}" RESERVE=$k ATTACKER_MODE=coordinated ATTACKER_COUNTS=1500 \
            SUBNET_LEVELS="6 25 50 100 spread" \
            POLICIES="bucketed_vouchers bucketed_vouchers_reserve" \
            STOP_TIME=1200 SEEDS="$SEEDS"
    done
    # Cost side: 200 honest, small attackers below the crossover.
    run "reserve5_h200" RESERVE=5 HONEST=200 ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
        SUBNET_LEVELS="8 16" POLICIES="bucketed_vouchers bucketed_vouchers_reserve" \
        STOP_TIME=3900 SEEDS="$SEEDS"
}

chain_native() {
    # Cheap attacker: announces, serves fakes, no daemon port.
    run "native_cheap" ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
        SUBNET_LEVELS="6 8 25" POLICIES="bucketed_vouchers bucketed_vouchers_native" \
        STOP_TIME=1200 SEEDS="$SEEDS"
    # Full attacker: also listens on the target network's daemon port.
    run "native_full" ATTACKER_NATIVE=1 ATTACKER_MODE=coordinated ATTACKER_COUNTS=500 \
        SUBNET_LEVELS="6 8 25" POLICIES="bucketed_vouchers_native" \
        STOP_TIME=1200 SEEDS="$SEEDS"
}

case "${1:-both}" in
    reserve) chain_reserve ;;
    native) chain_native ;;
    both)
        chain_reserve > /fast/tmp/eclipse_defenses_reserve.log 2>&1 &
        chain_native > /fast/tmp/eclipse_defenses_native.log 2>&1 &
        wait
        ;;
    *) echo "usage: $0 [reserve|native|both]" >&2; exit 2 ;;
esac
echo "=== defenses finished $(date) ==="
