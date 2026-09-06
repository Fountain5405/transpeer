#!/bin/bash
# Run one experiment after another finishes.
#
#   queue_after.sh <pattern-of-running-runner> <ready-file> <next-runner>
#
# Waits until no process matches <pattern>, and until <ready-file> exists,
# then executes <next-runner>. The ready file lets the next experiment be
# queued before its code is finished: touch it when the runner is validated,
# and nothing starts early.
#
# Runs under nohup with its own log, so it survives the session that
# launched it.

set -u

PATTERN="$1"
READY="$2"
NEXT="$3"

echo "$(date) queued: '$NEXT'"
echo "$(date) waiting for '$PATTERN' to exit and '$READY' to appear"

# pgrep -f would match this script's own command line, which carries the
# pattern as an argument, so exclude our own PID.
still_running() { pgrep -f -- "$PATTERN" | grep -qvx "$$"; }
while still_running; do
    sleep 60
done
echo "$(date) '$PATTERN' has exited"

while [ ! -f "$READY" ]; do
    sleep 60
done
echo "$(date) ready file present"

# Let the previous run's compression and disk writes settle.
sleep 30

echo "$(date) starting '$NEXT'"
"$NEXT"
RC=$?
echo "$(date) '$NEXT' finished with exit code $RC"
exit $RC
