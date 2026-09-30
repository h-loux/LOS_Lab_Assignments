#!/bin/bash
# log_search.sh - search a log file for failed, denied, unauthorized and error

if [ $# -lt 1 ]; then
    echo "Usage: $0 <logfile>" >&2
    exit 1
fi
LOG="$1"

if [ ! -f "$LOG" ] || [ ! -r "$LOG" ]; then
    echo "Error: '$LOG' is not a readable file." >&2
    exit 2
fi

for WORD in failed denied unauthorized error; do
    COUNT=$(grep -i -c -- "$WORD" "$LOG")
    echo "=== '$WORD': $COUNT matching line(s) ==="
    if [ "$COUNT" -gt 0 ]; then
        grep -i -n -- "$WORD" "$LOG"
    fi
    echo
done

TOTAL=$(grep -i -c -E 'failed|denied|unauthorized|error' "$LOG")
echo "Lines containing at least one keyword: $TOTAL"
