#!/bin/bash
# investigate.sh - interactive log search for an investigator

if [ $# -lt 1 ]; then
    echo "Usage: $0 <logfile>" >&2
    exit 1
fi
LOG="$1"

# Verify the file exists and is readable
if [ ! -e "$LOG" ]; then
    echo "Error: '$LOG' does not exist." >&2
    exit 2
fi
if [ ! -r "$LOG" ]; then
    echo "Error: '$LOG' is not readable." >&2
    exit 3
fi

echo -n "Enter a search term: "
read -r TERM_IN

if [ -z "$TERM_IN" ]; then
    echo "Error: the search term cannot be empty." >&2
    exit 4
fi

TOTAL=$(grep -i -c -F -- "$TERM_IN" "$LOG")

if [ "$TOTAL" -eq 0 ]; then
    echo "No records match '$TERM_IN'."
    exit 0
fi

echo "First 5 matching records:"
grep -i -F -- "$TERM_IN" "$LOG" | head -n 5
echo "Total matching records: $TOTAL"
