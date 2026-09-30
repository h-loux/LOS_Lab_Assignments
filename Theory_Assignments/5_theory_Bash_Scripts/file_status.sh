#!/bin/bash
# file_status.sh - check existence, regular-file status and emptiness

if [ $# -lt 1 ]; then
    echo "Usage: $0 <filename>" >&2
    exit 1
fi
F="$1"

if [ ! -e "$F" ]; then
    echo "'$F' does not exist."
    exit 2
fi
echo "'$F' exists."

if [ ! -f "$F" ]; then
    echo "'$F' is not a regular file."
    exit 3
fi
echo "'$F' is a regular file."

if [ -s "$F" ]; then
    echo "'$F' is non-empty. First 5 lines:"
    head -n 5 "$F"
else
    echo "'$F' is empty."
fi
