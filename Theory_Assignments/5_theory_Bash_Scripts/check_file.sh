#!/bin/bash
# check_file.sh - show the first 5 lines of a file given as the first argument

# 1. Was an argument supplied?
if [ $# -lt 1 ]; then
    echo "Error: no filename supplied." >&2
    echo "Usage: $0 <filename>" >&2
    exit 1
fi

FILE="$1"

# 2. Does it exist (as a regular file)?
if [ -f "$FILE" ]; then
    echo "File '$FILE' exists. First 5 lines:"
    head -n 5 "$FILE"
else
    echo "Error: '$FILE' does not exist or is not a regular file." >&2
    exit 2
fi
