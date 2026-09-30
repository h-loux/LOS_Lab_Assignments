#!/bin/bash
# perm_checker.sh - report the type and the current user's permissions on a path

if [ $# -lt 1 ]; then
    echo "Usage: $0 <path>" >&2
    exit 1
fi

P="$1"

if [ ! -e "$P" ]; then
    echo "Error: '$P' does not exist." >&2
    exit 2
fi

# Type
if [ -f "$P" ]; then
    echo "$P is a regular file."
elif [ -d "$P" ]; then
    echo "$P is a directory."
else
    echo "$P exists but is neither a regular file nor a directory."
fi

# Permissions for the user running the script
[ -r "$P" ] && echo "  Readable   : yes" || echo "  Readable   : no"
[ -w "$P" ] && echo "  Writable   : yes" || echo "  Writable   : no"
[ -x "$P" ] && echo "  Executable : yes" || echo "  Executable : no"
