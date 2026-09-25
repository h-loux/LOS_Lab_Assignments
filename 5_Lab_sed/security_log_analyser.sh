#!/bin/bash
# security_log_analyser.sh - build a redacted alert report from an auth log
# Usage: ./security_log_analyser.sh <logfile>

REPORT="security_alert_report.txt"

# 1. argument supplied?
if [ $# -lt 1 ]; then
    echo "Usage: $0 <logfile>" >&2
    exit 1
fi
LOG="$1"

# 2. file exists (and is readable)?
if [ ! -f "$LOG" ]; then
    echo "Error: file '$LOG' not found." >&2
    exit 2
fi
if [ ! -r "$LOG" ]; then
    echo "Error: file '$LOG' is not readable." >&2
    exit 3
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# 3. extract failed-login and invalid-user attempts, redact IPs, flag with [ALERT]
sed -n -E '/Failed password|Invalid user/{
    s/[0-9]{1,3}(\.[0-9]{1,3}){3}/[REDACTED_IP]/g
    s/^/[ALERT] /
    p
}' "$LOG" > "$TMP"

FAILED=$(grep -c 'Failed password' "$LOG")
INVALID=$(grep -c 'Invalid user' "$LOG")

# 4. heading + summary + body + footer
{
    echo "SECURITY ALERT REPORT"
    echo "Source file : $LOG"
    echo "Failed logins : $FAILED"
    echo "Invalid-user attempts : $INVALID"
    echo "-------------------------------------"
    cat "$TMP"
    echo "-------------------------------------"
    echo "END OF REPORT"
} > "$REPORT"

# 5. display
cat "$REPORT"
