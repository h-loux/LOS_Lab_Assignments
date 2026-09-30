#!/bin/bash
# analyse_auth_log.sh - SSH authentication-log analysis using grep, sort/uniq, sed and awk
#
# Usage:   ./analyse_auth_log.sh [-m] [-o OUTDIR] LOGFILE
#   -m        mask the last octet of every IP address in the final report (safe to share)
#   -o DIR    write results into DIR (default: ./output)
#
# Pipeline overview
#   1. grep / grep -c            quick counts of each event type
#   2. sed | sort | uniq -c      top attacking IPs and targeted usernames
#   3. sed -f classify_events.sed   tag every line with an event class  -> tagged_events.log
#   4. awk -f detect_ips.awk     per-IP statistics + verdict            -> ip_summary.txt
#   5. awk -f hourly_failures.awk   failures per hour (bar chart)       -> hourly_failures.txt
#      (also: scanner sources via grep | sed | sort | uniq -c)
#   6. awk -f compromise_check.awk  success-after-failures and what followed -> compromise_findings.txt
#   7. everything is assembled into security_report.txt

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="output"
MASK=0

usage() { echo "Usage: $0 [-m] [-o OUTDIR] LOGFILE" >&2; exit 1; }

while getopts ":mo:" opt; do
    case "$opt" in
        m) MASK=1 ;;
        o) OUTDIR="$OPTARG" ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage
LOG="$1"

# ---- input validation
[ -f "$LOG" ] || { echo "Error: '$LOG' is not a file." >&2; exit 2; }
[ -r "$LOG" ] || { echo "Error: '$LOG' is not readable." >&2; exit 3; }
[ -s "$LOG" ] || { echo "Error: '$LOG' is empty." >&2; exit 4; }
for f in classify_events.sed mask_ips.sed detect_ips.awk hourly_failures.awk compromise_check.awk; do
    [ -f "$SCRIPT_DIR/$f" ] || { echo "Error: helper script $f not found next to this script." >&2; exit 5; }
done
mkdir -p "$OUTDIR" || exit 6

TAGGED="$OUTDIR/tagged_events.log"
SUMMARY="$OUTDIR/ip_summary.txt"
HOURLY="$OUTDIR/hourly_failures.txt"
FINDINGS="$OUTDIR/compromise_findings.txt"
REPORT="$OUTDIR/security_report.txt"

# ---- step 3: classify with sed (CRLF removed first so $ anchors and fields behave)
tr -d '\r' < "$LOG" | sed -E -f "$SCRIPT_DIR/classify_events.sed" > "$TAGGED"

# ---- step 4: per-IP statistics (awk), sorted by failures, most first
{
    printf "%-16s %-9s %6s %6s %9s %-15s %-15s %5s  %s\n" IP SCOPE FAILS USERS MAX/5MIN FIRST LAST OK VERDICT
    awk -f "$SCRIPT_DIR/detect_ips.awk" "$TAGGED" | sort -k3,3nr |
        awk '{ printf "%-16s %-9s %6d %6d %9d %-15s %-15s %5d  %s\n", $1,$2,$3,$4,$5,$6,$7,$8,$9 }'
} > "$SUMMARY"

# ---- step 5 and 6
awk -f "$SCRIPT_DIR/hourly_failures.awk" "$TAGGED" > "$HOURLY"
awk -f "$SCRIPT_DIR/compromise_check.awk" "$TAGGED" > "$FINDINGS"

# ---- step 1 and 2: counts and top lists
count() { grep -c -E "$1" "$LOG"; }

{
    echo "=============================================================="
    echo " SSH AUTHENTICATION LOG ANALYSIS REPORT"
    echo " Log file : $LOG"
    echo " Lines    : $(wc -l < "$LOG")"
    echo " Period   : $(head -n 1 "$LOG" | cut -d' ' -f1-3)  to  $(tail -n 1 "$LOG" | cut -d' ' -f1-3)"
    echo "=============================================================="
    echo
    echo "[1] EVENT COUNTS"
    printf "  %-34s %5d\n" "Failed password attempts"        "$(count 'Failed password')"
    printf "  %-34s %5d\n" "  of which for non-existent users" "$(count 'Failed password for invalid user')"
    printf "  %-34s %5d\n" "Accepted logins"                 "$(count 'Accepted password')"
    printf "  %-34s %5d\n" "sudo commands"                   "$(count 'COMMAND=')"
    printf "  %-34s %5d\n" "New accounts created"            "$(count 'new user:')"
    printf "  %-34s %5d\n" "Scanner banner-grab events"      "$(count 'Did not receive identification string')"
    echo
    echo "[2] TOP 5 SOURCE IPs BY FAILED LOGINS (grep | sed | sort | uniq -c | sort -nr | head)"
    grep 'Failed password' "$LOG" | sed -E 's/.* from ([0-9.]+) port.*/\1/' | sort | uniq -c | sort -nr | head -n 5 |
        awk '{ printf "  %5d  %s\n", $1, $2 }'
    echo
    echo "[3] TOP 8 TARGETED USERNAMES"
    grep 'Failed password' "$LOG" | sed -nE 's/.*Failed password for (invalid user )?([^ ]+) from .*/\2/p' |
        sort | uniq -c | sort -nr | head -n 8 | awk '{ printf "  %5d  %s\n", $1, $2 }'
    echo
    echo "[4] SCANNER-LIKE SOURCES (connections that never attempt to authenticate)"
    grep 'Did not receive identification string' "$LOG" | sed -E 's/.* from ([0-9.]+) port.*/\1/' |
        sort | uniq -c | sort -nr | awk '{ printf "  %5d  %s\n", $1, $2 }'
    echo
    echo "[5] PER-IP ANALYSIS (verdict thresholds explained in the report)"
    sed 's/^/  /' "$SUMMARY"
    echo
    echo "[6] FAILED LOGINS PER HOUR  (# = 2 failures)"
    sed 's/^/  /' "$HOURLY"
    echo
    echo "[7] SUCCESSFUL LOGINS FOLLOWING FAILURES, AND WHAT HAPPENED NEXT"
    if [ -s "$FINDINGS" ]; then sed 's/^/  /' "$FINDINGS"; else echo "  none"; fi
    echo
    echo "[8] ALERT SUMMARY"
    for v in BRUTE_FORCE PASSWORD_SPRAYING PERSISTENT WATCH; do
        ips=$(awk -v v="$v" 'NR > 1 && $NF == v { printf "%s ", $1 }' "$SUMMARY")
        [ -n "$ips" ] && echo "  [ALERT] $v : $ips"
    done
    scan=$(grep 'Did not receive identification string' "$LOG" | sed -E 's/.* from ([0-9.]+) port.*/\1/' |
           sort | uniq -c | awk '$1 >= 3 { printf "%s ", $2 }')
    [ -n "$scan" ] && echo "  [ALERT] SCANNER : $scan"
    grep -E '^\[(CRITICAL|OFF_HOURS_EXTERNAL)' "$FINDINGS" | sed 's/^/  [ALERT] /'
    echo
    echo "END OF REPORT"
} > "$REPORT"

# ---- optional masking of addresses for sharing
if [ "$MASK" -eq 1 ]; then
    sed -E -i -f "$SCRIPT_DIR/mask_ips.sed" "$REPORT"
fi

cat "$REPORT"
echo
echo "Files written to $OUTDIR/: tagged_events.log ip_summary.txt hourly_failures.txt compromise_findings.txt security_report.txt" >&2
