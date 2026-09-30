# detect_ips.awk - per-source-IP statistics and verdict
# Input : tagged log (output of classify_events.sed), so $1 is the event tag,
#         $2 $3 = month day, $4 = time, then host, process, message
# Output: one line per IP:  IP SCOPE FAILS USERS MAX_IN_WINDOW FIRST LAST LOGINS_OK VERDICT
# Tunable thresholds (override with  awk -v BURST_MIN=8 ... ):
#   WINDOW     sliding window length in seconds          (default 300 = 5 min)
#   BURST_MIN  failures inside one window => brute force (default 10)
#   SPRAY_MIN  distinct usernames tried => password spraying (default 5)
#   TOTAL_MIN  total failures from one IP => persistent attacker (default 20)
#   WATCH_MIN  failures inside one window => watch-list  (default 5)

function epoch(day, hms,   t) { split(hms, t, ":"); return day * 86400 + t[1] * 3600 + t[2] * 60 + t[3] }
function is_private(ip) { return ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ }

BEGIN {
    if (WINDOW == "")    WINDOW = 300
    if (BURST_MIN == "") BURST_MIN = 10
    if (SPRAY_MIN == "") SPRAY_MIN = 5
    if (TOTAL_MIN == "") TOTAL_MIN = 20
    if (WATCH_MIN == "") WATCH_MIN = 5
}

$1 == "[FAIL]" || $1 == "[FAIL_INVALID_USER]" {
    ip = ""; user = ""
    for (i = 5; i <= NF; i++) {
        if ($i == "for" && user == "") { user = $(i + 1); if (user == "invalid") user = $(i + 3) }
        if ($i == "from") ip = $(i + 1)
    }
    if (ip == "") next
    ts = epoch($3, $4)
    fails[ip]++
    if (!((ip, user) in seen)) { seen[ip, user] = 1; users[ip]++ }
    n[ip]++; stamp[ip, n[ip]] = ts                     # sliding window over this IP's failures
    while (ts - stamp[ip, head[ip] + 1] > WINDOW) head[ip]++
    if (n[ip] - head[ip] > maxwin[ip]) maxwin[ip] = n[ip] - head[ip]
    if (!(ip in first)) first[ip] = $2 $3 "-" $4
    last[ip] = $2 $3 "-" $4
}

$1 == "[LOGIN_OK]" {
    for (i = 5; i <= NF; i++) if ($i == "from") ok[$(i + 1)]++
}

END {
    for (ip in fails) {
        if (maxwin[ip] >= BURST_MIN)        v = "BRUTE_FORCE"
        else if (users[ip] >= SPRAY_MIN)    v = "PASSWORD_SPRAYING"
        else if (fails[ip] >= TOTAL_MIN)    v = "PERSISTENT"
        else if (maxwin[ip] >= WATCH_MIN)   v = "WATCH"
        else                                v = "normal"
        printf "%s %s %d %d %d %s %s %d %s\n", ip, (is_private(ip) ? "internal" : "external"),
               fails[ip], users[ip], maxwin[ip], first[ip], last[ip], ok[ip] + 0, v
    }
}
