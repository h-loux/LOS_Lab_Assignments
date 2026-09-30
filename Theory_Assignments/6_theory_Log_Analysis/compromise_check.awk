# compromise_check.awk - look for a successful login that follows many failures
# Input: tagged log in time order.
# Rules:
#   R1  [LOGIN_OK] from an IP that had >= MIN_FAILS failures before it
#       -> CRITICAL if the IP is external, REVIEW if internal (possible forgotten password)
#   R2  [LOGIN_OK] from an external IP between 00:00 and 05:59 -> OFF_HOURS_EXTERNAL
#   R3  For logins flagged by R1, list sudo commands and new accounts within FOLLOW seconds
function epoch(day, hms,   t) { split(hms, t, ":"); return day * 86400 + t[1] * 3600 + t[2] * 60 + t[3] }
function is_private(ip) { return ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/ }
BEGIN { if (MIN_FAILS == "") MIN_FAILS = 5; if (FOLLOW == "") FOLLOW = 1800 }

$1 == "[FAIL]" || $1 == "[FAIL_INVALID_USER]" {
    for (i = 5; i <= NF; i++) if ($i == "from") pf[$(i + 1)]++
}
$1 == "[LOGIN_OK]" {
    user = ""; ip = ""
    for (i = 5; i <= NF; i++) { if ($i == "for") user = $(i + 1); if ($i == "from") ip = $(i + 1) }
    ts = epoch($3, $4); split($4, t, ":")
    if (pf[ip] >= MIN_FAILS) {
        sev = is_private(ip) ? "REVIEW  " : "CRITICAL"
        printf "[%s] %s %s %s  login for '%s' from %s after %d failed attempts\n", sev, $2, $3, $4, user, ip, pf[ip]
        if (!is_private(ip)) { watch[user] = ts; watchip[user] = ip }
        pf[ip] = 0
    } else if (t[1] + 0 < 6 && !is_private(ip)) {
        printf "[OFF_HOURS_EXTERNAL] %s %s %s  login for '%s' from %s\n", $2, $3, $4, user, ip
    } else if (t[1] + 0 >= 22 || t[1] + 0 < 6) {
        printf "[INFO    ] %s %s %s  off-hours login for '%s' from internal address %s (not escalated)\n", $2, $3, $4, user, ip
    }
}
$1 == "[SUDO]" {
    u = $7
    if ((u in watch) && epoch($3, $4) - watch[u] <= FOLLOW) {
        match($0, /COMMAND=.*/)
        printf "    -> %s  sudo by '%s': %s\n", $4, u, substr($0, RSTART + 8, RLENGTH - 8)
    }
}
$1 == "[NEW_ACCOUNT]" {
    for (u in watch) if (epoch($3, $4) - watch[u] <= FOLLOW) {
        match($0, /name=[^,]*/)
        printf "    -> %s  NEW ACCOUNT created: %s\n", $4, substr($0, RSTART + 5, RLENGTH - 5)
        break
    }
}
