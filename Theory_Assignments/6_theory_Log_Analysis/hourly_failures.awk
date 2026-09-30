# hourly_failures.awk - failed logins per hour as a text bar chart (1 '#' = 2 failures)
# Input: tagged log. Output order follows the log (chronological).
$1 == "[FAIL]" || $1 == "[FAIL_INVALID_USER]" {
    split($4, t, ":")
    key = $2 " " $3 " " t[1] ":00"
    if (!(key in cnt)) order[++k] = key
    cnt[key]++
}
END {
    for (i = 1; i <= k; i++) {
        bar = ""
        for (j = 0; j < int((cnt[order[i]] + 1) / 2); j++) bar = bar "#"
        printf "%s  %3d  %s\n", order[i], cnt[order[i]], bar
    }
}
