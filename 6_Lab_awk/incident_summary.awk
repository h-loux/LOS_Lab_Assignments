# Incident summary: entries per severity category
BEGIN { FS = "," }
NR > 1 { count[$4]++ }
END {
    print "Incident summary by severity"
    n = split("LOW MEDIUM HIGH CRITICAL", order, " ")
    for (i = 1; i <= n; i++)
        printf "%-9s %d\n", order[i], count[order[i]] + 0
}
