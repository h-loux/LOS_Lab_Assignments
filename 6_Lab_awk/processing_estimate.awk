# Processing estimate: 2 seconds of analyst review per attempt
BEGIN { FS = ","; printf "%-6s %-15s %8s %12s\n", "Time", "Source_IP", "Attempts", "Review (s)" }
NR > 1 {
    secs = $5 * 2
    total += secs
    printf "%-6s %-15s %8d %12d\n", $1, $2, $5, secs
}
END { printf "Total review time: %d seconds (%.2f minutes)\n", total, total / 60 }
