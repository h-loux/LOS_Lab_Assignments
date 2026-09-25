# Priority queue: CRITICAL -> Immediate, HIGH -> Soon, everything else -> Routine
BEGIN { FS = ","; printf "%-6s %-15s %-15s %s\n", "Time", "Source_IP", "Event", "Priority" }
NR > 1 {
    if ($4 == "CRITICAL")  p = "Immediate"
    else if ($4 == "HIGH") p = "Soon"
    else                   p = "Routine"
    printf "%-6s %-15s %-15s %s\n", $1, $2, $3, p
}
