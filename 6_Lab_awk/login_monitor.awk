# Login monitoring: Login_Failed entries with 5 or more attempts are suspicious
BEGIN { FS = ","; print "Suspicious failed-login entries (attempts >= 5)" }
NR > 1 && $3 == "Login_Failed" && $5 >= 5 {
    printf "%-15s %d\n", $2, $5
    suspicious++
}
END { print "Suspicious entries found:", suspicious + 0 }
