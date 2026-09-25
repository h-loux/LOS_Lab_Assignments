# Log normalisation: Login_Failed -> Failed_Login, output as CSV (input is never modified)
BEGIN { FS = OFS = "," }
$3 == "Login_Failed" { $3 = "Failed_Login" }
{ print }
