# classify_events.sed - prefix every auth-log line with an event tag
# Run with:  sed -E -f classify_events.sed auth.log
# The first matching rule tags the line and "b" jumps to the end of the script,
# so a line is never tagged twice (order matters: specific rules come first).
/Failed password for invalid user/    { s/^/[FAIL_INVALID_USER] /; b }
/Failed password/                     { s/^/[FAIL] /;              b }
/Accepted password/                   { s/^/[LOGIN_OK] /;          b }
/Invalid user/                        { s/^/[INVALID_USER] /;      b }
/COMMAND=/                            { s/^/[SUDO] /;              b }
/new user:/                           { s/^/[NEW_ACCOUNT] /;       b }
/Did not receive identification string/ { s/^/[SCAN] /;            b }
/session (opened|closed)/             { s/^/[SESSION] /;           b }
s/^/[OTHER] /
