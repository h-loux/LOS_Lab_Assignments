# SSH Authentication Log Analysis (Linux command-line tools)

Linux Operating System, Theory Assignment 6
Student: Ribhav Devprasad | Reg. No.: 26110690002

## What this does
`analyse_auth_log.sh` analyses an SSH/sudo authentication log (syslog `auth.log` format) with
`grep`, `sort | uniq -c`, `sed` and `awk`, and writes a report that flags brute-force attacks,
password spraying, scanners and a successful login that followed many failures.

## Files
| File | Purpose |
|---|---|
| `generate_log.py` | Creates the **simulated** log (fixed random seed, repeatable). No real system is touched. |
| `auth_simulated.log` | The simulated log analysed in the report (236 lines, 12-13 Oct 2026). |
| `analyse_auth_log.sh` | Main Bash script that runs the whole pipeline. |
| `classify_events.sed` | sed script: tags each line with an event class (`[FAIL]`, `[LOGIN_OK]`, ...). |
| `mask_ips.sed` | sed script: masks the last octet of IP addresses (`203.0.113.xxx`). |
| `detect_ips.awk` | awk: per-IP failures, distinct usernames, sliding-window burst size, verdict. |
| `hourly_failures.awk` | awk: failed logins per hour as a text bar chart. |
| `compromise_check.awk` | awk: success-after-failures check and what the account did next. |
| `output/` | Generated results (`security_report.txt`, `ip_summary.txt`, `hourly_failures.txt`, `compromise_findings.txt`, `tagged_events.log`). |

## Requirements
Linux or WSL with `bash`, `grep`, `sed` (GNU), `awk` (gawk or mawk), `sort`, `uniq`, `tr`, `cut`, `head`.
Python 3 is needed **only** to regenerate the log with `generate_log.py`.

## How to run
```bash
cd 6_Theory_Log_Analysis
chmod +x analyse_auth_log.sh

# (optional) regenerate the simulated log - produces an identical file every time
python3 generate_log.py auth_simulated.log

# analyse it (results go to ./output)
./analyse_auth_log.sh auth_simulated.log

# options
./analyse_auth_log.sh -m auth_simulated.log          # mask last octet of IPs in the report
./analyse_auth_log.sh -o results auth_simulated.log  # choose the output directory
```
Exit codes: 0 success, 1 bad usage, 2 not a file, 3 not readable, 4 empty, 5 helper script missing, 6 cannot create output directory.

## Changing the detection thresholds
The thresholds are variables at the top of `detect_ips.awk` and `compromise_check.awk` and can be overridden,
for example `awk -v BURST_MIN=8 -v WINDOW=120 -f detect_ips.awk output/tagged_events.log`.

## Dataset source details
The log is **simulated** (not downloaded). `generate_log.py` writes syslog-style lines from a fixed seed (2026).
Public IP addresses used are from the documentation ranges 203.0.113.0/24 and 198.51.100.0/24 (RFC 5737),
internal users use private 192.168.1.0/24 addresses, user names are fictional, and no passwords, tokens
or personal data appear in the file. No network scanning or testing of any real system was performed.

## Resources and assistance
- Linux man pages: `grep(1)`, `sed(1)`, `awk(1)`, `sort(1)`, `uniq(1)`, `bash(1)`; GNU sed and gawk manuals.
- Course material on power filters, Bash scripting, sed and awk.
- MITRE ATT&CK technique descriptions T1110, T1078, T1136 (for terminology).
- AI assistance: Claude (Anthropic) was used to help design and write the simulation script, the Bash/sed/awk
  scripts and the report text. The scripts were run and their output reviewed before submission.
