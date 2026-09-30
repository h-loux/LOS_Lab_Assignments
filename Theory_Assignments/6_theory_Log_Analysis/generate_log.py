#!/usr/bin/env python3
"""
generate_log.py - create a SIMULATED SSH authentication log (syslog / auth.log style).

No real system is scanned, attacked or logged. The file is produced entirely by this
script from a fixed random seed, so the result is repeatable. Addresses are either
private (RFC 1918) for the "internal" users or from the documentation ranges
203.0.113.0/24 and 198.51.100.0/24 (RFC 5737), which are reserved for examples and are
never routed on the Internet. User names are fictional; no passwords are logged.

Usage:  python3 generate_log.py [output_file]      (default: auth_simulated.log)
"""
import random, sys
from datetime import datetime, timedelta

OUT = sys.argv[1] if len(sys.argv) > 1 else "auth_simulated.log"
rnd = random.Random(2026)            # fixed seed -> identical log every run
HOST = "labsrv01"
D1 = datetime(2026, 10, 12)          # Monday
D2 = datetime(2026, 10, 13)

events = []                          # (datetime, process-name, message)
def add(t, proc, msg): events.append((t, proc, msg))
def pid(): return rnd.randint(1500, 4900)
def port(): return rnd.randint(32768, 60999)
def at(day, h, m, s=0): return day + timedelta(hours=h, minutes=m, seconds=s)

USERS = {"alice": "192.168.1.20", "bob": "192.168.1.21", "carol": "192.168.1.22", "dave": "192.168.1.23"}

def session(t, user, ip, dur_min, sudo_cmds=()):
    p = pid()
    add(t, f"sshd[{p}]", f"Accepted password for {user} from {ip} port {port()} ssh2")
    add(t + timedelta(seconds=1), f"sshd[{p}]", f"pam_unix(sshd:session): session opened for user {user} by (uid=0)")
    for i, cmd in enumerate(sudo_cmds):
        add(t + timedelta(minutes=2 + 7 * i), "sudo",
            f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}")
    add(t + timedelta(minutes=dur_min), f"sshd[{p}]", f"pam_unix(sshd:session): session closed for user {user}")

def fail(t, user, ip, valid=True):
    p = pid(); pt = port()
    if not valid:
        add(t, f"sshd[{p}]", f"Invalid user {user} from {ip} port {pt}")
    add(t + timedelta(seconds=1), f"sshd[{p}]",
        f"Failed password for {'' if valid else 'invalid user '}{user} from {ip} port {pt} ssh2")
    return p, pt

# ---- 1. Normal working-hours activity (both days)
for day in (D1, D2):
    for user, ip in USERS.items():
        for _ in range(rnd.randint(1, 3)):
            t = at(day, rnd.randint(8, 17), rnd.randint(0, 59), rnd.randint(0, 59))
            cmds = rnd.choice([(), (), ("/usr/bin/apt update",), ("/usr/bin/systemctl restart nginx",)]) if user in ("alice", "dave") else ()
            session(t, user, ip, rnd.randint(8, 120), cmds)

# ---- 2. Harmless typos
fail(at(D1, 10, 5, 12), "bob", USERS["bob"]);  fail(at(D1, 10, 5, 31), "bob", USERS["bob"])
session(at(D1, 10, 5, 50), "bob", USERS["bob"], 45)
fail(at(D2, 9, 14, 3), "dave", USERS["dave"]); session(at(D2, 9, 14, 20), "dave", USERS["dave"], 60)

# ---- 3. Internal user forgets password: 6 failures then success (expected false positive)
for k in range(6):
    fail(at(D1, 14, 20, 5 + 14 * k), "eve", "192.168.1.35")
session(at(D1, 14, 22, 10), "eve", "192.168.1.35", 30)

# ---- 4. Legitimate late-evening login from an internal address (off-hours but benign)
session(at(D1, 23, 32, 41), "bob", USERS["bob"], 25)

# ---- 5. Banner-grabbing scanner (no authentication attempted)
for k in range(5):
    t = at(D1, 1, 30 + k * 3, rnd.randint(0, 59)); pt = port()
    add(t, f"sshd[{pid()}]", f"Did not receive identification string from 198.51.100.99 port {pt}")
    add(t + timedelta(seconds=2), f"sshd[{pid()}]", f"Connection closed by 198.51.100.99 port {pt} [preauth]")

# ---- 6. SCENARIO A - fast brute force against root and common names from 203.0.113.45
ATT = "203.0.113.45"
names = ["root"] * 9 + ["admin", "test", "oracle", "ubuntu", "postgres", "user"]
t = at(D1, 2, 10, 5)
for k in range(62):
    u = rnd.choice(names)
    p, pt = fail(t, u, ATT, valid=(u == "root"))
    if u == "root" and k % 6 == 0:
        add(t + timedelta(seconds=2), f"sshd[{p}]",
            f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ATT}  user=root")
    if k % 11 == 10:
        add(t + timedelta(seconds=3), f"sshd[{p}]", f"error: maximum authentication attempts exceeded for root from {ATT} port {pt} ssh2 [preauth]")
    t += timedelta(seconds=rnd.randint(2, 5))

# ---- 7. SCENARIO B - slow password spraying from 198.51.100.23 (one or two tries per name)
SPR = "198.51.100.23"
spray_users = ["admin", "user", "test", "guest", "ftp", "postgres", "mysql", "jenkins", "git", "oracle",
               "support", "backup", "dev", "deploy", "pi", "alice", "dave"]
t = at(D1, 5, 0, 17)
for u in spray_users:
    valid = u in ("alice", "dave")
    for _ in range(rnd.choice([1, 2])):
        fail(t, u, SPR, valid=valid)
        t += timedelta(minutes=rnd.randint(4, 9), seconds=rnd.randint(0, 59))

# ---- 8. SCENARIO C - brute force that SUCCEEDS (203.0.113.77 -> carol), then privileged actions
CMP = "203.0.113.77"
t = at(D2, 3, 38, 10)
for k in range(12):
    fail(t, "carol", CMP); t += timedelta(seconds=rnd.randint(5, 9))
tl = at(D2, 3, 39, 47)
p = pid()
add(tl, f"sshd[{p}]", f"Accepted password for carol from {CMP} port {port()} ssh2")
add(tl + timedelta(seconds=1), f"sshd[{p}]", "pam_unix(sshd:session): session opened for user carol by (uid=0)")
add(tl + timedelta(minutes=1, seconds=25), "sudo", "carol : TTY=pts/1 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/bash")
add(tl + timedelta(minutes=2, seconds=38), "sudo", "carol : TTY=pts/1 ; PWD=/home/carol ; USER=root ; COMMAND=/bin/cat /etc/shadow")
add(tl + timedelta(minutes=3, seconds=15), "sudo", "carol : TTY=pts/1 ; PWD=/home/carol ; USER=root ; COMMAND=/usr/sbin/useradd -m svc_backup")
add(tl + timedelta(minutes=3, seconds=16), f"useradd[{pid()}]", "new user: name=svc_backup, UID=1007, GID=1007, home=/home/svc_backup, shell=/bin/bash")
add(tl + timedelta(minutes=16), f"sshd[{p}]", "pam_unix(sshd:session): session closed for user carol")

events.sort(key=lambda e: e[0])
with open(OUT, "w") as f:
    for t, proc, msg in events:
        f.write(f"{t.strftime('%b %d %H:%M:%S')} {HOST} {proc}: {msg}\n")
print(f"wrote {len(events)} lines to {OUT}")
