#!/bin/bash
# filesystem_lab.sh - runs the commands for Exercises 1-16 on YOUR Linux machine
# and saves a transcript to ~/filesystem_lab_output.txt
#
# Safe to run: it only READS system locations. The only things it creates or
# changes are ~/cyber_lab and the text added to cyber_lab/reports/investigation.txt.
#
# Usage:  chmod +x filesystem_lab.sh && ./filesystem_lab.sh

OUT="$HOME/filesystem_lab_output.txt"

r() {                       # print a command, then run it
    echo
    echo "\$ $*"
    eval "$@" 2>&1
}
ex() { echo; echo "################ $* ################"; }

{
ex "Exercise 1 - Identify the filesystem"
r lsblk
r lsblk -f
r df -T
r df -h

ex "Exercise 3 - Explore the root filesystem"
cd ~
r pwd
r cd /
r pwd
r ls
r "ls -d */"
r "ls -A / | grep '^\.' || echo '(no hidden entries directly under /)'"

ex "Exercise 4 - Filesystem hierarchy"
for d in /home /root /etc /var /var/log /tmp /usr /boot /dev /proc; do
    echo; echo "==== $d ===="
    ls "$d" 2>&1 | head -n 8
done

ex "Exercise 5 - Home directory"
r whoami
r 'echo $HOME'
r cd ~
r pwd
r ls
r ls -a

ex "Exercise 6 - Hidden files"
r ls
r ls -a
r "ls -d .[!.]*"
r "ls -ld . .."

ex "Exercise 7 - Build cyber_lab"
r mkdir -p cyber_lab/{evidence/{network,system},logs,scripts,reports}
r touch cyber_lab/evidence/network/traffic.txt cyber_lab/evidence/system/processes.txt cyber_lab/logs/security.log cyber_lab/scripts/check.sh cyber_lab/reports/investigation.txt
if command -v tree >/dev/null; then r tree cyber_lab; else r "find cyber_lab | sort"; echo "(tree not installed: sudo apt install tree)"; fi

ex "Exercise 8 - Absolute and relative paths"
r "cd ~/cyber_lab"; r pwd
r "cd evidence/network"; r pwd
r "cd /etc"; r pwd
r "cd"; r pwd
r "cd cyber_lab/reports"; r pwd
r "cd .."; r pwd

ex "Exercise 9 - File types"
for f in /etc/passwd /etc /bin/bash /dev/null /proc ~/cyber_lab/logs/security.log ~/cyber_lab/scripts/check.sh; do
    r file "$f"
    r ls -ld "$f"
done

ex "Exercise 10 - Metadata"
cd ~/cyber_lab/reports
echo "Investigation notes: suspicious login reviewed." >> investigation.txt
r ls -l investigation.txt
r stat investigation.txt

ex "Exercise 11 - /etc"
r ls -l /etc/passwd /etc/group /etc/hostname /etc/hosts
r cat /etc/hostname
r cat /etc/hosts
r head -n 5 /etc/passwd
r head -n 5 /etc/group

ex "Exercise 12 - /var/log"
r ls -l /var/log
r "ls -ld /var/log/*/"
r "ls -lt /var/log | head -n 8"
echo; echo "Readable / not readable for $(whoami):"
for f in /var/log/*; do [ -r "$f" ] && echo "readable      $f" || echo "NOT readable  $f"; done

ex "Exercise 13 - /tmp"
r ls -la /tmp
r ls -ld /tmp
r "ls -lat /tmp | head -n 8"

ex "Exercise 14 - /proc"
r "head -n 12 /proc/cpuinfo"
r "head -n 5 /proc/meminfo"
r 'echo $$'
r 'ls -d /proc/$$'
r 'ls /proc/$$ | head -n 8'
r "mount | grep ' /proc '"

ex "Exercise 15 - /dev"
r "ls /dev | head -n 20"
r ls -l /dev/null /dev/zero
r file /dev/null

ex "Exercise 16 - Space"
r df -h /
r df -h ~
r "df --output=source,size,used,avail,pcent /"
r du -sh ~
r du -sh ~/cyber_lab
} 2>&1 | tee "$OUT"

echo
echo "Transcript saved to $OUT"
