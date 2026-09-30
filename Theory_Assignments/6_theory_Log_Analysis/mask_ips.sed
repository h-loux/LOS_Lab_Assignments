# mask_ips.sed - hide the last octet of every IPv4 address (for sharing a report)
# Run with:  sed -E -f mask_ips.sed report.txt
s/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.[0-9]{1,3}/\1.xxx/g
