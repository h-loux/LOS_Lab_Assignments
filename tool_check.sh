#!/bin/bash
#Tool checker script
echo "Tool Checker"
read -p "Enter the name of the tool (e.g., git, curl, nano):" tool
# Check if the tool exists
if which "$tool" &> /dev/null; then
echo "Yes! '$tool' is installed on this system."
echo "Location: $(which "$tool")"
else
echo "No, '$tool' is NOT installed."
fi
