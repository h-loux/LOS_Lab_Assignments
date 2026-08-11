#!/bin/bash
#Script to update Linux system.
echo "Starting system update ..."
sudo apt update
#-y automatically bypasses confirmation
sudo apt upgrade -y
echo "System update complete."
