#!/bin/sh
# Run this once (as root/sudo) BEFORE `containerlab deploy`.
#
# containerlab's `bridge` kind doesn't create the Linux bridge for you -
# it expects one to already exist on the host with the same name as the
# node. This creates the three bridges used as L2 switches for the DMZ,
# Finance, and Engineering subnets.

set -e

for br in sw-dmz sw-finance sw-engineering; do
  if ip link show "$br" > /dev/null 2>&1; then
    echo "bridge already exists: $br"
  else
    ip link add name "$br" type bridge
    ip link set "$br" up
    echo "created bridge: $br"
  fi
done
