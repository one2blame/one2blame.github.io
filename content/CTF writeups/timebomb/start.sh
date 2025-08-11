#!/bin/bash

set -e

echo "[*] Compiling challenge.c..."
gcc /home/ctf/challenge.c -o /home/ctf/challenge \
  -fno-stack-protector -z execstack -no-pie 

echo "[*] Deleting challenge.c"
rm /home/ctf/challenge.c

echo "[*] Setting permissions..."
chmod 750 /home/ctf/challenge
chown root:ctf /home/ctf/challenge

echo "[*] Environment:"
echo "    LAMBDA_URL=$LAMBDA_URL"
echo "    SECRET_TOKEN=$SECRET_TOKEN"

echo "Try harder." > /etc/banner_fail

echo "[*] Starting xinetd..."
/usr/sbin/xinetd -dontfork -f /etc/xinetd.conf -filelog /tmp/xinetd.log


