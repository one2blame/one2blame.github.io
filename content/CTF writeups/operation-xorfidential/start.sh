#!/bin/sh
# /start.sh

SECRET_DIR="/opt/h3x_data"
SECRET_FILE="$SECRET_DIR/.creds"

echo "[*] Base64-encoding and staging sensitive data to secure file..."

mkdir -p "$SECRET_DIR"
chown root:ctf "$SECRET_DIR"
chmod 750 "$SECRET_DIR"

# Use `echo -n` to prevent adding a trailing newline to the variable
# before it gets Base64 encoded. This is the critical fix.
echo -n "$CHALLENGE_AWS_ACCESS_KEY_ID" | base64 -w 0 > "$SECRET_FILE"
echo "" >> "$SECRET_FILE" # Add a newline separator in the file
echo -n "$CHALLENGE_AWS_SECRET_ACCESS_KEY" | base64 -w 0 >> "$SECRET_FILE"

chown root:ctf "$SECRET_FILE"
chmod 440 "$SECRET_FILE"

echo "[*] Sensitive data staged. Permissions locked."

cd /home/ctf

echo "[*] Compiling challenge binary..."
gcc challenge.c -m32 -fno-stack-protector -no-pie -fcf-protection=none -g -o challenge
rm challenge.c
chown root:ctf challenge
chmod 755 challenge

echo "[*] Compilation complete."
echo "[*] Starting listener service on port 8888..."
exec /usr/sbin/xinetd -dontfork