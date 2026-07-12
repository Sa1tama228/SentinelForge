#!/usr/bin/env bash

set -u

echo "=== SentinelForge :: Local audit ==="
echo

echo "[1] Listening TCP ports"
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo

echo "[2] sshd hardening (PermitRootLogin / PasswordAuth)"
for k in PermitRootLogin PasswordAuthentication; do
    v=$(sshd -T 2>/dev/null | awk -v key="$k" '$1==key{print $2}')
    echo "  $k = ${v:-(sshd -T unavailable, need root)}"
done
echo

echo "[3] fail2ban status"
if command -v fail2ban-client >/dev/null 2>&1; then
    fail2ban-client status 2>/dev/null || echo "  fail2ban not running"
else
    echo "  fail2ban-client not installed"
fi
echo

echo "[4] World-writable files under /etc (should be empty)"
ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -20)
[[ -z "$ww" ]] && echo "  none" || echo "$ww"
echo

echo "Audit complete."
