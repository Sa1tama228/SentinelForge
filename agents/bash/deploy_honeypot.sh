#!/usr/bin/env bash
# SentinelForge :: deploy the Python honeypots as a systemd service on Linux.
#
# Usage:  sudo ./deploy_honeypot.sh install | start | stop | status | uninstall
#
# Deploy only on hosts you own. Edit SF_DIR / SF_USER below to match your setup.

set -euo pipefail

SF_DIR="${SF_DIR:-/opt/sentinelforge}"
SF_USER="${SF_USER:-root}"
SERVICE="sentinelforge-honeypot.service"

usage() {
    echo "Usage: $0 {install|start|stop|status|uninstall}" >&2
    exit 1
}

cmd="${1:-}"; [[ -n "$cmd" ]] || usage

install_service() {
    echo "[+] Writing systemd unit: $SERVICE"
    cat >"/etc/systemd/system/$SERVICE" <<EOF
[Unit]
Description=SentinelForge honeypots (HTTP/SSH/FTP)
After=network.target

[Service]
Type=simple
User=$SF_USER
WorkingDirectory=$SF_DIR
ExecStart=/usr/bin/env python3 -c "from sentinelforge.modules.honeypot.server import manager; m=manager(); [m.start(k) for k in ('http','ssh','ftp')]; import time; [time.sleep(3600)]"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "$SERVICE"
    echo "[+] Installed. Start with: $0 start"
}

case "$cmd" in
    install)    install_service ;;
    start)      systemctl start "$SERVICE" && echo "[+] started" ;;
    stop)       systemctl stop "$SERVICE" && echo "[+] stopped" ;;
    status)     systemctl status "$SERVICE" ;;
    uninstall)  systemctl disable --now "$SERVICE" 2>/dev/null || true
                rm -f "/etc/systemd/system/$SERVICE"
                systemctl daemon-reload
                echo "[+] removed" ;;
    *)          usage ;;
esac
