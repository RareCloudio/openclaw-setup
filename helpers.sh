#!/usr/bin/env bash
# openclaw-setup — Helper scripts installer
# Installs management commands to /usr/local/bin/
set -euo pipefail

cat > /usr/local/bin/openclaw-status <<'HELPER'
#!/bin/bash
echo "=== OpenClaw Gateway ==="
systemctl status openclaw-gateway --no-pager -l
echo ""
echo "=== Health ==="
curl -s http://127.0.0.1:18789/health 2>/dev/null || echo "Not responding"
echo ""
echo "=== Logs (last 20) ==="
journalctl -u openclaw-gateway -n 20 --no-pager
HELPER
chmod +x /usr/local/bin/openclaw-status

cat > /usr/local/bin/openclaw-backup <<'HELPER'
#!/bin/bash
BACKUP_DIR="${1:-/var/backups/openclaw}"
DATE=$(date +%Y%m%d-%H%M%S)
mkdir -p "$BACKUP_DIR"
tar -czf "$BACKUP_DIR/openclaw-$DATE.tar.gz" \
    /home/openclaw/.clawdbot /home/openclaw/clawd /home/openclaw/.env 2>/dev/null
echo "Backup: $BACKUP_DIR/openclaw-$DATE.tar.gz"
ls -t "$BACKUP_DIR"/openclaw-*.tar.gz | tail -n +8 | xargs -r rm
HELPER
chmod +x /usr/local/bin/openclaw-backup

cat > /usr/local/bin/openclaw-security-check <<'HELPER'
#!/bin/bash
echo "=== OpenClaw Security Audit ==="; echo ""; P=0; F=0
c() { if eval "$1"; then echo "[PASS] $2"; P=$((P+1)); else echo "[FAIL] $3"; F=$((F+1)); fi; }
c '! ss -tlnp 2>/dev/null | grep -q "0.0.0.0:18789"' "Port 18789 localhost-only" "Port 18789 exposed!"
c 'test "$(stat -c %a /home/openclaw/.env 2>/dev/null)" = "600"' ".env perms 600" ".env perms wrong"
c 'test "$(stat -c %a /home/openclaw/.clawdbot/clawdbot.json 2>/dev/null)" = "600"' "Config perms 600" "Config perms wrong"
c 'systemctl is-active --quiet nftables' "Firewall active" "Firewall down!"
c 'systemctl is-active --quiet fail2ban' "fail2ban active" "fail2ban down!"
c 'systemctl is-active --quiet nginx' "nginx active" "nginx down!"
c 'systemctl is-active --quiet docker' "Docker running" "Docker down!"
c 'grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null' "SSH passwd disabled" "SSH passwd enabled!"
TL=$(grep "CLAWDBOT_GATEWAY_TOKEN=" /home/openclaw/.env 2>/dev/null | cut -d= -f2 | wc -c)
c 'test "$TL" -ge 32' "Token OK (${TL}c)" "Token missing/short!"
echo ""; echo "Score: ${P} pass, ${F} fail"
HELPER
chmod +x /usr/local/bin/openclaw-security-check

echo "[openclaw-setup] Helper scripts installed."
