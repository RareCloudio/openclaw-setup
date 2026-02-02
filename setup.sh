#!/usr/bin/env bash
# openclaw-setup — Automated secure OpenClaw VPS setup
# https://github.com/rarecloud/openclaw-setup
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rarecloud/openclaw-setup/main/setup.sh | bash
#
# With custom credentials (for automation):
#   bash setup.sh --webui-pass "mypass" --gateway-token "mytoken"
#
# Architecture: OpenClaw runs NATIVELY on host (not in Docker).
# Docker is used ONLY for OpenClaw's built-in agent sandbox.
# This enables full browser tool support (headless Chromium).
#
# Security: 8-layer hardening model
#   1. nftables firewall (ports 22 + 443 only)
#   2. fail2ban (SSH + nginx brute-force protection)
#   3. nginx TLS reverse proxy + rate limiting
#   4. nginx basic-auth
#   5. OpenClaw gateway token
#   6. AppArmor process confinement
#   7. Docker sandbox (agent code execution isolation)
#   8. systemd hardening (NoNewPrivileges, ProtectSystem, etc.)

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
OPENCLAW_USER="openclaw"
OPENCLAW_HOME="/home/${OPENCLAW_USER}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_HOME}/.clawdbot"
OPENCLAW_WORKSPACE="${OPENCLAW_HOME}/clawd"
SETUP_LOG="/var/log/openclaw-setup.log"
PROVISIONED_FLAG="/opt/openclaw-setup/.provisioned"

# Defaults (overridable via CLI args)
WEBUI_USER="admin"
WEBUI_PASS=""
GATEWAY_TOKEN=""

# ============================================================
# Parse arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --webui-user)  WEBUI_USER="$2"; shift 2 ;;
        --webui-pass)  WEBUI_PASS="$2"; shift 2 ;;
        --gateway-token) GATEWAY_TOKEN="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: bash setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --webui-user USER     WebUI username (default: admin)"
            echo "  --webui-pass PASS     WebUI password (generated if empty)"
            echo "  --gateway-token TOKEN Gateway token (generated if empty)"
            echo "  --help                Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ============================================================
# Pre-flight checks
# ============================================================
if [[ "$(id -u)" -ne 0 ]]; then
    echo "[openclaw-setup] ERROR: Must run as root."
    exit 1
fi

if [[ -f "${PROVISIONED_FLAG}" ]]; then
    echo "[openclaw-setup] Already provisioned. Remove ${PROVISIONED_FLAG} to re-run."
    exit 0
fi

# Redirect all output to log + stdout
exec > >(tee -a "${SETUP_LOG}") 2>&1

echo "[openclaw-setup] ============================================"
echo "[openclaw-setup] OpenClaw Secure VPS Setup"
echo "[openclaw-setup] Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "[openclaw-setup] ============================================"

export DEBIAN_FRONTEND=noninteractive

# ============================================================
# Generate credentials if not provided
# ============================================================
if [[ -z "${WEBUI_PASS}" ]]; then
    WEBUI_PASS=$(openssl rand -base64 16 | tr -d '=+/')
    echo "[openclaw-setup] Generated random WebUI password."
fi

if [[ -z "${GATEWAY_TOKEN}" ]]; then
    GATEWAY_TOKEN=$(openssl rand -hex 32)
    echo "[openclaw-setup] Generated random gateway token."
fi

VPS_IP=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
HOSTNAME_FQDN=$(hostname -f 2>/dev/null || echo "${VPS_IP}")

echo "[openclaw-setup] VPS IP: ${VPS_IP}"

# ============================================================
# 1. Install system dependencies
# ============================================================
echo "[openclaw-setup] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git jq htop \
    nginx certbot python3-certbot-nginx \
    nftables fail2ban \
    apache2-utils \
    unattended-upgrades apt-listchanges \
    ca-certificates gnupg openssl \
    apparmor apparmor-utils

# ============================================================
# 2. Install headless Chromium (for browser tool)
# ============================================================
echo "[openclaw-setup] Installing headless Chromium..."
apt-get install -y -qq \
    chromium chromium-sandbox \
    fonts-liberation fonts-noto-color-emoji \
    libatk-bridge2.0-0 libatk1.0-0 libcups2 libdrm2 libgbm1 \
    libnss3 libxcomposite1 libxdamage1 libxrandr2 xdg-utils \
    2>/dev/null || {
    apt-get install -y -qq chromium-browser 2>/dev/null || \
        echo "[openclaw-setup] WARNING: Could not install Chromium. Browser tool will be unavailable."
}

# ============================================================
# 3. Install Node.js 22
# ============================================================
echo "[openclaw-setup] Installing Node.js 22..."
if ! command -v node &>/dev/null || [[ "$(node -v | cut -d'v' -f2 | cut -d'.' -f1)" -lt 22 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y -qq nodejs
fi
echo "[openclaw-setup] Node.js $(node -v) installed."

# ============================================================
# 4. Install Docker (for agent sandbox only)
# ============================================================
echo "[openclaw-setup] Installing Docker..."
if ! command -v docker &>/dev/null; then
    install -m 0755 -d /etc/apt/keyrings
    . /etc/os-release
    curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc
    chmod a+r /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
systemctl enable docker.service
systemctl enable containerd.service

# ============================================================
# 5. Create openclaw user
# ============================================================
echo "[openclaw-setup] Creating openclaw user..."
useradd -r -m -s /bin/bash -d "${OPENCLAW_HOME}" "${OPENCLAW_USER}" 2>/dev/null || true
usermod -aG docker "${OPENCLAW_USER}"
mkdir -p "${OPENCLAW_CONFIG_DIR}"
mkdir -p "${OPENCLAW_WORKSPACE}"/{documents,skills,memory,sessions,logs}
mkdir -p "${OPENCLAW_HOME}/workspace"
chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}"

# ============================================================
# 6. Install OpenClaw
# ============================================================
echo "[openclaw-setup] Installing OpenClaw (latest)..."
npm install -g moltbot@latest || {
    echo "[openclaw-setup] npm install failed, trying curl installer..."
    su - "${OPENCLAW_USER}" -c 'curl -fsSL https://molt.bot/install.sh | bash' || true
}

# Pre-pull sandbox Docker image
echo "[openclaw-setup] Pre-pulling sandbox image..."
docker pull node:22-bookworm-slim || echo "[openclaw-setup] WARNING: Could not pre-pull sandbox image."

# ============================================================
# 7. Configure OpenClaw
# ============================================================
echo "[openclaw-setup] Writing OpenClaw configuration..."
cat > "${OPENCLAW_CONFIG_DIR}/clawdbot.json" <<OCCONFIG
{
  "gateway": {
    "bind": "loopback",
    "port": 18789,
    "token": "${GATEWAY_TOKEN}"
  },
  "agents": {
    "defaults": {
      "workspace": "${OPENCLAW_WORKSPACE}",
      "sandbox": {
        "mode": "non-main",
        "scope": "agent",
        "workspaceAccess": "rw",
        "docker": {
          "image": "moltbot-sandbox:bookworm-slim",
          "network": "none",
          "readOnlyRoot": true,
          "user": "1000:1000",
          "capDrop": ["ALL"],
          "memory": "1g",
          "cpus": 1,
          "pidsLimit": 256
        }
      },
      "tools": {
        "allow": ["read", "write", "edit", "bash", "web_search", "browser"],
        "deny": ["cron", "gateway", "nodes", "canvas"]
      }
    }
  },
  "channels": {
    "telegram": {
      "groups": { "*": { "requireMention": true } }
    },
    "whatsapp": {
      "groups": { "*": { "requireMention": true } }
    }
  },
  "messages": {
    "groupChat": {
      "mentionPatterns": ["@openclaw", "@bot"]
    }
  }
}
OCCONFIG
chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_CONFIG_DIR}/clawdbot.json"
chmod 600 "${OPENCLAW_CONFIG_DIR}/clawdbot.json"

# Environment file
cat > "${OPENCLAW_HOME}/.env" <<ENVFILE
# OpenClaw Environment — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# DO NOT SHARE THIS FILE

# Gateway
CLAWDBOT_GATEWAY_TOKEN=${GATEWAY_TOKEN}
CLAWDBOT_GATEWAY_BIND=loopback

# Browser tool (headless Chromium)
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
PUPPETEER_SKIP_DOWNLOAD=true

# LLM API Keys — add your own:
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...

# Channel Tokens — add your own:
# TELEGRAM_BOT_TOKEN=...

# Runtime
CLAWDBOT_LOG_LEVEL=info
NODE_ENV=production
ENVFILE
chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/.env"
chmod 600 "${OPENCLAW_HOME}/.env"

# Default SOUL.md
cat > "${OPENCLAW_WORKSPACE}/SOUL.md" <<'SOUL'
# OpenClaw Personality

You are a helpful AI assistant.

## Traits
- Professional and efficient
- Clear and concise in responses
- Cautious with sensitive operations
- Always asks for confirmation before destructive actions

## Guidelines
- Never share API keys, credentials, or tokens
- Explain what you're about to do before doing it
- If unsure, ask for clarification
- Respect user privacy
- Do not access files outside ~/clawd without explicit permission
SOUL
chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_WORKSPACE}/SOUL.md"

# ============================================================
# 8. Hardening — nftables firewall
# ============================================================
echo "[openclaw-setup] Configuring nftables firewall..."
cat > /etc/nftables.conf <<'NFT'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept
        tcp dport 22 ct state new limit rate 10/minute accept
        tcp dport 443 ct state new accept
        limit rate 5/minute log prefix "[nftables-drop] " drop
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        iifname "docker0" oifname "docker0" accept
        iifname "br-*" oifname "br-*" accept
        ct state established,related accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFT
systemctl enable nftables.service

# ============================================================
# 9. Hardening — SSH
# ============================================================
echo "[openclaw-setup] Hardening SSH..."
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding local/' /etc/ssh/sshd_config
sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config

grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config || echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
grep -q "^LoginGraceTime" /etc/ssh/sshd_config || echo "LoginGraceTime 30" >> /etc/ssh/sshd_config
grep -q "^Ciphers" /etc/ssh/sshd_config || \
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> /etc/ssh/sshd_config
grep -q "^MACs" /etc/ssh/sshd_config || \
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> /etc/ssh/sshd_config

# ============================================================
# 10. Hardening — fail2ban
# ============================================================
echo "[openclaw-setup] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
maxretry = 3
bantime = 7200

[nginx-http-auth]
enabled = true
port = https
logpath = /var/log/nginx/openclaw-error.log
maxretry = 5
bantime = 3600

[nginx-limit-req]
enabled = true
port = https
logpath = /var/log/nginx/openclaw-error.log
maxretry = 10
bantime = 600

[nginx-botsearch]
enabled = true
port = https
logpath = /var/log/nginx/openclaw-access.log
maxretry = 2
bantime = 86400
F2B
systemctl enable fail2ban.service

# ============================================================
# 11. Hardening — automatic security updates
# ============================================================
echo "[openclaw-setup] Enabling automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'APT'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
APT

# ============================================================
# 12. Hardening — kernel (sysctl)
# ============================================================
echo "[openclaw-setup] Applying kernel hardening..."
cat > /etc/sysctl.d/99-openclaw-hardening.conf <<'SYSCTL'
net.ipv6.conf.all.forwarding = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.tcp_rfc1337 = 1
net.ipv4.ip_local_port_range = 32768 65535
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3
fs.suid_dumpable = 0
SYSCTL
sysctl --system >/dev/null 2>&1

# ============================================================
# 13. Hardening — Docker daemon
# ============================================================
echo "[openclaw-setup] Hardening Docker daemon..."
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'DOCKERCFG'
{
    "icc": false,
    "userland-proxy": false,
    "no-new-privileges": true,
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "live-restore": true,
    "default-ulimits": {
        "nofile": { "Name": "nofile", "Hard": 1024, "Soft": 512 },
        "nproc": { "Name": "nproc", "Hard": 256, "Soft": 128 }
    }
}
DOCKERCFG

# ============================================================
# 14. Hardening — disable unnecessary services + packages
# ============================================================
echo "[openclaw-setup] Disabling unnecessary services..."
for svc in avahi-daemon cups bluetooth snapd; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done
apt-get purge -y -qq telnet rsh-client 2>/dev/null || true

grep -q "^umask 027" /etc/profile || echo "umask 027" >> /etc/profile
echo "* hard core 0" >> /etc/security/limits.conf

# ============================================================
# 15. Hardening — AppArmor profile
# ============================================================
echo "[openclaw-setup] Installing AppArmor profile..."
cat > /etc/apparmor.d/usr.bin.moltbot <<'APPARMOR'
#include <tunables/global>

/usr/bin/moltbot {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  /usr/bin/moltbot mr,
  /usr/bin/node mrix,
  /usr/lib/node_modules/** r,
  /usr/local/lib/node_modules/** r,

  owner /home/openclaw/ r,
  owner /home/openclaw/** rwk,
  owner /home/openclaw/.clawdbot/** rw,
  owner /home/openclaw/clawd/** rw,
  owner /home/openclaw/workspace/** rw,
  owner /home/openclaw/.env r,

  /usr/bin/chromium mrix,
  /usr/bin/chromium-browser mrix,
  /usr/lib/chromium/** mr,
  /usr/share/chromium/** r,
  owner /home/openclaw/.cache/chromium/** rwk,
  owner /tmp/.org.chromium.* rwk,

  /usr/bin/docker mrix,
  /var/run/docker.sock rw,

  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,
  network unix stream,

  owner /tmp/** rwk,

  /etc/hosts r,
  /etc/resolv.conf r,
  /etc/ssl/** r,
  /proc/sys/kernel/random/uuid r,
  /proc/meminfo r,
  /proc/cpuinfo r,
  /sys/devices/system/cpu/** r,

  deny /etc/shadow r,
  deny /etc/passwd w,
  deny /root/** rwx,
  deny /var/log/** w,
  deny /boot/** rwx,
}
APPARMOR
apparmor_parser -r /etc/apparmor.d/usr.bin.moltbot 2>/dev/null || \
    echo "[openclaw-setup] WARNING: Could not load AppArmor profile (will load at next boot)."

# ============================================================
# 16. Nginx reverse proxy + TLS + basic-auth
# ============================================================
echo "[openclaw-setup] Configuring nginx reverse proxy..."

# Basic auth
htpasswd -bc /etc/nginx/.htpasswd "${WEBUI_USER}" "${WEBUI_PASS}"
chmod 640 /etc/nginx/.htpasswd
chown root:www-data /etc/nginx/.htpasswd

# Self-signed TLS cert
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/openclaw.key \
    -out /etc/nginx/ssl/openclaw.crt \
    -subj "/CN=${HOSTNAME_FQDN}/O=OpenClaw/C=US" 2>/dev/null

# Nginx config
cat > /etc/nginx/sites-available/openclaw <<NGINX
limit_req_zone \$binary_remote_addr zone=openclaw:10m rate=10r/s;
limit_conn_zone \$binary_remote_addr zone=openclaw_conn:10m;

server {
    listen 443 ssl http2;
    server_name ${HOSTNAME_FQDN} ${VPS_IP};

    ssl_certificate /etc/nginx/ssl/openclaw.crt;
    ssl_certificate_key /etc/nginx/ssl/openclaw.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss:" always;

    limit_req zone=openclaw burst=20 nodelay;
    limit_conn openclaw_conn 20;

    auth_basic "OpenClaw WebUI";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
    }

    location ~ /\\. { deny all; }

    access_log /var/log/nginx/openclaw-access.log;
    error_log /var/log/nginx/openclaw-error.log;
}

server {
    listen 80;
    server_name ${HOSTNAME_FQDN} ${VPS_IP};
    return 301 https://\$host\$request_uri;
}
NGINX

rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/openclaw /etc/nginx/sites-enabled/openclaw
nginx -t && systemctl restart nginx

# ============================================================
# 17. Systemd service for OpenClaw gateway
# ============================================================
echo "[openclaw-setup] Creating systemd service..."
cat > /etc/systemd/system/openclaw-gateway.service <<SVCFILE
[Unit]
Description=OpenClaw Gateway - AI Assistant
Documentation=https://docs.molt.bot
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_HOME}
EnvironmentFile=${OPENCLAW_HOME}/.env
ExecStart=/usr/bin/moltbot gateway
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${OPENCLAW_HOME}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=false

[Install]
WantedBy=multi-user.target
SVCFILE
systemctl daemon-reload
systemctl enable openclaw-gateway.service
systemctl start openclaw-gateway.service

echo "[openclaw-setup] Waiting for gateway to start..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:18789/health >/dev/null 2>&1; then
        echo "[openclaw-setup] Gateway is running."
        break
    fi
    sleep 2
done

# ============================================================
# 18. Install helper scripts
# ============================================================
echo "[openclaw-setup] Installing helper scripts..."

# Download helpers if available, otherwise install inline
HELPERS_URL="https://raw.githubusercontent.com/rarecloud/openclaw-setup/main/helpers.sh"
if curl -fsSL "${HELPERS_URL}" -o /tmp/openclaw-helpers.sh 2>/dev/null; then
    bash /tmp/openclaw-helpers.sh
    rm -f /tmp/openclaw-helpers.sh
else
    # Inline fallback
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
fi

# Daily backup cron
echo "0 3 * * * root /usr/local/bin/openclaw-backup" > /etc/cron.d/openclaw-backup

# ============================================================
# 19. MOTD — credentials & info on SSH login
# ============================================================
echo "[openclaw-setup] Setting up MOTD..."
cat > /etc/motd <<MOTD

  ___                    ____ _
 / _ \ _ __   ___ _ __  / ___| | __ ___      __
| | | | '_ \ / _ \ '_ \| |   | |/ _\` \ \ /\ / /
| |_| | |_) |  __/ | | | |___| | (_| |\ V  V /
 \___/| .__/ \___|_| |_|\____|_|\__,_| \_/\_/
      |_|

  WebUI:    https://${VPS_IP}
  User:     ${WEBUI_USER}
  Password: ${WEBUI_PASS}

  Commands:
    openclaw-status          Check service status
    openclaw-security-check  Run security audit
    openclaw-backup          Create backup

  Config:   ${OPENCLAW_CONFIG_DIR}/clawdbot.json
  Env:      ${OPENCLAW_HOME}/.env
  Logs:     journalctl -u openclaw-gateway -f

  Add your LLM API key:
    nano ${OPENCLAW_HOME}/.env
    systemctl restart openclaw-gateway

MOTD

# ============================================================
# 20. Finalize
# ============================================================
mkdir -p /opt/openclaw-setup
touch "${PROVISIONED_FLAG}"

# Save credentials for reference
cat > /opt/openclaw-setup/.credentials <<CREDS
# OpenClaw Credentials — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
VPS_IP=${VPS_IP}
WEBUI_URL=https://${VPS_IP}
WEBUI_USER=${WEBUI_USER}
WEBUI_PASS=${WEBUI_PASS}
GATEWAY_TOKEN=${GATEWAY_TOKEN}
CREDS
chmod 600 /opt/openclaw-setup/.credentials

echo ""
echo "[openclaw-setup] ============================================"
echo "[openclaw-setup] Setup complete!"
echo "[openclaw-setup] WebUI:    https://${VPS_IP}"
echo "[openclaw-setup] User:     ${WEBUI_USER}"
echo "[openclaw-setup] Password: ${WEBUI_PASS}"
echo "[openclaw-setup] ============================================"
echo "[openclaw-setup] Add your LLM API key in ${OPENCLAW_HOME}/.env"
echo "[openclaw-setup] Then: systemctl restart openclaw-gateway"
echo "[openclaw-setup] ============================================"
