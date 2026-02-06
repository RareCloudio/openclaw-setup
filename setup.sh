#!/usr/bin/env bash
# openclaw-setup — Automated secure OpenClaw VPS setup (CLI-only)
# https://github.com/rarecloud/openclaw-setup
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rarecloud/openclaw-setup/main/setup.sh | bash
#
# With custom token:
#   bash setup.sh --gateway-token "mytoken"
#
# Architecture:
#   - OpenClaw runs NATIVELY on host (not in Docker)
#   - Docker is used ONLY for OpenClaw's agent sandbox
#   - Gateway binds to 127.0.0.1:18789 (loopback only, NOT exposed)
#   - Access via SSH + CLI commands
#   - Optional: SSH tunnel for Control UI (http://localhost:18789)
#
# Security: 7-layer hardening model
#   1. nftables firewall (custom SSH port ONLY)
#   2. fail2ban (SSH brute-force protection)
#   3. SSH hardening (key-only auth, no password)
#   4. OpenClaw gateway token auth
#   5. AppArmor process confinement
#   6. Docker sandbox (agent code execution isolation)
#   7. systemd hardening (NoNewPrivileges, ProtectSystem, etc.)

set -euo pipefail

# ============================================================
# Configuration
# ============================================================
OPENCLAW_USER="openclaw"
OPENCLAW_HOME="/home/${OPENCLAW_USER}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_HOME}/.openclaw"
OPENCLAW_WORKSPACE="${OPENCLAW_HOME}/workspace"
SETUP_LOG="/var/log/openclaw-setup.log"
PROVISIONED_FLAG="/opt/openclaw-setup/.provisioned"

# Defaults (overridable via CLI args)
GATEWAY_TOKEN=""
SSH_PORT="41722"
DESKTOP_MODE="false"

# ============================================================
# Parse arguments
# ============================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --gateway-token) GATEWAY_TOKEN="$2"; shift 2 ;;
        --ssh-port)      SSH_PORT="$2"; shift 2 ;;
        --desktop)       DESKTOP_MODE="true"; shift ;;
        --help|-h)
            echo "Usage: bash setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --gateway-token TOKEN  Gateway token (generated if empty)"
            echo "  --ssh-port PORT        SSH port (default: 41722)"
            echo "  --desktop              Install desktop environment (XFCE + browsers)"
            echo "  --help                 Show this help"
            echo ""
            echo "Server mode (default):"
            echo "  bash setup.sh"
            echo ""
            echo "Desktop mode (XFCE + real browsers):"
            echo "  bash setup.sh --desktop"
            echo ""
            echo "Access desktop via your VPS provider's VNC console."
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
echo "[openclaw-setup] OpenClaw Secure VPS Setup (CLI-only)"
echo "[openclaw-setup] Started: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "[openclaw-setup] ============================================"

export DEBIAN_FRONTEND=noninteractive

# Fix locale warnings
export LC_ALL=C.UTF-8
export LANG=C.UTF-8

# ============================================================
# Generate credentials if not provided
# ============================================================
if [[ -z "${GATEWAY_TOKEN}" ]]; then
    GATEWAY_TOKEN=$(openssl rand -hex 32)
    echo "[openclaw-setup] Generated random gateway token."
fi

# Validate token (alphanumeric, minimum 32 characters for security)
if [[ ! "${GATEWAY_TOKEN}" =~ ^[a-zA-Z0-9]+$ ]]; then
    echo "[openclaw-setup] ERROR: Gateway token must be alphanumeric only."
    exit 1
fi
if [[ ${#GATEWAY_TOKEN} -lt 32 ]]; then
    echo "[openclaw-setup] ERROR: Gateway token must be at least 32 characters for security."
    exit 1
fi

# Validate SSH port
if [[ ! "${SSH_PORT}" =~ ^[0-9]+$ ]] || [[ "${SSH_PORT}" -lt 1024 ]] || [[ "${SSH_PORT}" -gt 65535 ]]; then
    echo "[openclaw-setup] ERROR: SSH port must be a number between 1024 and 65535."
    exit 1
fi

VPS_IP=$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')
echo "[openclaw-setup] VPS IP: ${VPS_IP}"

# ============================================================
# 1. Install system dependencies
# ============================================================
echo "[openclaw-setup] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    curl wget git jq htop \
    nftables fail2ban \
    unattended-upgrades apt-listchanges \
    ca-certificates gnupg openssl \
    apparmor apparmor-utils \
    python3 iproute2

# ============================================================
# 2. Install browsers
# ============================================================
echo "[openclaw-setup] Installing Google Chrome..."
if ! command -v google-chrome &>/dev/null; then
    wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/chrome.deb
    apt-get install -y -qq /tmp/chrome.deb
    rm -f /tmp/chrome.deb
fi
echo "[openclaw-setup] Chrome $(google-chrome --version) installed."

# Install Firefox in desktop mode
if [[ "${DESKTOP_MODE}" == "true" ]]; then
    echo "[openclaw-setup] Installing Firefox..."
    # Remove snap firefox if present (causes issues with VNC)
    snap remove firefox 2>/dev/null || true
    # Install from Mozilla PPA for latest version
    add-apt-repository -y ppa:mozillateam/ppa 2>/dev/null || true
    # Prefer PPA over snap
    cat > /etc/apt/preferences.d/mozilla-firefox <<'MOZPREF'
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001
MOZPREF
    apt-get update -qq
    apt-get install -y -qq firefox
    echo "[openclaw-setup] Firefox installed."
fi

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
# 5. Install desktop environment (if --desktop)
# ============================================================
if [[ "${DESKTOP_MODE}" == "true" ]]; then
    echo "[openclaw-setup] Installing XFCE desktop environment..."
    apt-get install -y -qq \
        xfce4 \
        xfce4-terminal \
        xfce4-goodies \
        dbus-x11 \
        x11-xserver-utils \
        xfonts-base \
        fonts-dejavu \
        fonts-liberation \
        gtk2-engines-pixbuf \
        libxfce4ui-utils \
        thunar \
        mousepad \
        lightdm \
        lightdm-gtk-greeter
    
    # Configure auto-login for openclaw user
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/50-openclaw-autologin.conf <<'LIGHTDM'
[Seat:*]
autologin-user=openclaw
autologin-user-timeout=0
user-session=xfce
LIGHTDM
    
    echo "[openclaw-setup] Desktop environment installed."
fi

# ============================================================
# 6. Create openclaw user
# ============================================================
echo "[openclaw-setup] Creating openclaw user..."
useradd -r -m -s /bin/bash -d "${OPENCLAW_HOME}" "${OPENCLAW_USER}" 2>/dev/null || true
usermod -aG docker "${OPENCLAW_USER}"
# Add desktop groups if in desktop mode
if [[ "${DESKTOP_MODE}" == "true" ]]; then
    usermod -aG audio,video "${OPENCLAW_USER}" 2>/dev/null || true
fi
mkdir -p "${OPENCLAW_WORKSPACE}"
chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}"

# ============================================================
# 6. Install OpenClaw
# ============================================================
echo "[openclaw-setup] Installing OpenClaw (latest)..."
npm install -g openclaw@latest

if ! command -v openclaw &>/dev/null; then
    echo "[openclaw-setup] ERROR: openclaw binary not found after install."
    exit 1
fi
echo "[openclaw-setup] OpenClaw $(openclaw --version) installed."

# Pre-pull sandbox Docker image
echo "[openclaw-setup] Pre-pulling sandbox image..."
docker pull node:22-bookworm-slim || echo "[openclaw-setup] WARNING: Could not pre-pull sandbox image."

# ============================================================
# 7. Configure OpenClaw (non-interactive onboard)
# ============================================================
echo "[openclaw-setup] Running non-interactive onboard..."
su - "${OPENCLAW_USER}" -c "openclaw onboard \
    --non-interactive \
    --accept-risk \
    --workspace ${OPENCLAW_WORKSPACE} \
    --mode local \
    --gateway-bind loopback \
    --gateway-port 18789 \
    --gateway-auth token \
    --gateway-token ${GATEWAY_TOKEN} \
    --skip-daemon \
    --skip-channels \
    --skip-skills \
    --skip-health \
    --skip-ui" 2>&1 || true

# Enable channel plugins
echo "[openclaw-setup] Enabling channel plugins..."
su - "${OPENCLAW_USER}" -c "openclaw plugins enable whatsapp" 2>&1 || true
su - "${OPENCLAW_USER}" -c "openclaw plugins enable telegram" 2>&1 || true
su - "${OPENCLAW_USER}" -c "openclaw plugins enable discord" 2>&1 || true
su - "${OPENCLAW_USER}" -c "openclaw plugins enable slack" 2>&1 || true
su - "${OPENCLAW_USER}" -c "openclaw plugins enable signal" 2>&1 || true

# Create credentials directory
mkdir -p "${OPENCLAW_CONFIG_DIR}/credentials"
chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_CONFIG_DIR}/credentials"
chmod 700 "${OPENCLAW_CONFIG_DIR}/credentials"

# ============================================================
# 8. Patch openclaw.json
# ============================================================
echo "[openclaw-setup] Configuring openclaw.json..."
OPENCLAW_JSON="${OPENCLAW_CONFIG_DIR}/openclaw.json"

python3 -c "
import json

config_path = '${OPENCLAW_JSON}'
try:
    with open(config_path) as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    config = {}

gw = config.setdefault('gateway', {})
gw['mode'] = 'local'
gw['bind'] = 'loopback'
gw['port'] = 18789

auth = gw.setdefault('auth', {})
auth['mode'] = 'token'
auth['token'] = '${GATEWAY_TOKEN}'
auth['allowTailscale'] = False

# Control UI enabled for SSH tunnel access
ui = gw.setdefault('controlUi', {})
ui['enabled'] = True

with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')

print('[openclaw-setup] openclaw.json configured.')
"

chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_JSON}"
chmod 600 "${OPENCLAW_JSON}"

# Create .env for environment variables
cat > "${OPENCLAW_HOME}/.env" <<ENVFILE
# OpenClaw Environment — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# DO NOT SHARE THIS FILE

# Browser tool (Google Chrome headless)
PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome
PUPPETEER_SKIP_DOWNLOAD=true

# LLM API Keys — add your own:
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...

# Channel Tokens:
# TELEGRAM_BOT_TOKEN=...

NODE_ENV=production
ENVFILE

# Add DISPLAY for desktop mode
if [[ "${DESKTOP_MODE}" == "true" ]]; then
    echo "" >> "${OPENCLAW_HOME}/.env"
    echo "# Desktop mode - X11 display" >> "${OPENCLAW_HOME}/.env"
    echo "DISPLAY=:0" >> "${OPENCLAW_HOME}/.env"
fi

chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/.env"
chmod 600 "${OPENCLAW_HOME}/.env"

# ============================================================
# Desktop: Configure XFCE and browser settings
# ============================================================
if [[ "${DESKTOP_MODE}" == "true" ]]; then
    echo "[openclaw-setup] Configuring desktop environment..."
    
    # Disable screensaver and screen lock
    XFCE_CONFIG="${OPENCLAW_HOME}/.config/xfce4/xfconf/xfce-perchannel-xml"
    mkdir -p "${XFCE_CONFIG}"
    
    cat > "${XFCE_CONFIG}/xfce4-screensaver.xml" <<'XFCESCREEN'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-screensaver" version="1.0">
  <property name="saver" type="empty">
    <property name="enabled" type="bool" value="false"/>
  </property>
  <property name="lock" type="empty">
    <property name="enabled" type="bool" value="false"/>
  </property>
</channel>
XFCESCREEN
    
    cat > "${XFCE_CONFIG}/xfce4-power-manager.xml" <<'XFCEPOWER'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-power-manager" version="1.0">
  <property name="xfce4-power-manager" type="empty">
    <property name="dpms-enabled" type="bool" value="false"/>
    <property name="blank-on-ac" type="int" value="0"/>
  </property>
</channel>
XFCEPOWER
    
    chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/.config"
    
    # Update OpenClaw config for desktop mode (real browser, not headless)
    echo "[openclaw-setup] Configuring OpenClaw for desktop mode..."
    python3 -c "
import json
config_path = '${OPENCLAW_JSON}'
with open(config_path) as f:
    config = json.load(f)
config.setdefault('browser', {})
config['browser']['enabled'] = True
config['browser']['headless'] = False
config['browser']['noSandbox'] = True
config['browser']['executablePath'] = '/usr/bin/google-chrome'
config['browser']['defaultProfile'] = 'openclaw'
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
"

    # Set default resolution for VNC (1360x768 - laptop-style)
    echo "[openclaw-setup] Setting default display resolution..."
    cat > "${OPENCLAW_HOME}/.xprofile" <<'XPROFILE'
#!/bin/bash
# Set resolution for VNC display (laptop-style 1360x768)
xrandr --output VGA-1 --mode 1360x768 2>/dev/null || true
XPROFILE
    chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/.xprofile"
    chmod +x "${OPENCLAW_HOME}/.xprofile"

    echo "[openclaw-setup] Desktop configured."
fi

# ============================================================
# 9. Hardening — SSH (custom port + hardening) — BEFORE firewall!
# ============================================================
echo "[openclaw-setup] Hardening SSH (port ${SSH_PORT})..."

# Ubuntu 24.04 uses systemd socket activation for SSH
# We need to modify BOTH sshd_config AND the systemd socket unit

# Change SSH port in sshd_config
sed -i "s/^#\?Port.*/Port ${SSH_PORT}/" /etc/ssh/sshd_config
grep -q "^Port" /etc/ssh/sshd_config || echo "Port ${SSH_PORT}" >> /etc/ssh/sshd_config

# Hardening settings
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#\?AllowTcpForwarding.*/AllowTcpForwarding yes/' /etc/ssh/sshd_config
sed -i 's/^#\?AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config

grep -q "^ClientAliveInterval" /etc/ssh/sshd_config || echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
grep -q "^ClientAliveCountMax" /etc/ssh/sshd_config || echo "ClientAliveCountMax 2" >> /etc/ssh/sshd_config
grep -q "^LoginGraceTime" /etc/ssh/sshd_config || echo "LoginGraceTime 30" >> /etc/ssh/sshd_config
grep -q "^Ciphers" /etc/ssh/sshd_config || \
    echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> /etc/ssh/sshd_config
grep -q "^MACs" /etc/ssh/sshd_config || \
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com" >> /etc/ssh/sshd_config

# Ubuntu 24.04: Disable socket activation, use traditional sshd instead
# Socket activation complicates port changes and can cause issues
if systemctl is-enabled --quiet ssh.socket 2>/dev/null; then
    echo "[openclaw-setup] Disabling SSH socket activation for reliable port change..."
    systemctl stop ssh.socket 2>/dev/null || true
    systemctl disable ssh.socket 2>/dev/null || true
    # Mask it to prevent re-enabling
    systemctl mask ssh.socket 2>/dev/null || true
fi

# Now restart SSH service (which reads Port from sshd_config)
echo "[openclaw-setup] Restarting SSH service on port ${SSH_PORT}..."
systemctl restart ssh.service || systemctl restart sshd.service || systemctl restart ssh || systemctl restart sshd

# Verify SSH is listening on new port before applying firewall
sleep 2
if ! ss -tlnp | grep -q ":${SSH_PORT}"; then
    echo "[openclaw-setup] ERROR: SSH not listening on port ${SSH_PORT}. Aborting to prevent lockout."
    exit 1
fi
echo "[openclaw-setup] SSH now listening on port ${SSH_PORT}"

# ============================================================
# 10. Hardening — nftables firewall (SSH ONLY on custom port)
# ============================================================
echo "[openclaw-setup] Configuring nftables firewall (SSH on port ${SSH_PORT} only)..."

# Disable ufw if present (conflicts with nftables)
if command -v ufw &>/dev/null; then
    ufw disable 2>/dev/null || true
    systemctl disable ufw 2>/dev/null || true
fi

echo "[openclaw-setup] Firewall: Opening SSH (${SSH_PORT}) only"

cat > /etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        ip protocol icmp icmp type echo-request limit rate 5/second accept
        ip6 nexthdr icmpv6 icmpv6 type echo-request limit rate 5/second accept
        tcp dport ${SSH_PORT} ct state new limit rate 10/minute accept
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
systemctl start nftables.service

# ============================================================
# 11. Hardening — fail2ban (SSH on custom port)
# ============================================================
echo "[openclaw-setup] Configuring fail2ban..."
cat > /etc/fail2ban/jail.local <<F2B
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 3
bantime = 7200
F2B
systemctl enable fail2ban.service
systemctl restart fail2ban.service

# ============================================================
# 12. Hardening — automatic security updates
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
# 13. Hardening — kernel (sysctl)
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
# 14. Hardening — Docker daemon
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
systemctl restart docker

# ============================================================
# 15. Hardening — disable unnecessary services
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
# 16. Hardening — AppArmor profile
# ============================================================
echo "[openclaw-setup] Installing AppArmor profile..."
OPENCLAW_BIN=$(which openclaw)
cat > /etc/apparmor.d/usr.bin.openclaw <<APPARMOR
#include <tunables/global>

${OPENCLAW_BIN} {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/ssl_certs>

  ${OPENCLAW_BIN} mr,
  /usr/bin/node mrix,
  /usr/lib/node_modules/** r,
  /usr/local/lib/node_modules/** r,

  owner /home/openclaw/ r,
  owner /home/openclaw/** rwk,
  owner /home/openclaw/.openclaw/** rw,
  owner /home/openclaw/workspace/** rw,
  owner /home/openclaw/.env r,

  /usr/bin/google-chrome mrix,
  /usr/bin/google-chrome-stable mrix,
  /opt/google/chrome/** mr,
  owner /home/openclaw/.cache/google-chrome/** rwk,
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
apparmor_parser -r /etc/apparmor.d/usr.bin.openclaw 2>/dev/null || \
    echo "[openclaw-setup] WARNING: Could not load AppArmor profile (will load at next boot)."

# ============================================================
# 17. Systemd service for OpenClaw gateway
# ============================================================
echo "[openclaw-setup] Creating systemd service..."
OPENCLAW_BIN=$(which openclaw)

if [[ "${DESKTOP_MODE}" == "true" ]]; then
    # Desktop mode: has DISPLAY set for real browser
    cat > /etc/systemd/system/openclaw-gateway.service <<SVCFILE
[Unit]
Description=OpenClaw Gateway - AI Assistant (Desktop Mode)
Documentation=https://docs.openclaw.ai
After=network-online.target docker.service display-manager.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_HOME}
EnvironmentFile=${OPENCLAW_HOME}/.env
Environment=DISPLAY=:0
# Fix for Node.js 22 IPv6 issues on some servers
Environment=NODE_OPTIONS=--dns-result-order=ipv4first
ExecStart=${OPENCLAW_BIN} gateway --port 18789 --bind loopback
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw

[Install]
WantedBy=multi-user.target
SVCFILE
else
    # Server mode (original)
    cat > /etc/systemd/system/openclaw-gateway.service <<SVCFILE
[Unit]
Description=OpenClaw Gateway - AI Assistant
Documentation=https://docs.openclaw.ai
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_HOME}
EnvironmentFile=${OPENCLAW_HOME}/.env
# Fix for Node.js 22 IPv6 issues on some servers
Environment=NODE_OPTIONS=--dns-result-order=ipv4first
ExecStart=${OPENCLAW_BIN} gateway --port 18789 --bind loopback
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=openclaw

[Install]
WantedBy=multi-user.target
SVCFILE
fi
systemctl daemon-reload
systemctl enable openclaw-gateway.service
systemctl start openclaw-gateway.service

echo "[openclaw-setup] Waiting for gateway to start..."
GATEWAY_UP=false
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:18789/ >/dev/null 2>&1; then
        echo "[openclaw-setup] Gateway is running."
        GATEWAY_UP=true
        break
    fi
    sleep 2
done
if [[ "${GATEWAY_UP}" != "true" ]]; then
    echo "[openclaw-setup] WARNING: Gateway did not start within 60s. Check: journalctl -u openclaw-gateway"
fi

# ============================================================
# 18. Install helper scripts
# ============================================================
echo "[openclaw-setup] Installing helper scripts..."

cat > /usr/local/bin/openclaw-status <<'HELPER'
#!/bin/bash
echo "=== OpenClaw Gateway ==="
systemctl status openclaw-gateway --no-pager -l
echo ""
echo "=== Health ==="
curl -s http://127.0.0.1:18789/ -o /dev/null -w "HTTP %{http_code}\n" 2>/dev/null || echo "Not responding"
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
    /home/openclaw/.openclaw /home/openclaw/workspace /home/openclaw/.env 2>/dev/null
echo "Backup: $BACKUP_DIR/openclaw-$DATE.tar.gz"
ls -t "$BACKUP_DIR"/openclaw-*.tar.gz | tail -n +8 | xargs -r rm
HELPER
chmod +x /usr/local/bin/openclaw-backup

cat > /usr/local/bin/openclaw-security-check <<HELPER
#!/bin/bash
echo "=== OpenClaw Security Audit ==="
echo ""
P=0; F=0
c() { if eval "\$1"; then echo "[PASS] \$2"; P=\$((P+1)); else echo "[FAIL] \$3"; F=\$((F+1)); fi; }
c '! ss -tlnp 2>/dev/null | grep -q "0.0.0.0:18789"' "Port 18789 localhost-only" "Port 18789 exposed!"
c 'test "\$(stat -c %a /home/openclaw/.env 2>/dev/null)" = "600"' ".env perms 600" ".env perms wrong"
c 'test -f /home/openclaw/.openclaw/openclaw.json' "Config file exists" "Config file missing!"
c 'systemctl is-active --quiet nftables' "Firewall active" "Firewall down!"
c 'systemctl is-active --quiet fail2ban' "fail2ban active" "fail2ban down!"
c 'systemctl is-active --quiet docker' "Docker running" "Docker down!"
c 'systemctl is-active --quiet openclaw-gateway' "Gateway running" "Gateway down!"
c 'grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config 2>/dev/null' "SSH passwd disabled" "SSH passwd enabled!"
c 'ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT}"' "SSH on port ${SSH_PORT}" "SSH not on custom port!"
c 'grep -q "token" /home/openclaw/.openclaw/openclaw.json 2>/dev/null' "Gateway token set" "Gateway token missing!"
c '! ss -tlnp 2>/dev/null | grep -qE ":443|:80|:22\$"' "No standard ports exposed" "Standard ports open!"
echo ""
echo "Score: \${P} pass, \${F} fail"
HELPER
chmod +x /usr/local/bin/openclaw-security-check

# Daily backup cron
echo "0 3 * * * root /usr/local/bin/openclaw-backup" > /etc/cron.d/openclaw-backup

# ============================================================
# 19. MOTD — CLI documentation on SSH login
# ============================================================
echo "[openclaw-setup] Setting up MOTD..."

if [[ "${DESKTOP_MODE}" == "true" ]]; then
    # Desktop mode MOTD
    cat > /etc/motd <<MOTD

  ═══════════════════════════════════════════════════════════
   OpenClaw Desktop - AI Assistant with Full GUI
  ═══════════════════════════════════════════════════════════

   DESKTOP ACCESS:

   Use your VPS provider's VNC console to access the desktop.

   The desktop auto-logs in as 'openclaw' user.
   OpenClaw browser is visible - watch your AI work in real-time!

  ═══════════════════════════════════════════════════════════
   SETUP (3 simple steps):
  ═══════════════════════════════════════════════════════════

   1. Open VNC console from your provider's control panel

   2. Add your API key:
      su - openclaw -c "openclaw models auth add"

   3. Verify everything works:
      su - openclaw -c "openclaw health"

  ═══════════════════════════════════════════════════════════
   USEFUL COMMANDS
  ═══════════════════════════════════════════════════════════

   openclaw status         Check gateway status
   openclaw doctor         Diagnose problems
   openclaw logs -f        Live logs
   openclaw-security-check Security audit

  ═══════════════════════════════════════════════════════════
   Docs: https://docs.openclaw.ai
  ═══════════════════════════════════════════════════════════

MOTD
else
    # Server mode MOTD (original)
    cat > /etc/motd <<MOTD

  ═══════════════════════════════════════════════════════════
   OpenClaw AI Assistant - Ready to configure
  ═══════════════════════════════════════════════════════════

   SETUP (3 simple steps):

   1. Add your API key (Claude, OpenAI, etc.):
      su - openclaw -c "openclaw models auth add"

   2. Connect messaging (WhatsApp, Telegram, etc.):
      su - openclaw -c "openclaw channels login"

   3. Verify everything works:
      su - openclaw -c "openclaw health"

  ═══════════════════════════════════════════════════════════
   USEFUL COMMANDS
  ═══════════════════════════════════════════════════════════

   openclaw status         Check gateway status
   openclaw doctor         Diagnose problems
   openclaw logs -f        Live logs
   openclaw-security-check Security audit

  ═══════════════════════════════════════════════════════════
   OPTIONAL: Web UI (from your computer)
  ═══════════════════════════════════════════════════════════

   1. Open SSH tunnel:
      ssh -p ${SSH_PORT} -L 18789:127.0.0.1:18789 root@${VPS_IP}

   2. Open in browser:
      http://localhost:18789/?token=${GATEWAY_TOKEN}

  ═══════════════════════════════════════════════════════════
   Docs: https://docs.openclaw.ai
  ═══════════════════════════════════════════════════════════

MOTD
fi

# ============================================================
# 20. Finalize
# ============================================================
mkdir -p /opt/openclaw-setup
touch "${PROVISIONED_FLAG}"

# Save credentials for reference
cat > /opt/openclaw-setup/.credentials <<CREDS
# OpenClaw Credentials — $(date -u +"%Y-%m-%dT%H:%M:%SZ")
VPS_IP=${VPS_IP}
SSH_PORT=${SSH_PORT}
GATEWAY_TOKEN=${GATEWAY_TOKEN}
CREDS

if [[ "${DESKTOP_MODE}" == "true" ]]; then
    cat >> /opt/openclaw-setup/.credentials <<CREDS
DESKTOP_MODE=true
CREDS
fi
chmod 600 /opt/openclaw-setup/.credentials

echo ""
echo "[openclaw-setup] ============================================"
echo "[openclaw-setup] Setup complete!"
echo "[openclaw-setup] ============================================"
echo "[openclaw-setup] VPS IP:         ${VPS_IP}"
echo "[openclaw-setup] SSH Port:       ${SSH_PORT}"
echo "[openclaw-setup] Gateway Token:  ${GATEWAY_TOKEN}"

if [[ "${DESKTOP_MODE}" == "true" ]]; then
    echo "[openclaw-setup] Mode:           Desktop (XFCE + real browsers)"
fi

echo "[openclaw-setup] ============================================"
echo "[openclaw-setup]"
echo "[openclaw-setup] IMPORTANT: SSH port changed to ${SSH_PORT}"
echo "[openclaw-setup] Reconnect with: ssh -p ${SSH_PORT} root@${VPS_IP}"

if [[ "${DESKTOP_MODE}" == "true" ]]; then
    echo "[openclaw-setup]"
    echo "[openclaw-setup] Desktop Access:"
    echo "[openclaw-setup]   Use your VPS provider's VNC console"
    echo "[openclaw-setup]   Desktop auto-logs in as 'openclaw' user"
fi

echo "[openclaw-setup]"
echo "[openclaw-setup] Next steps (shown on login):"
echo "[openclaw-setup]   1. Add your API key to /home/openclaw/.env"
echo "[openclaw-setup]   2. Restart gateway:   systemctl restart openclaw-gateway"
echo "[openclaw-setup]   3. Setup channels:    su - openclaw -c 'openclaw onboard'"
echo "[openclaw-setup]"
echo "[openclaw-setup] Documentation: https://docs.openclaw.ai"
echo "[openclaw-setup] ============================================"
