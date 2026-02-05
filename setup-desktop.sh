#!/bin/bash
#
# OpenClaw Desktop Setup Script
# Ubuntu Desktop environment for OpenClaw with real browser and VNC access
#
# Usage: sudo ./setup-desktop.sh [OPTIONS]
#
# Options:
#   --vnc-password PASS    Set VNC password (prompted if not provided)
#   --novnc                Enable noVNC web access on port 6080
#   --browser chrome       Use Chrome instead of Firefox (default: firefox)
#   --ssh-port PORT        SSH port (default: 41722)
#   --skip-firewall        Skip firewall configuration
#   --help                 Show this help
#
# Requirements:
#   - Ubuntu 24.04 Desktop or Server (will install desktop packages)
#   - 4GB+ RAM recommended
#   - Root/sudo access
#   - Internet connection
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_VERSION="1.0.0"
OPENCLAW_USER="openclaw"
OPENCLAW_HOME="/home/${OPENCLAW_USER}"
OPENCLAW_WORKSPACE="${OPENCLAW_HOME}/workspace"

# Defaults
SSH_PORT="${SSH_PORT:-41722}"
VNC_PORT="5901"
NOVNC_PORT="6080"
VNC_PASSWORD=""
ENABLE_NOVNC=false
BROWSER="firefox"
SKIP_FIREWALL=false

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# =============================================================================
# ARGUMENT PARSING
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --vnc-password)
                VNC_PASSWORD="$2"
                shift 2
                ;;
            --novnc)
                ENABLE_NOVNC=true
                shift
                ;;
            --browser)
                BROWSER="$2"
                shift 2
                ;;
            --ssh-port)
                SSH_PORT="$2"
                shift 2
                ;;
            --skip-firewall)
                SKIP_FIREWALL=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

show_help() {
    head -30 "$0" | tail -25 | sed 's/^#//'
}

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Root check
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Ubuntu check
    if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
        log_error "This script requires Ubuntu"
        exit 1
    fi
    
    # Version check
    VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
    if [[ "${VERSION}" != "24.04" && "${VERSION}" != "22.04" ]]; then
        log_warn "Tested on Ubuntu 24.04/22.04. You have ${VERSION}. Proceeding anyway..."
    fi
    
    # RAM check
    TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
    if [[ ${TOTAL_RAM} -lt 3500 ]]; then
        log_warn "Less than 4GB RAM detected (${TOTAL_RAM}MB). Desktop may be slow."
    fi
    
    log_success "Prerequisites check passed"
}

# =============================================================================
# USER SETUP
# =============================================================================

setup_user() {
    log_info "Setting up user ${OPENCLAW_USER}..."
    
    if id "${OPENCLAW_USER}" &>/dev/null; then
        log_info "User ${OPENCLAW_USER} already exists"
    else
        useradd -m -s /bin/bash "${OPENCLAW_USER}"
        log_success "Created user ${OPENCLAW_USER}"
    fi
    
    # Add to necessary groups for desktop
    usermod -aG sudo,audio,video,plugdev "${OPENCLAW_USER}" 2>/dev/null || true
    
    # Create workspace
    mkdir -p "${OPENCLAW_WORKSPACE}"
    chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}"
    
    log_success "User setup complete"
}

# =============================================================================
# DESKTOP ENVIRONMENT
# =============================================================================

install_desktop_environment() {
    log_info "Installing XFCE desktop environment..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update
    apt-get install -y --no-install-recommends \
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
        mousepad
    
    # Clean up
    apt-get autoremove -y
    apt-get clean
    
    log_success "XFCE desktop installed"
}

configure_autologin() {
    log_info "Configuring auto-login for ${OPENCLAW_USER}..."
    
    # Install LightDM if not present
    apt-get install -y lightdm lightdm-gtk-greeter
    
    # Configure LightDM auto-login
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/50-openclaw-autologin.conf << EOF
[Seat:*]
autologin-user=${OPENCLAW_USER}
autologin-user-timeout=0
user-session=xfce
EOF
    
    log_success "Auto-login configured"
}

disable_screen_lock() {
    log_info "Disabling screen lock and screensaver..."
    
    # Create XFCE config directory
    XFCE_CONFIG="${OPENCLAW_HOME}/.config/xfce4/xfconf/xfce-perchannel-xml"
    mkdir -p "${XFCE_CONFIG}"
    
    # Disable screensaver
    cat > "${XFCE_CONFIG}/xfce4-screensaver.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-screensaver" version="1.0">
  <property name="saver" type="empty">
    <property name="enabled" type="bool" value="false"/>
  </property>
  <property name="lock" type="empty">
    <property name="enabled" type="bool" value="false"/>
  </property>
</channel>
EOF
    
    # Disable power management screen blank
    cat > "${XFCE_CONFIG}/xfce4-power-manager.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-power-manager" version="1.0">
  <property name="xfce4-power-manager" type="empty">
    <property name="dpms-enabled" type="bool" value="false"/>
    <property name="blank-on-ac" type="int" value="0"/>
    <property name="dpms-on-ac-sleep" type="uint" value="0"/>
    <property name="dpms-on-ac-off" type="uint" value="0"/>
  </property>
</channel>
EOF
    
    chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/.config"
    
    log_success "Screen lock and screensaver disabled"
}

# =============================================================================
# VNC SERVER
# =============================================================================

install_vnc_server() {
    log_info "Installing TigerVNC server..."
    
    apt-get install -y tigervnc-standalone-server tigervnc-common
    
    log_success "TigerVNC installed"
}

configure_vnc_server() {
    log_info "Configuring VNC server..."
    
    VNC_DIR="${OPENCLAW_HOME}/.vnc"
    mkdir -p "${VNC_DIR}"
    
    # Set VNC password
    if [[ -z "${VNC_PASSWORD}" ]]; then
        log_warn "No VNC password provided. Generating random password..."
        VNC_PASSWORD=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
        echo ""
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}  VNC PASSWORD: ${VNC_PASSWORD}${NC}"
        echo -e "${YELLOW}  Save this password! You'll need it to connect.${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
        echo ""
    fi
    
    # Create password file
    echo "${VNC_PASSWORD}" | vncpasswd -f > "${VNC_DIR}/passwd"
    chmod 600 "${VNC_DIR}/passwd"
    
    # VNC startup script
    cat > "${VNC_DIR}/xstartup" << 'EOF'
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XKL_XMODMAP_DISABLE=1

# Start XFCE
exec startxfce4
EOF
    chmod +x "${VNC_DIR}/xstartup"
    
    # VNC config
    cat > "${VNC_DIR}/config" << EOF
geometry=1920x1080
depth=24
EOF
    
    chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${VNC_DIR}"
    
    # Create systemd service for VNC
    cat > /etc/systemd/system/vncserver@.service << EOF
[Unit]
Description=TigerVNC Server for %i
After=syslog.target network.target

[Service]
Type=forking
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_HOME}

ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1
ExecStart=/usr/bin/vncserver :%i -geometry 1920x1080 -depth 24 -localhost no
ExecStop=/usr/bin/vncserver -kill :%i

Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable vncserver@1
    systemctl start vncserver@1
    
    log_success "VNC server configured and started on display :1 (port ${VNC_PORT})"
}

# =============================================================================
# noVNC (Web-based VNC)
# =============================================================================

install_novnc() {
    if [[ "${ENABLE_NOVNC}" != "true" ]]; then
        log_info "Skipping noVNC installation (use --novnc to enable)"
        return
    fi
    
    log_info "Installing noVNC for web-based access..."
    
    apt-get install -y novnc websockify python3-websockify
    
    # Create systemd service for noVNC
    cat > /etc/systemd/system/novnc.service << EOF
[Unit]
Description=noVNC WebSocket proxy
After=vncserver@1.service
Requires=vncserver@1.service

[Service]
Type=simple
User=${OPENCLAW_USER}
ExecStart=/usr/bin/websockify --web=/usr/share/novnc/ ${NOVNC_PORT} localhost:${VNC_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable novnc
    systemctl start novnc
    
    log_success "noVNC installed and started on port ${NOVNC_PORT}"
    log_info "Access via: http://<your-ip>:${NOVNC_PORT}/vnc.html"
}

# =============================================================================
# BROWSER INSTALLATION
# =============================================================================

install_browser() {
    log_info "Installing browser: ${BROWSER}..."
    
    if [[ "${BROWSER}" == "chrome" ]]; then
        install_chrome
    else
        install_firefox
    fi
    
    log_success "Browser ${BROWSER} installed"
}

install_firefox() {
    # Remove snap firefox if present (causes issues)
    snap remove firefox 2>/dev/null || true
    
    # Install from Mozilla PPA for latest version
    add-apt-repository -y ppa:mozillateam/ppa
    
    # Prefer PPA over snap
    cat > /etc/apt/preferences.d/mozilla-firefox << 'EOF'
Package: *
Pin: release o=LP-PPA-mozillateam
Pin-Priority: 1001
EOF
    
    apt-get update
    apt-get install -y firefox
    
    # Create desktop shortcut
    cp /usr/share/applications/firefox.desktop "${OPENCLAW_HOME}/Desktop/" 2>/dev/null || true
    chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/Desktop/firefox.desktop" 2>/dev/null || true
}

install_chrome() {
    # Download and install Chrome
    wget -q -O /tmp/chrome.deb "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
    apt-get install -y /tmp/chrome.deb
    rm /tmp/chrome.deb
    
    # Create desktop shortcut
    mkdir -p "${OPENCLAW_HOME}/Desktop"
    cp /usr/share/applications/google-chrome.desktop "${OPENCLAW_HOME}/Desktop/" 2>/dev/null || true
    chown "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/Desktop/google-chrome.desktop" 2>/dev/null || true
}

# =============================================================================
# OPENCLAW INSTALLATION
# =============================================================================

install_openclaw() {
    log_info "Installing OpenClaw..."
    
    # Install Node.js if not present
    if ! command -v node &>/dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
        apt-get install -y nodejs
    fi
    
    # Install OpenClaw globally
    npm install -g openclaw
    
    log_success "OpenClaw installed"
}

configure_openclaw_desktop() {
    log_info "Configuring OpenClaw for desktop mode..."
    
    OPENCLAW_CONFIG_DIR="${OPENCLAW_HOME}/.openclaw"
    mkdir -p "${OPENCLAW_CONFIG_DIR}"
    
    # Determine browser executable
    if [[ "${BROWSER}" == "chrome" ]]; then
        BROWSER_PATH="/usr/bin/google-chrome"
    else
        BROWSER_PATH="/usr/bin/firefox"
    fi
    
    # Create config with headless disabled
    cat > "${OPENCLAW_CONFIG_DIR}/config.yaml" << EOF
# OpenClaw Desktop Configuration
# Generated by setup-desktop.sh

gateway:
  port: 18789
  host: "127.0.0.1"

browser:
  headless: false
  executablePath: "${BROWSER_PATH}"
  defaultViewport:
    width: 1920
    height: 1080

# Security: only allow local connections
# Access via VNC to see the browser
EOF
    
    chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_CONFIG_DIR}"
    
    # Set DISPLAY in openclaw user's environment
    echo 'export DISPLAY=:1' >> "${OPENCLAW_HOME}/.bashrc"
    echo 'export DISPLAY=:1' >> "${OPENCLAW_HOME}/.profile"
    
    log_success "OpenClaw configured for desktop mode (headless: false)"
}

create_openclaw_service() {
    log_info "Creating OpenClaw systemd service..."
    
    cat > /etc/systemd/system/openclaw.service << EOF
[Unit]
Description=OpenClaw Gateway
After=network.target vncserver@1.service
Wants=vncserver@1.service

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_WORKSPACE}
Environment="DISPLAY=:1"
Environment="HOME=${OPENCLAW_HOME}"
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/bin/openclaw gateway start --foreground
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable openclaw
    
    log_info "OpenClaw service created (not started - configure your agent first)"
}

# =============================================================================
# FIREWALL CONFIGURATION
# =============================================================================

configure_firewall() {
    if [[ "${SKIP_FIREWALL}" == "true" ]]; then
        log_info "Skipping firewall configuration"
        return
    fi
    
    log_info "Configuring firewall..."
    
    apt-get install -y nftables
    
    # Build port list
    ALLOWED_PORTS="tcp dport { ${SSH_PORT} }"
    if [[ "${ENABLE_NOVNC}" == "true" ]]; then
        ALLOWED_PORTS="tcp dport { ${SSH_PORT}, ${NOVNC_PORT} }"
        log_info "Opening ports: SSH (${SSH_PORT}), noVNC (${NOVNC_PORT})"
    else
        log_info "Opening ports: SSH (${SSH_PORT})"
        log_info "VNC (${VNC_PORT}) accessible only via SSH tunnel"
    fi
    
    cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Allow established connections
        ct state established,related accept
        
        # Allow loopback
        iif lo accept
        
        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        
        # Allow SSH and optionally noVNC
        ${ALLOWED_PORTS} accept
        
        # Log and drop everything else
        log prefix "[nftables] Dropped: " drop
    }
    
    chain forward {
        type filter hook forward priority 0; policy drop;
    }
    
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
    
    systemctl enable nftables
    systemctl restart nftables
    
    log_success "Firewall configured"
}

configure_fail2ban() {
    log_info "Configuring fail2ban..."
    
    apt-get install -y fail2ban
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
banaction = nftables-multiport

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_success "fail2ban configured"
}

# =============================================================================
# SSH HARDENING
# =============================================================================

configure_ssh() {
    log_info "Configuring SSH on port ${SSH_PORT}..."
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)
    
    cat > /etc/ssh/sshd_config.d/99-openclaw-desktop.conf << EOF
# OpenClaw Desktop SSH Configuration
Port ${SSH_PORT}
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding yes
EOF
    
    systemctl restart sshd
    
    log_success "SSH configured on port ${SSH_PORT}"
}

# =============================================================================
# FINAL SETUP
# =============================================================================

create_motd() {
    log_info "Creating MOTD..."
    
    # Get IP address
    SERVER_IP=$(curl -s --max-time 5 ifconfig.me || hostname -I | awk '{print $1}')
    
    cat > /etc/update-motd.d/99-openclaw-desktop << EOF
#!/bin/bash

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "\${BLUE}═══════════════════════════════════════════════════════════════════\${NC}"
echo -e "\${BLUE}       OpenClaw Desktop - AI Assistant with Full GUI              \${NC}"
echo -e "\${BLUE}═══════════════════════════════════════════════════════════════════\${NC}"
echo ""
echo -e "\${GREEN}REMOTE DESKTOP ACCESS:\${NC}"
echo ""
EOF

    if [[ "${ENABLE_NOVNC}" == "true" ]]; then
        cat >> /etc/update-motd.d/99-openclaw-desktop << EOF
echo -e "  \${CYAN}Option 1 - Browser (noVNC):\${NC}"
echo -e "    URL:      \${YELLOW}http://${SERVER_IP}:${NOVNC_PORT}/vnc.html\${NC}"
echo -e "    Password: \${YELLOW}${VNC_PASSWORD}\${NC}"
echo ""
echo -e "  \${CYAN}Option 2 - VNC Client:\${NC}"
echo -e "    Server:   \${YELLOW}${SERVER_IP}:${VNC_PORT}\${NC}"
echo -e "    Password: \${YELLOW}${VNC_PASSWORD}\${NC}"
echo ""
echo -e "  \${CYAN}Option 3 - SSH Tunnel (most secure):\${NC}"
EOF
    else
        cat >> /etc/update-motd.d/99-openclaw-desktop << EOF
echo -e "  \${CYAN}Option 1 - VNC Client (via SSH tunnel):\${NC}"
echo -e "    Password: \${YELLOW}${VNC_PASSWORD}\${NC}"
echo ""
echo -e "  \${CYAN}Option 2 - SSH Tunnel (recommended):\${NC}"
EOF
    fi

    cat >> /etc/update-motd.d/99-openclaw-desktop << EOF
echo -e "    \${YELLOW}ssh -p ${SSH_PORT} -L 5901:127.0.0.1:5901 ${OPENCLAW_USER}@${SERVER_IP}\${NC}"
echo -e "    Then connect VNC viewer to: \${YELLOW}localhost:5901\${NC}"
echo ""
echo -e "\${BLUE}───────────────────────────────────────────────────────────────────\${NC}"
echo ""
echo -e "\${GREEN}QUICK COMMANDS:\${NC}"
echo ""
echo -e "  openclaw-status           Check gateway status"
echo -e "  openclaw-security-check   Run security audit"
echo -e "  systemctl status vncserver@1   Check VNC status"
echo ""
echo -e "\${GREEN}NEXT STEPS:\${NC}"
echo ""
echo -e "  1. Connect via VNC to see the desktop"
echo -e "  2. Add your API key:  su - ${OPENCLAW_USER} -c 'openclaw models auth add'"
echo -e "  3. Start OpenClaw:    sudo systemctl start openclaw"
echo -e "  4. Watch your AI work in the browser!"
echo ""
echo -e "\${GREEN}DOCUMENTATION:\${NC}"
echo -e "  https://github.com/RareCloudio/openclaw-setup/blob/main/docs/DESKTOP.md"
echo ""
echo -e "\${BLUE}═══════════════════════════════════════════════════════════════════\${NC}"
echo ""
EOF

    chmod +x /etc/update-motd.d/99-openclaw-desktop
    
    # Disable default Ubuntu MOTD components that add noise
    chmod -x /etc/update-motd.d/10-help-text 2>/dev/null || true
    chmod -x /etc/update-motd.d/50-motd-news 2>/dev/null || true
    
    log_success "MOTD created"
}

create_desktop_shortcuts() {
    log_info "Creating desktop shortcuts..."
    
    DESKTOP_DIR="${OPENCLAW_HOME}/Desktop"
    mkdir -p "${DESKTOP_DIR}"
    
    # Terminal shortcut
    cat > "${DESKTOP_DIR}/Terminal.desktop" << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Terminal
Exec=xfce4-terminal
Icon=utilities-terminal
Terminal=false
Categories=Utility;TerminalEmulator;
EOF
    
    # File Manager shortcut
    cat > "${DESKTOP_DIR}/Files.desktop" << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Files
Exec=thunar
Icon=system-file-manager
Terminal=false
Categories=Utility;FileManager;
EOF
    
    chmod +x "${DESKTOP_DIR}"/*.desktop
    chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${DESKTOP_DIR}"
    
    # Trust desktop files (XFCE specific)
    sudo -u "${OPENCLAW_USER}" bash -c "
        mkdir -p ${OPENCLAW_HOME}/.config/xfce4/desktop
        for f in ${DESKTOP_DIR}/*.desktop; do
            gio set \"\$f\" metadata::trusted true 2>/dev/null || true
        done
    "
    
    log_success "Desktop shortcuts created"
}

print_summary() {
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  OpenClaw Desktop Setup Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BLUE}SSH Access:${NC}"
    echo -e "    ssh -p ${SSH_PORT} ${OPENCLAW_USER}@<your-ip>"
    echo ""
    echo -e "  ${BLUE}VNC Access (via SSH tunnel):${NC}"
    echo -e "    ssh -p ${SSH_PORT} -L 5901:localhost:5901 ${OPENCLAW_USER}@<your-ip>"
    echo -e "    Then connect VNC viewer to: localhost:5901"
    echo ""
    if [[ "${ENABLE_NOVNC}" == "true" ]]; then
        echo -e "  ${BLUE}noVNC Web Access:${NC}"
        echo -e "    http://<your-ip>:${NOVNC_PORT}/vnc.html"
        echo ""
    fi
    echo -e "  ${BLUE}VNC Password:${NC} ${VNC_PASSWORD:-'(set during installation)'}"
    echo ""
    echo -e "  ${BLUE}Next Steps:${NC}"
    echo -e "    1. Connect via VNC to see the desktop"
    echo -e "    2. Configure your OpenClaw agent in ~/.openclaw/config.yaml"
    echo -e "    3. Start OpenClaw: sudo systemctl start openclaw"
    echo -e "    4. Watch your AI work in the browser! 🤖"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         OpenClaw Desktop Setup v${SCRIPT_VERSION}                       ║${NC}"
    echo -e "${BLUE}║         Ubuntu Desktop for AI Agents                          ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    parse_args "$@"
    
    check_prerequisites
    setup_user
    
    # Desktop environment
    install_desktop_environment
    configure_autologin
    disable_screen_lock
    
    # VNC
    install_vnc_server
    configure_vnc_server
    install_novnc
    
    # Browser
    install_browser
    
    # OpenClaw
    install_openclaw
    configure_openclaw_desktop
    create_openclaw_service
    
    # Security
    configure_ssh
    configure_firewall
    configure_fail2ban
    
    # Finishing touches
    create_desktop_shortcuts
    create_motd
    
    print_summary
}

main "$@"
