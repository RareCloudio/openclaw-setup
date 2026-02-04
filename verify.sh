#!/usr/bin/env bash
# openclaw-setup-verify — Post-installation verification script
# Verifies that all security layers and components are properly configured

set -euo pipefail

echo "🔍 OpenClaw Setup Verification"
echo "================================"
echo ""

PASSED=0
FAILED=0
WARNINGS=0

# Helper functions
pass() {
    echo "✅ PASS: $1"
    ((PASSED++))
}

fail() {
    echo "❌ FAIL: $1"
    ((FAILED++))
}

warn() {
    echo "⚠️  WARN: $1"
    ((WARNINGS++))
}

# ============================================================
# 1. Check OpenClaw Installation
# ============================================================
echo "[1/11] Checking OpenClaw installation..."
if command -v openclaw &>/dev/null; then
    VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
    pass "OpenClaw installed (version: $VERSION)"
else
    fail "OpenClaw not found in PATH"
fi

# ============================================================
# 2. Check OpenClaw User
# ============================================================
echo "[2/11] Checking openclaw user..."
if id openclaw &>/dev/null; then
    pass "User 'openclaw' exists"
else
    fail "User 'openclaw' not found"
fi

# ============================================================
# 3. Check Gateway Status
# ============================================================
echo "[3/11] Checking Gateway service..."
if systemctl is-active --quiet openclaw-gateway; then
    pass "Gateway service is running"
else
    fail "Gateway service is not running"
fi

# ============================================================
# 4. Check Gateway Binding
# ============================================================
echo "[4/11] Checking Gateway binding..."
if ss -tlnp | grep -q ":18789.*127.0.0.1"; then
    pass "Gateway bound to loopback only (127.0.0.1:18789)"
elif ss -tlnp | grep -q ":18789.*0.0.0.0"; then
    fail "Gateway exposed on 0.0.0.0:18789 - SECURITY RISK!"
else
    warn "Gateway not listening on port 18789"
fi

# ============================================================
# 5. Check Firewall (nftables)
# ============================================================
echo "[5/11] Checking firewall..."
if systemctl is-active --quiet nftables; then
    pass "nftables service is active"
    
    # Check if only SSH port is open
    if nft list ruleset | grep -q "tcp dport"; then
        pass "Firewall rules configured"
    else
        warn "No firewall rules found"
    fi
else
    fail "nftables service not active"
fi

# ============================================================
# 6. Check fail2ban
# ============================================================
echo "[6/11] Checking fail2ban..."
if systemctl is-active --quiet fail2ban; then
    pass "fail2ban service is active"
else
    fail "fail2ban service not active"
fi

# ============================================================
# 7. Check SSH Configuration
# ============================================================
echo "[7/11] Checking SSH hardening..."
SSH_CONFIG="/etc/ssh/sshd_config"

if grep -q "^PasswordAuthentication no" "$SSH_CONFIG"; then
    pass "Password authentication disabled"
else
    fail "Password authentication still enabled"
fi

if grep -q "^PermitRootLogin prohibit-password" "$SSH_CONFIG" || \
   grep -q "^PermitRootLogin no" "$SSH_CONFIG"; then
    pass "Root login properly restricted"
else
    warn "Root login configuration not hardened"
fi

# ============================================================
# 8. Check Docker
# ============================================================
echo "[8/11] Checking Docker..."
if systemctl is-active --quiet docker; then
    pass "Docker service is active"
    
    # Check if openclaw user is in docker group
    if groups openclaw 2>/dev/null | grep -q docker; then
        pass "User 'openclaw' in docker group"
    else
        fail "User 'openclaw' not in docker group"
    fi
else
    fail "Docker service not active"
fi

# ============================================================
# 9. Check AppArmor
# ============================================================
echo "[9/11] Checking AppArmor..."
if systemctl is-active --quiet apparmor; then
    pass "AppArmor service is active"
else
    warn "AppArmor service not active"
fi

# ============================================================
# 10. Check Workspace Permissions
# ============================================================
echo "[10/11] Checking workspace permissions..."
WORKSPACE="/home/openclaw/workspace"
if [[ -d "$WORKSPACE" ]]; then
    OWNER=$(stat -c '%U' "$WORKSPACE")
    if [[ "$OWNER" == "openclaw" ]]; then
        pass "Workspace owned by openclaw user"
    else
        fail "Workspace not owned by openclaw (owner: $OWNER)"
    fi
else
    fail "Workspace directory not found"
fi

# ============================================================
# 11. Check Credentials Security
# ============================================================
echo "[11/11] Checking credentials security..."
CREDS_FILE="/opt/openclaw-setup/.credentials"
if [[ -f "$CREDS_FILE" ]]; then
    PERMS=$(stat -c '%a' "$CREDS_FILE")
    if [[ "$PERMS" == "600" ]]; then
        pass "Credentials file has secure permissions (600)"
    else
        fail "Credentials file has insecure permissions ($PERMS)"
    fi
else
    warn "Credentials file not found"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "================================"
echo "📊 Verification Summary"
echo "================================"
echo "✅ Passed:   $PASSED"
echo "❌ Failed:   $FAILED"
echo "⚠️  Warnings: $WARNINGS"
echo ""

if [[ $FAILED -eq 0 ]]; then
    echo "🎉 All critical checks passed!"
    exit 0
elif [[ $FAILED -le 2 ]]; then
    echo "⚠️  Minor issues detected. Review failed checks above."
    exit 1
else
    echo "❌ Multiple critical failures detected. System may not be secure."
    exit 2
fi
