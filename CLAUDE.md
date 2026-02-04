# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Automated, hardened OpenClaw setup for Ubuntu 24.04 VPS. Single script that installs everything and applies 7-layer security hardening. **CLI-only access** — no WebUI exposed to the internet.

## Files

- `setup.sh` — Main setup script. Installs Node.js 22, Docker, Chrome, OpenClaw, and applies all hardening. Accepts `--gateway-token` and `--ssh-port` flags.
- `OPENCLAW-REFERENCE.md` — Comprehensive reference document about OpenClaw internals, WebSocket protocol, authentication, configuration.

## Architecture

```
Internet --> SSH (port 41722) --> CLI access to OpenClaw
                                          |
             Gateway (127.0.0.1:18789) <--+
                      |
             Docker sandbox (agent sessions)
```

- OpenClaw runs natively on host (not Docker)
- Docker is only for agent sandbox isolation
- Gateway binds to loopback:18789 (NEVER exposed)
- Access via SSH + CLI commands only
- Optional: SSH tunnel for WebUI (`ssh -p 41722 -L 18789:127.0.0.1:18789 root@server`)

## Key Configuration

In `openclaw.json`:
```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "auth": {
      "mode": "token",
      "token": "<generated>",
      "allowTailscale": false
    },
    "controlUi": {
      "enabled": true
    }
  }
}
```

## Security Model (7 layers)

1. nftables firewall (custom SSH port only, all else blocked)
2. fail2ban (SSH brute-force protection)
3. SSH hardening (key-only, no password, custom port 41722)
4. Gateway token (WebSocket first-frame auth)
5. AppArmor (process confinement)
6. Docker sandbox (agent isolation, cap_drop ALL)
7. systemd hardening (NoNewPrivileges, ProtectSystem)

## Ubuntu 24.04 SSH Port Change

Ubuntu 24.04 uses systemd socket activation for SSH. Changing the port requires:
1. Modify `/etc/ssh/sshd_config` (Port directive)
2. Create systemd socket override at `/etc/systemd/system/ssh.socket.d/override.conf`
3. Reload systemd and restart ssh.socket + ssh.service

The script handles this automatically.

## Testing

```bash
# On a fresh Ubuntu 24.04 VPS:
# Token is auto-generated if not provided (recommended)
bash setup.sh

# Or generate a secure token explicitly:
bash setup.sh --gateway-token "$(openssl rand -hex 32)"

# After setup, reconnect on new port:
ssh -p 41722 root@VPS_IP

# Verify:
openclaw-status
openclaw-security-check  # Should show 11/11 pass
```

## Common Commands (for customers)

```bash
# Add API key
nano /home/openclaw/.env
systemctl restart openclaw-gateway

# Connect WhatsApp
su - openclaw -c "openclaw channels login"

# Check status
openclaw status
openclaw health
openclaw doctor

# Security audit
openclaw-security-check
```
