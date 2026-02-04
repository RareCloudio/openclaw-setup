# OpenClaw Secure VPS Setup

**Stop exposing your AI assistant to the internet.**

In January 2026, security researchers found [42,000+ OpenClaw instances](https://www.theregister.com/2026/02/02/openclaw_security_issues/) running with no authentication — API keys, conversations, and personal data wide open. This project fixes that.

One command. 7-layer security. **Your OpenClaw, locked down.**

> **Want a pre-configured VPS?** Get OpenClaw ready-to-use at [rarecloud.io](https://rarecloud.io) — no setup required.

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/RareCloudio/openclaw-setup/main/setup.sh | bash
```

After setup, SSH is moved to port **41722**. Reconnect with:
```bash
ssh -p 41722 root@YOUR_VPS_IP
```

The MOTD will show your Gateway Token and step-by-step instructions for adding your API key and connecting messaging channels.

## What It Does

1. **Installs** Node.js 22, Docker, headless Chrome
2. **Installs** OpenClaw (latest version via npm)
3. **Configures** OpenClaw gateway on loopback:18789 (not exposed)
4. **Enables** channel plugins (WhatsApp, Telegram, Discord, Slack, Signal)
5. **Hardens** the entire system (see Security below)
6. **Changes** SSH to custom port (41722 by default)
7. **Creates** systemd service, helper commands, daily backups
8. **Displays** comprehensive setup guide in MOTD on SSH login

## Options

```bash
# Recommended: let the script generate a secure token
bash setup.sh

# Or provide your own secure token:
bash setup.sh --gateway-token "$(openssl rand -hex 32)" --ssh-port 41722
```

| Flag | Description | Default |
|------|-------------|---------|
| `--gateway-token` | Gateway auth token (alphanumeric, min 32 chars) | random 64-char hex |
| `--ssh-port` | SSH port (1024-65535) | 41722 |

## Architecture

OpenClaw runs **natively on the host** (not in Docker):
- Browser tool works (headless Chrome)
- Full filesystem access within user boundaries
- Docker is used **only** for agent sandbox isolation

```
Internet --> SSH (port 41722) --> CLI access to OpenClaw
                                          |
             Gateway (127.0.0.1:18789) <--+
                      |
             Docker sandbox (agent sessions)
```

**Port 18789 is NEVER exposed** to the internet. Access is via:
- **SSH + CLI commands** (primary method)
- **SSH tunnel for WebUI** (optional): `ssh -p 41722 -L 18789:127.0.0.1:18789 root@server`

## 7-Layer Security Model

| Layer | What | Why |
|-------|------|-----|
| 1. nftables | Firewall: only custom SSH port open | Blocks all unauthorized access |
| 2. fail2ban | Brute-force protection (SSH) | Auto-bans attackers |
| 3. SSH hardening | Key-only auth, no password, custom port | Prevents brute-force |
| 4. Gateway token | OpenClaw token auth (64-char hex) | API-level authentication |
| 5. AppArmor | Kernel-level process confinement | Restricts what OpenClaw can access |
| 6. Docker sandbox | Agent code runs in isolated containers | cap_drop ALL, resource limits |
| 7. systemd | NoNewPrivileges, ProtectSystem, PrivateTmp | OS-level isolation |

No WebUI exposure eliminates the attack surface from the 42,000+ exposed instances found in January 2026.

## Post-Setup Guide

After SSH login, you'll see the setup instructions. Here's the quick version:

### Step 1: Add Your API Key

```bash
su - openclaw -c "openclaw models auth add"
```

This interactive wizard lets you add API keys for Claude, OpenAI, and other providers.

### Step 2: Connect a Messaging Channel

```bash
su - openclaw -c "openclaw channels login"
```

For WhatsApp, scan the QR code. For Telegram/Discord/Slack, run `openclaw onboard`.

### Step 3: Verify Setup

```bash
su - openclaw -c "openclaw health"
```

## Helper Commands

```bash
openclaw-status          # Check gateway status, health, recent logs
openclaw-security-check  # Run full security audit (11 checks)
openclaw-backup          # Create backup (auto-runs daily at 3 AM)
```

## Post-Install Verification

After setup completes, verify all security layers are properly configured:

```bash
bash verify.sh
```

This runs 11 automated checks including:
- OpenClaw installation and gateway status
- Firewall configuration (nftables)
- SSH hardening
- fail2ban protection
- Docker and AppArmor
- File permissions and workspace setup

Exit codes:
- `0` - All checks passed ✅
- `1` - Minor issues (warnings) ⚠️
- `2` - Critical failures ❌

## Optional: WebUI via SSH Tunnel

If you prefer using the Control UI instead of CLI:

```bash
# From your local machine:
ssh -p 41722 -L 18789:127.0.0.1:18789 root@YOUR_VPS_IP

# Then open in browser (token is in /opt/openclaw-setup/.credentials):
http://localhost:18789/?token=YOUR_GATEWAY_TOKEN
```

The full URL with token is shown in the MOTD when you SSH into the server.

## Files & Locations

| Path | Description |
|------|-------------|
| `/home/openclaw/.openclaw/openclaw.json` | OpenClaw configuration |
| `/home/openclaw/.env` | API keys and environment variables |
| `/home/openclaw/workspace` | Agent workspace |
| `/opt/openclaw-setup/.credentials` | Saved credentials (chmod 600) |
| `/var/log/openclaw-setup.log` | Setup log |

## Requirements

- Fresh Ubuntu 24.04 LTS VPS
- Root access (SSH key recommended)
- Minimum: 2 vCPU, 4GB RAM, 20GB disk

## Troubleshooting

```bash
# Gateway not starting?
journalctl -u openclaw-gateway -f

# Config issues?
su - openclaw -c "openclaw doctor"

# Security audit?
openclaw-security-check
```

## Contributing

We need help securing more OpenClaw installations. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- Support for more Linux distributions
- Additional hardening measures
- Automated security testing
- Translations

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

If you fork or build upon this project, a link back to [RareCloudio/openclaw-setup](https://github.com/RareCloudio/openclaw-setup) is appreciated.
