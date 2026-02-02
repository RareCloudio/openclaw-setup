# OpenClaw Secure VPS Setup

Automated, hardened setup for [OpenClaw](https://molt.bot) (formerly MoltBot) on a fresh Ubuntu 24.04 VPS.

One command to install OpenClaw with 8-layer security hardening.

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/rarecloud/openclaw-setup/main/setup.sh -o setup.sh
bash setup.sh
```

After setup completes, you'll see your WebUI URL and credentials. Add your LLM API key and you're ready to go.

## What It Does

1. **Installs** Node.js 22, Docker, headless Chromium, nginx
2. **Installs** OpenClaw (latest version via npm)
3. **Configures** nginx reverse proxy with TLS (self-signed) + basic-auth
4. **Configures** OpenClaw gateway on loopback:18789 with token auth
5. **Hardens** the entire system (see Security below)
6. **Creates** systemd service, helper commands, daily backups
7. **Displays** credentials in MOTD on SSH login

## Custom Credentials

For automation (e.g., hosting providers):

```bash
bash setup.sh --webui-pass "customerpass" --gateway-token "customtoken"
```

| Flag | Description | Default |
|------|-------------|---------|
| `--webui-user` | WebUI username | `admin` |
| `--webui-pass` | WebUI password | random generated |
| `--gateway-token` | Gateway API token | random generated |

## Architecture

OpenClaw runs **natively on the host** (not in Docker) for full functionality:
- Browser tool works (headless Chromium)
- Full filesystem access within user boundaries
- Docker is used **only** for agent sandbox isolation (code execution)

```
Internet → nginx (443/TLS + basic-auth) → OpenClaw gateway (127.0.0.1:18789)
                                                    ↓
                                           Docker sandbox (agent sessions)
```

Port 18789 is **never exposed** to the network. Access is only through:
- HTTPS (nginx reverse proxy on port 443)
- SSH tunnel (`ssh -L 18789:127.0.0.1:18789 root@server`)

## 8-Layer Security Model

| Layer | What | Why |
|-------|------|-----|
| 1. nftables | Firewall: only ports 22 + 443 open | Blocks all unauthorized access |
| 2. fail2ban | Brute-force protection (SSH + nginx) | Auto-bans attackers |
| 3. nginx TLS | HTTPS + security headers + rate limiting | Encrypted transport |
| 4. Basic-auth | Username/password on WebUI | First auth layer |
| 5. Gateway token | OpenClaw API token (64-char hex) | Second auth layer |
| 6. AppArmor | Kernel-level process confinement | Restricts what OpenClaw can access |
| 7. Docker sandbox | Agent code runs in isolated containers | cap_drop ALL, no network, 1GB mem |
| 8. systemd | NoNewPrivileges, ProtectSystem, PrivateTmp | OS-level isolation |

Based on security research: 780+ exposed OpenClaw/MoltBot instances found on Shodan in January 2026, 8+ without any authentication.

## Helper Commands

After setup, these commands are available:

```bash
openclaw-status          # Check service status, health, recent logs
openclaw-security-check  # Run full security audit (pass/fail checklist)
openclaw-backup          # Create backup (auto-runs daily at 3 AM)
```

## Post-Setup

1. **Add your LLM API key:**
   ```bash
   nano /home/openclaw/.env
   # Add: ANTHROPIC_API_KEY=sk-ant-...
   systemctl restart openclaw-gateway
   ```

2. **Custom domain + real TLS cert:**
   ```bash
   certbot --nginx -d yourdomain.com
   ```

3. **Check everything works:**
   ```bash
   openclaw-security-check
   ```

## Requirements

- Fresh Ubuntu 24.04 LTS VPS
- Root access
- Minimum: 2 vCPU, 4GB RAM, 20GB disk

## Contributing

Contributions welcome — especially around security hardening. Open an issue or PR.

## License

MIT
