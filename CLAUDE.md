# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Automated, hardened OpenClaw (formerly MoltBot) setup for Ubuntu 24.04 VPS. Single script that installs everything and applies 8-layer security hardening.

## Files

- `setup.sh` — Main setup script. Installs Node.js 22, Docker, Chromium, OpenClaw, nginx reverse proxy, and applies all hardening. Accepts `--webui-pass`, `--gateway-token`, `--webui-user` flags.
- `helpers.sh` — Installs helper commands (`openclaw-status`, `openclaw-backup`, `openclaw-security-check`) to `/usr/local/bin/`. Called by setup.sh, can also run standalone.

## Architecture

OpenClaw runs natively on host (not Docker). Docker is only for agent sandbox isolation. Gateway binds to loopback:18789, nginx proxies HTTPS:443 to it with basic-auth + TLS.

## Security Model (8 layers)

nftables (22+443 only) → fail2ban → nginx TLS + rate limit → basic-auth → gateway token → AppArmor → Docker sandbox (cap_drop ALL) → systemd hardening

## Testing

```bash
# On a fresh Ubuntu 24.04 VPS:
bash setup.sh --webui-pass "test123" --gateway-token "testtoken123"

# Verify:
openclaw-status
openclaw-security-check
curl -k https://localhost
```
