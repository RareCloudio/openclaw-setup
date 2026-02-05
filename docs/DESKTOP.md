# OpenClaw Desktop Setup

A Mac Mini alternative in the cloud — full Ubuntu Desktop with VNC access for your AI assistant.

## Why Desktop?

| You want... | Use |
|-------------|-----|
| Minimal resources, CLI workflow | [Server Setup](../README.md) |
| Watch AI work in real-time | **Desktop Setup** ✓ |
| Visual debugging | **Desktop Setup** ✓ |
| Browser extensions | **Desktop Setup** ✓ |
| Demos for stakeholders | **Desktop Setup** ✓ |

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/RareCloudio/openclaw-setup/main/setup-desktop.sh -o setup-desktop.sh
chmod +x setup-desktop.sh
sudo ./setup-desktop.sh --novnc
```

Save the VNC password shown at the end!

## Connection Methods

### Method 1: Browser (noVNC) — Easiest

If you used `--novnc`:
```
https://YOUR_IP:6080/vnc.html
```

No software needed — works in any browser.

### Method 2: VNC Client — Best Quality

1. Install a VNC viewer ([RealVNC](https://www.realvnc.com/), [TigerVNC](https://tigervnc.org/), or built-in on Mac)
2. Connect to: `YOUR_IP:5901`
3. Enter the VNC password

### Method 3: SSH Tunnel — Most Secure

VNC traffic is encrypted through SSH:

```bash
# From your local machine:
ssh -p 41722 -L 5901:127.0.0.1:5901 openclaw@YOUR_IP

# Keep this terminal open, then connect VNC to:
localhost:5901
```

This method works even if port 5901 is firewalled.

## Options

```bash
sudo ./setup-desktop.sh [OPTIONS]
```

| Option | Description | Default |
|--------|-------------|---------|
| `--vnc-password PASS` | Set VNC password | random 12-char |
| `--novnc` | Enable web-based VNC (port 6080) | disabled |
| `--browser chrome` | Use Chrome instead of Firefox | firefox |
| `--ssh-port PORT` | SSH port | 41722 |
| `--skip-firewall` | Skip firewall setup | false |

## What Gets Installed

```
Ubuntu 24.04
├── XFCE Desktop (lightweight, ~300MB RAM)
├── TigerVNC Server (display :1, port 5901)
├── noVNC (optional, port 6080)
├── Firefox or Chrome (real browser, not headless)
├── OpenClaw (configured for GUI)
└── Security stack (firewall, fail2ban, SSH hardening)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Internet                              │
└─────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
    ┌──────────┐       ┌──────────┐       ┌──────────┐
    │SSH 41722 │       │VNC 5901  │       │noVNC 6080│
    │(always)  │       │(tunnel)  │       │(optional)│
    └────┬─────┘       └────┬─────┘       └────┬─────┘
         │                  │                  │
         └──────────────────┴──────────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         │         Ubuntu Desktop 24.04         │
         │  ┌─────────────────────────────────┐ │
         │  │         XFCE Desktop            │ │
         │  │  ┌───────────┐  ┌────────────┐  │ │
         │  │  │  Browser  │  │  Terminal  │  │ │
         │  │  │ (Firefox) │  │            │  │ │
         │  │  └───────────┘  └────────────┘  │ │
         │  │                                 │ │
         │  │  OpenClaw Gateway               │ │
         │  │  (localhost:18789)              │ │
         │  │  DISPLAY=:1 (uses real browser) │ │
         │  └─────────────────────────────────┘ │
         │                                      │
         │  TigerVNC Server (:1)                │
         └──────────────────────────────────────┘
```

## OpenClaw Configuration

The desktop setup configures OpenClaw to use the real browser:

```yaml
# ~/.openclaw/config.yaml
browser:
  headless: false
  executablePath: /usr/bin/firefox  # or /usr/bin/google-chrome
```

The `DISPLAY=:1` environment variable routes browser windows to the VNC display.

## Watching Your AI Work

1. Connect via VNC (any method above)
2. You'll see the XFCE desktop
3. Start OpenClaw: `openclaw gateway start`
4. When OpenClaw uses the browser, you'll see it open in real-time
5. Watch your AI navigate, click, type — just like screen sharing

## Security

### Ports

| Port | Service | Exposed? |
|------|---------|----------|
| 41722 | SSH | Yes (key-only) |
| 5901 | VNC | No (SSH tunnel) |
| 6080 | noVNC | Optional (`--novnc`) |
| 18789 | OpenClaw | No (localhost only) |

### Recommendations

1. **Use SSH tunnel for VNC** — encrypts traffic, no extra port exposed
2. **Strong VNC password** — use `--vnc-password` with a good password
3. **Disable noVNC in production** — only enable for convenience during setup
4. **Regular updates** — `apt update && apt upgrade`

## Troubleshooting

### VNC won't connect

```bash
# Check if VNC is running:
systemctl status vncserver@1

# Restart VNC:
sudo systemctl restart vncserver@1

# Check logs:
journalctl -u vncserver@1 -f
```

### Black screen in VNC

```bash
# XFCE might not have started. Check:
cat ~/.vnc/*.log

# Restart the VNC server:
vncserver -kill :1
vncserver :1
```

### Browser not visible

```bash
# Make sure DISPLAY is set:
echo $DISPLAY  # Should show :1

# If not:
export DISPLAY=:1
```

### noVNC not accessible

```bash
# Check if running:
systemctl status novnc

# Check firewall:
sudo nft list ruleset | grep 6080
```

## Resource Usage

| Component | RAM | CPU |
|-----------|-----|-----|
| XFCE Desktop | ~300MB | Minimal |
| TigerVNC | ~50MB | Minimal |
| Firefox | ~500MB-1GB | Variable |
| Chrome | ~500MB-1.5GB | Variable |
| OpenClaw | ~200MB | Variable |

**Recommended VPS specs:**
- 4GB RAM minimum (8GB for comfortable use)
- 2 vCPU minimum
- 30GB disk

## Comparison: Server vs Desktop

| Aspect | Server | Desktop |
|--------|--------|---------|
| RAM usage | 2-3GB | 4-6GB |
| Browser | Headless (invisible) | Real (visible in VNC) |
| Debugging | Logs only | See exactly what AI sees |
| Access | SSH only | SSH + VNC |
| Best for | Production | Development, demos |

## Uninstalling

To remove the desktop components (keeps OpenClaw):

```bash
sudo systemctl stop vncserver@1 novnc
sudo systemctl disable vncserver@1 novnc
sudo apt remove --purge xfce4 tigervnc-standalone-server novnc
sudo apt autoremove
```

## Support

- **Issues:** [GitHub Issues](https://github.com/RareCloudio/openclaw-setup/issues)
- **Pre-configured VPS:** [rarecloud.io](https://rarecloud.io)
- **OpenClaw docs:** [docs.openclaw.ai](https://docs.openclaw.ai)
