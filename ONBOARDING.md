# Non-Tech User Onboarding Experience

## Problem Statement

Current setup requires:
- SSH knowledge (what is SSH? what's a port?)
- CLI commands (`su - openclaw -c "..."` - intimidating!)
- Manual configuration (edit files, tokens, etc.)
- No visual feedback (did it work? is it running?)

**For non-tech users buying a VPS with auto-install, this is overwhelming.**

## Proposed Solution: 5-Step Easy Onboarding

### Step 1: After Purchase Email

**Subject:** Your OpenClaw Assistant is Ready! ☁️

```
Hi [Customer Name],

Your OpenClaw AI assistant is being set up right now on your VPS!

⏱️ Estimated time: 5-10 minutes

We'll send you another email when it's ready with your personal setup link.

Questions? Reply to this email or visit https://docs.rarecloud.io

— RareCloud Team
```

### Step 2: Setup Complete Email

**Subject:** ✅ Your OpenClaw is Ready - Complete Setup (3 minutes)

```
Hi [Customer Name],

Your OpenClaw assistant is installed and waiting for you!

👉 Click here to complete setup (takes 3 minutes):
https://setup.rarecloud.io/[UNIQUE_TOKEN]

This link expires in 24 hours for security.

What you'll do:
1. Add your AI API key (Claude or OpenAI)
2. Connect WhatsApp or Telegram
3. Send your first message!

No technical knowledge needed. Just follow the wizard.

— RareCloud Team
```

### Step 3: Web Setup Wizard

**URL:** `https://setup.rarecloud.io/[UNIQUE_TOKEN]`

**Features:**
- Mobile-friendly design
- Progress bar (Step 1 of 3, Step 2 of 3, etc.)
- Clear instructions with screenshots
- Validates inputs (is this a valid API key?)
- No SSH, no terminal, no scary commands

**Page 1: Add Your AI API Key**
```
Welcome! Let's connect your AI brain 🧠

Choose your AI provider:
[ ] Claude (Anthropic) - Recommended
[ ] OpenAI (ChatGPT)
[ ] Other

[Input: API Key]
[Button: Test Connection]

✅ Connection successful! Your AI is ready.

[Button: Next →]
```

**Page 2: Connect Messaging**
```
How do you want to talk to your assistant? 📱

[ ] WhatsApp - Scan QR code (easiest!)
[ ] Telegram - Click to authorize
[ ] Keep it web-only (no messaging)

[If WhatsApp selected:]
Scan this QR code with WhatsApp:
[QR CODE]

Waiting for scan... ⏳

✅ Connected! You're all set.

[Button: Next →]
```

**Page 3: Send Your First Message**
```
🎉 You're ready!

Send a test message to confirm everything works:

[If WhatsApp:]
Open WhatsApp and send any message to yourself.
Your assistant will reply within seconds.

[If Telegram:]
Open Telegram and message @your_openclaw_bot

[If Web-only:]
[Chat interface right here]

Try it now, then click Finish below.

[Button: Finish Setup]
```

**Page 4: Success!**
```
🎊 Congratulations! Your OpenClaw assistant is live.

📱 Access your assistant:
   - WhatsApp: [Phone number]
   - Dashboard: https://my.rarecloud.io/[your-id]

📚 Learn more:
   - Quick Start Guide
   - Video Tutorials (2 min each)
   - Community Forum

🔒 Security:
   Your setup link has been deleted for security.
   Your credentials are safe and encrypted.

[Button: Go to Dashboard]
```

### Step 4: Auto-Send Test Message

**After setup completes:**
- System automatically sends first message via chosen channel
- Example: "Hi! I'm your OpenClaw assistant. I'm ready to help. What would you like to know?"

**Why this matters:**
- Confirms everything works
- User sees immediate value
- Removes doubt ("did it work?")

### Step 5: Persistent Dashboard

**URL:** `https://my.rarecloud.io/[user-id]`

**Features:**
- Status: ✅ Online / ❌ Offline
- Usage stats:
  - Messages today: 12
  - Tokens used this month: 45,231
  - Cost estimate: $2.34
- Quick actions:
  - Reconnect WhatsApp (if disconnected)
  - Add another messaging channel
  - View recent conversations
  - Manage API keys
- Alerts:
  - "⚠️ Your API key expires in 7 days"
  - "❌ WhatsApp disconnected - click to reconnect"

---

## Technical Implementation Plan

### 1. Setup Wizard Backend

**Tech Stack:**
- Simple Node.js/Express server
- Runs on the VPS during initial setup
- Auto-terminates after completion
- One-time use tokens (24h expiry)

**Security:**
- HTTPS only (Let's Encrypt auto-cert)
- Rate limiting (prevent brute force)
- Token expires after use or 24h
- Server shuts down after completion

**Flow:**
```
1. setup.sh generates unique token on install
2. Sends token to RareCloud API → email customer
3. Customer clicks link → opens wizard
4. Wizard configures OpenClaw via API
5. After completion → server terminates
```

### 2. Web Dashboard

**Persistent Service:**
- Lightweight web UI (React/Vue)
- Reverse proxy via Tailscale or Cloudflare Tunnel
- Authentication via magic link (email-based, no passwords)
- Read-only status + basic controls

**API Endpoints:**
- `GET /status` → gateway health, uptime
- `GET /stats` → usage metrics
- `POST /reconnect/whatsapp` → regenerate QR code
- `GET /logs/recent` → last 10 messages (sanitized)

### 3. Email Templates

**Automated Emails:**
- Purchase → "Setup starting..."
- Install complete → "Click to finish setup"
- Setup complete → "You're live!"
- Weekly digest → "Your assistant handled 234 messages this week"
- Alerts → "WhatsApp disconnected" / "API key expiring"

### 4. Video Tutorials

**3x Short Videos (2 min each):**
1. "What is OpenClaw?" - Overview
2. "Your first conversation" - Demo
3. "Dashboard tour" - Features

**Hosted:** YouTube + embedded in dashboard

---

## User Journey Comparison

### Current Experience (Technical)

```
1. Buy VPS
2. Receive IP + SSH credentials
3. ??? (What's SSH?)
4. Google "how to use SSH"
5. Install PuTTY or Terminal
6. Connect via SSH (port 41722??)
7. Run: su - openclaw -c "openclaw models auth add"
8. ??? (What's a model? What's auth?)
9. Google "Anthropic API key"
10. Create account, get key, paste
11. Run: su - openclaw -c "openclaw channels login"
12. ??? (How do I scan QR from terminal??)
13. Give up or spend 2 hours frustrated
```

**Drop-off rate: ~70%**

### Proposed Experience (Non-Tech)

```
1. Buy VPS
2. Receive email: "Your assistant is being set up!"
3. 10 minutes later: "Click here to finish setup"
4. Click link → opens clean web page
5. "Add your Claude API key" → paste, test, ✅
6. "Connect WhatsApp" → scan QR code with phone, ✅
7. "Send a test message" → works immediately!
8. Done! Dashboard shows "✅ Online"
```

**Drop-off rate: ~10%**

---

## Quick Wins (Can Implement Now)

### 1. Setup Summary Page

After `setup.sh` completes, generate a simple HTML file:

**File:** `/var/www/openclaw-setup/index.html`

```html
<!DOCTYPE html>
<html>
<head>
    <title>OpenClaw Setup Complete</title>
    <style>/* Simple clean design */</style>
</head>
<body>
    <h1>✅ OpenClaw Installed</h1>
    <h2>Next Steps:</h2>
    <ol>
        <li>Add API Key: <code>openclaw models auth add</code></li>
        <li>Connect Messaging: <code>openclaw channels login</code></li>
        <li>Verify: <code>openclaw health</code></li>
    </ol>
    <a href="https://docs.rarecloud.io/quick-start">Full Guide →</a>
</body>
</html>
```

Serve on port 8080 (temporary nginx)

### 2. Email Template System

Add to `setup.sh`:

```bash
# After install complete
send_notification() {
    curl -X POST https://api.rarecloud.io/notify \
        -H "Content-Type: application/json" \
        -d "{
            \"customer_id\": \"${CUSTOMER_ID}\",
            \"event\": \"setup_complete\",
            \"vps_ip\": \"${VPS_IP}\",
            \"gateway_token\": \"${GATEWAY_TOKEN}\"
        }"
}
```

RareCloud API → sends email to customer

### 3. First-Run Wizard (CLI)

Add interactive mode to openclaw:

```bash
openclaw init --interactive

# Walks through:
# 1. "Let's add your AI provider"
# 2. "Connect a messaging app"
# 3. "Send a test message"
```

Much friendlier than raw commands

---

## Metrics to Track

**Setup Success:**
- % of VPS purchases that complete setup
- Average time to first message
- Drop-off points (where do users quit?)

**User Satisfaction:**
- Support tickets opened (fewer = better)
- User rating after first week
- Retention after 30 days

**Technical:**
- Setup wizard completion rate
- Dashboard usage frequency
- Reconnection events (WhatsApp drops)

---

## Next Steps

1. **Prototype Setup Wizard** - Build minimal web interface
2. **Test with 5 Non-Tech Users** - Watch them try to set up
3. **Iterate Based on Feedback** - Where do they get stuck?
4. **Integrate with RareCloud Billing** - Auto-provision on purchase
5. **Launch Beta** - Offer to first 50 customers

**Goal:** Any non-tech user can go from "buy VPS" to "chatting with assistant" in under 10 minutes, with zero frustration.
