#!/usr/bin/env bash
# Generate a simple onboarding web page after setup completes
# This serves as a bridge between "setup done" and "user knows what to do next"

set -euo pipefail

VPS_IP="${1:-$(ip -4 route get 1.1.1.1 | awk '{print $7; exit}')}"
GATEWAY_TOKEN="${2:-}"
SSH_PORT="${3:-41722}"

OUTPUT_FILE="/var/www/html/openclaw-welcome.html"

# Create web root if needed
mkdir -p /var/www/html

# Generate HTML
cat > "$OUTPUT_FILE" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to Your OpenClaw Assistant</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 600px;
            padding: 40px;
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 32px;
        }
        .status {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            padding: 16px;
            margin: 20px 0;
            color: #155724;
        }
        .status strong {
            font-size: 18px;
        }
        h2 {
            margin-top: 30px;
            margin-bottom: 15px;
            color: #333;
            font-size: 20px;
        }
        .steps {
            list-style: none;
            counter-reset: step-counter;
        }
        .steps li {
            counter-increment: step-counter;
            margin-bottom: 20px;
            padding-left: 40px;
            position: relative;
        }
        .steps li::before {
            content: counter(step-counter);
            position: absolute;
            left: 0;
            top: 0;
            width: 28px;
            height: 28px;
            background: #667eea;
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 14px;
        }
        .steps li strong {
            display: block;
            margin-bottom: 5px;
            color: #333;
        }
        code {
            background: #f5f5f5;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            color: #d63384;
        }
        .btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            margin-top: 20px;
            font-weight: 600;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #5568d3;
        }
        .info-box {
            background: #e7f3ff;
            border-left: 4px solid #2196F3;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
        }
        .info-box strong {
            color: #1976D2;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 16px;
            margin: 20px 0;
            border-radius: 4px;
            color: #856404;
        }
        footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            text-align: center;
            color: #999;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Your OpenClaw is Ready!</h1>
        <p style="color: #666; margin-top: 10px;">Installation completed successfully</p>
        
        <div class="status">
            <strong>🎉 Setup Complete</strong><br>
            Your AI assistant is installed and waiting for you.
        </div>

        <h2>📋 Next Steps (5 minutes)</h2>
        <ol class="steps">
            <li>
                <strong>Add Your AI API Key</strong>
                <p>Connect to your VPS via SSH and run:</p>
                <code>openclaw models auth add</code>
                <p style="margin-top: 8px; color: #666; font-size: 14px;">
                    You'll need a Claude (Anthropic) or OpenAI API key.<br>
                    Don't have one? <a href="https://console.anthropic.com" target="_blank">Get Claude key →</a>
                </p>
            </li>
            
            <li>
                <strong>Connect a Messaging App</strong>
                <p>Choose WhatsApp, Telegram, or another platform:</p>
                <code>openclaw channels login</code>
                <p style="margin-top: 8px; color: #666; font-size: 14px;">
                    Follow the interactive wizard to connect your preferred app.
                </p>
            </li>
            
            <li>
                <strong>Verify Everything Works</strong>
                <p>Run the health check:</p>
                <code>openclaw health</code>
                <p style="margin-top: 8px; color: #666; font-size: 14px;">
                    This confirms all components are running correctly.
                </p>
            </li>
        </ol>

        <div class="info-box">
            <strong>💡 Tip:</strong> Need help with SSH?<br>
            Windows: Use <a href="https://www.putty.org/" target="_blank">PuTTY</a><br>
            Mac/Linux: Open Terminal and type: <code>ssh -p SSH_PORT_PLACEHOLDER root@VPS_IP_PLACEHOLDER</code>
        </div>

        <div class="warning">
            <strong>⚠️ Security Notice:</strong><br>
            SSH is now on port <strong>SSH_PORT_PLACEHOLDER</strong> (not 22).<br>
            Use: <code>ssh -p SSH_PORT_PLACEHOLDER root@VPS_IP_PLACEHOLDER</code>
        </div>

        <h2>📚 Resources</h2>
        <ul style="margin-left: 20px; margin-top: 10px; line-height: 1.8;">
            <li><a href="https://docs.openclaw.ai" target="_blank">OpenClaw Documentation</a></li>
            <li><a href="https://docs.rarecloud.io/quick-start" target="_blank">Quick Start Guide</a></li>
            <li><a href="https://github.com/RareCloudio/openclaw-setup" target="_blank">GitHub Repository</a></li>
        </ul>

        <a href="https://docs.rarecloud.io/quick-start" class="btn" target="_blank">
            View Full Setup Guide →
        </a>

        <footer>
            Powered by <strong>RareCloud</strong> ☁️<br>
            Need help? <a href="mailto:support@rarecloud.io">support@rarecloud.io</a>
        </footer>
    </div>
</body>
</html>
EOF

# Replace placeholders
sed -i "s/VPS_IP_PLACEHOLDER/${VPS_IP}/g" "$OUTPUT_FILE"
sed -i "s/SSH_PORT_PLACEHOLDER/${SSH_PORT}/g" "$OUTPUT_FILE"

# Install nginx if not present
if ! command -v nginx &>/dev/null; then
    echo "[onboarding] Installing nginx for welcome page..."
    apt-get update -qq
    apt-get install -y -qq nginx
    systemctl enable nginx
fi

# Configure nginx
cat > /etc/nginx/sites-available/openclaw-welcome << EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    root /var/www/html;
    index openclaw-welcome.html;
    
    server_name _;
    
    location / {
        try_files \$uri \$uri/ /openclaw-welcome.html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/openclaw-welcome /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

echo "[onboarding] ============================================"
echo "[onboarding] Welcome page generated!"
echo "[onboarding] ============================================"
echo ""
echo "  🌐 Visit: http://${VPS_IP}"
echo ""
echo "  The page will guide your user through:"
echo "    1. Adding API keys"
echo "    2. Connecting messaging"
echo "    3. Verifying setup"
echo ""
echo "[onboarding] ============================================"
