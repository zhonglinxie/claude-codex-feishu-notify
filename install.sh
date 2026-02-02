#!/bin/bash
# Claude Code Feishu Notification - One-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/USER/REPO/main/install.sh | bash

set -e

SCRIPT_DIR="$HOME/.codex"
CLAUDE_SETTINGS="$HOME/.claude/settings.json"
NOTIFY_SCRIPT="$SCRIPT_DIR/notify.py"
REPO_RAW_URL="https://raw.githubusercontent.com/zhonglinxie/claude-codex-feishu-notify/main"

echo "=== Claude Code Feishu Notify Installer ==="
echo ""

# 1. Create directories
mkdir -p "$SCRIPT_DIR/log"
mkdir -p "$HOME/.claude"

# 2. Download notify.py
echo "[1/3] Downloading notify.py..."
if command -v curl &> /dev/null; then
    curl -fsSL "$REPO_RAW_URL/notify.py" -o "$NOTIFY_SCRIPT"
elif command -v wget &> /dev/null; then
    wget -q "$REPO_RAW_URL/notify.py" -O "$NOTIFY_SCRIPT"
else
    echo "Error: curl or wget required"
    exit 1
fi
chmod +x "$NOTIFY_SCRIPT"
echo "   -> Saved to $NOTIFY_SCRIPT"

# 3. Configure Claude Code hooks
echo "[2/3] Configuring Claude Code hooks..."

HOOKS_CONFIG='{
  "Stop": [
    {
      "matcher": "",
      "hooks": [
        {
          "type": "command",
          "command": "python3 '"$NOTIFY_SCRIPT"'"
        }
      ]
    }
  ],
  "Notification": [
    {
      "matcher": "idle_prompt|permission_prompt",
      "hooks": [
        {
          "type": "command",
          "command": "python3 '"$NOTIFY_SCRIPT"'"
        }
      ]
    }
  ]
}'

if [ -f "$CLAUDE_SETTINGS" ]; then
    # Merge hooks into existing settings
    if command -v python3 &> /dev/null; then
        python3 << EOF
import json
import sys

settings_path = "$CLAUDE_SETTINGS"
hooks_config = json.loads('''$HOOKS_CONFIG''')

try:
    with open(settings_path, 'r') as f:
        settings = json.load(f)
except:
    settings = {}

settings['hooks'] = hooks_config

with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2, ensure_ascii=False)

print("   -> Updated", settings_path)
EOF
    else
        echo "   -> Warning: python3 not found, please manually configure hooks"
    fi
else
    # Create new settings file
    echo "{\"hooks\": $HOOKS_CONFIG}" | python3 -m json.tool > "$CLAUDE_SETTINGS"
    echo "   -> Created $CLAUDE_SETTINGS"
fi

# 4. Check environment variables
echo "[3/3] Checking environment variables..."
MISSING=""
[ -z "$FEISHU_APP_ID" ] && MISSING="$MISSING FEISHU_APP_ID"
[ -z "$FEISHU_APP_SECRET" ] && MISSING="$MISSING FEISHU_APP_SECRET"
[ -z "$FEISHU_USER_ID" ] && MISSING="$MISSING FEISHU_USER_ID"

if [ -n "$MISSING" ]; then
    echo ""
    echo "=== IMPORTANT: Set these environment variables ==="
    echo ""
    echo "Add to your ~/.bashrc or ~/.zshrc:"
    echo ""
    echo "  export FEISHU_APP_ID=\"your_app_id\""
    echo "  export FEISHU_APP_SECRET=\"your_app_secret\""
    echo "  export FEISHU_USER_ID=\"your_user_id\""
    echo ""
    echo "Then run: source ~/.bashrc"
    echo ""
else
    echo "   -> All environment variables set!"
fi

echo ""
echo "=== Installation Complete! ==="
echo ""
echo "Test with: echo '{\"hook_event_name\":\"Stop\",\"session_id\":\"test\"}' | python3 $NOTIFY_SCRIPT"
echo ""
