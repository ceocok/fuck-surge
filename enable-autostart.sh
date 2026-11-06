#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

PLIST_NAME="com.fucksurge.hub.plist"
USER_AGENTS_DIR="$HOME/Library/LaunchAgents"
TARGET_PLIST="$USER_AGENTS_DIR/$PLIST_NAME"

PYTHON_BIN="$(which python3 || echo '/opt/homebrew/bin/python3')"

mkdir -p "$USER_AGENTS_DIR"
mkdir -p "$DIR/data"

cat << EOF > "$TARGET_PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.fucksurge.hub</string>
    <key>WorkingDirectory</key>
    <string>$DIR</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_BIN</string>
        <string>$DIR/app.py</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$DIR/data/launchd.log</string>
    <key>StandardErrorPath</key>
    <string>$DIR/data/launchd.error.log</string>
</dict>
</plist>
EOF

launchctl unload "$TARGET_PLIST" 2>/dev/null || true
launchctl load "$TARGET_PLIST"

echo "✅ 已成功配置开机静默自动启动服务！"
echo "服务标签: com.fucksurge.hub"
echo "配置文件: $TARGET_PLIST"
