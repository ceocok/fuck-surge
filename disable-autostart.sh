#!/usr/bin/env bash
set -e

PLIST_NAME="com.fucksurge.hub.plist"
USER_AGENTS_DIR="$HOME/Library/LaunchAgents"
TARGET_PLIST="$USER_AGENTS_DIR/$PLIST_NAME"

if [ -f "$TARGET_PLIST" ]; then
    launchctl unload "$TARGET_PLIST" 2>/dev/null || true
    rm -f "$TARGET_PLIST"
    echo "✅ 已移除开机静默自动启动配置！"
else
    echo "ℹ️ 未发现开机自启动配置文件: $TARGET_PLIST"
fi
