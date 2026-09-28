#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

PORT=9099

echo "🛑 正在停止 Surge VLESS Hub 面板与内核..."

# Stop Python web app by PID file
if [ -f "$DIR/data/app.pid" ]; then
    PID=$(cat "$DIR/data/app.pid")
    if kill -0 "$PID" 2>/dev/null; then
        kill "$PID" 2>/dev/null
        echo "已停止面板进程 (PID: $PID)"
    fi
    rm -f "$DIR/data/app.pid"
fi

# Stop any process holding port 9099
APP_PORT_PID=$(lsof -ti :${PORT})
if [ -n "$APP_PORT_PID" ]; then
    kill -9 $APP_PORT_PID 2>/dev/null
fi

# Stop Xray if running
if [ -f "$DIR/data/xray.pid" ]; then
    XPID=$(cat "$DIR/data/xray.pid")
    if kill -0 "$XPID" 2>/dev/null; then
        kill "$XPID" 2>/dev/null
        echo "已停止 Xray 内核 (PID: $XPID)"
    fi
    rm -f "$DIR/data/xray.pid"
fi

# Fallback kill any xray started from this dir
pkill -f "xray run -c $DIR/data/config.json" 2>/dev/null

echo "✅ 已完全停止！"
