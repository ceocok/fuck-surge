#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

PORT=9099

echo "🛑 正在停止 Surge VLESS & AnyTLS Hub 面板与内核..."

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

# Stop Core (sing-box or xray) if running
for pidfile in "$DIR/data/core.pid" "$DIR/data/xray.pid"; do
    if [ -f "$pidfile" ]; then
        XPID=$(cat "$pidfile")
        if kill -0 "$XPID" 2>/dev/null; then
            kill "$XPID" 2>/dev/null
            echo "已停止代理内核 (PID: $XPID)"
        fi
        rm -f "$pidfile"
    fi
done

# Fallback kill any xray / sing-box started with this config
pkill -f "xray run -c $DIR/data/config.json" 2>/dev/null
pkill -f "sing-box run -c $DIR/data/config.json" 2>/dev/null

echo "✅ 已完全停止！"
