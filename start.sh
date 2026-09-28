#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

PORT=9099
URL="http://127.0.0.1:${PORT}"

# Ensure data directory exists
mkdir -p "$DIR/data"

# Check python3
if ! command -v python3 &>/dev/null; then
    echo "❌ 错误: 未检测到 python3，请先安装 Python 3 (macOS 可运行: brew install python3)"
    exit 1
fi

# Check xray presence
if ! command -v xray &>/dev/null && [ ! -f "/opt/homebrew/bin/xray" ] && [ ! -f "/usr/local/bin/xray" ]; then
    echo "⚠️  提示: 系统中未找到 xray，请在终端运行: brew install xray"
fi

# Check if already running
if lsof -Pi :${PORT} -sTCP:LISTEN -t >/dev/null ; then
    echo "⚡ Surge VLESS Hub 已经在运行中: ${URL}"
    if command -v open &>/dev/null; then
        open "${URL}"
    elif command -v xdg-open &>/dev/null; then
        xdg-open "${URL}"
    fi
    exit 0
fi

echo "🚀 正在启动 Surge VLESS Hub 面板..."
nohup python3 "$DIR/app.py" > "$DIR/data/app.log" 2>&1 &
APP_PID=$!
echo "$APP_PID" > "$DIR/data/app.pid"

sleep 1

if lsof -Pi :${PORT} -sTCP:LISTEN -t >/dev/null ; then
    echo "✅ 服务已就绪！"
    echo "👉 面板地址: ${URL} (PID: ${APP_PID})"
    if command -v open &>/dev/null; then
        open "${URL}"
    elif command -v xdg-open &>/dev/null; then
        xdg-open "${URL}"
    fi
else
    echo "❌ 启动失败，请查看日志: $DIR/data/app.log"
    cat "$DIR/data/app.log"
    exit 1
fi
