#!/bin/bash
# 启动 LingOps 扫描扩展服务（端口扫描 + 上传点探测 + AI 修复包）
# 用法: bash start-ext.sh [端口]   默认 12801
set -e
cd "$(dirname "$0")"

PORT="${1:-12801}"

if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "扫描扩展服务已在 127.0.0.1:$PORT 运行"
  echo "面板: http://127.0.0.1:12800/assets_v2/lp-ext/panel.html"
  exit 0
fi

echo "========================================"
echo "   LingOps 扩展 · 端口 / 上传点扫描"
echo "========================================"
echo "监听: http://127.0.0.1:$PORT"
echo "面板: http://127.0.0.1:12800/assets_v2/lp-ext/panel.html"
echo "Ctrl+C 停止"
echo "========================================"

exec python3 ./ext/lp_scan_server.py --port "$PORT"
