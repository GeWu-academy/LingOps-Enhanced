#!/bin/bash
# 卸载 LingOps 扫描扩展：还原 index.html、删除注入文件与扫描后端
set -e
cd "$(dirname "$0")/.."

ROOT="$(pwd)"

rm -rf "$ROOT/frontend/dist/assets_v2/lp-ext"
if [ -f "$ROOT/frontend/dist/index.html.bak-lingops-ext" ]; then
  mv "$ROOT/frontend/dist/index.html.bak-lingops-ext" "$ROOT/frontend/dist/index.html"
  echo "已还原 frontend/dist/index.html"
else
  # 没有备份时直接剔除注入行
  if grep -q 'lp-ext/boot.js' "$ROOT/frontend/dist/index.html" 2>/dev/null; then
    grep -v 'lp-ext/boot.js' "$ROOT/frontend/dist/index.html" > "$ROOT/frontend/dist/index.html.tmp"
    mv "$ROOT/frontend/dist/index.html.tmp" "$ROOT/frontend/dist/index.html"
    echo "已从 index.html 移除注入脚本"
  fi
fi

rm -rf "$ROOT/ext" "$ROOT/start-ext.sh"
echo "已卸载扫描扩展（重启 LingOps 后界面恢复原样）"
