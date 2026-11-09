#!/bin/bash
# LingOps 一键启动：主服务(12800) + 扩展服务(12801) + ARTEX(8787, 需 PostgreSQL 5433)
# 用法: ./start.sh            正常启动
#       ./start.sh --no-ext   只启动主服务
#       ./start.sh --no-artex 不启动 ARTEX
set -u
cd "$(dirname "$0")" || exit 1

chmod +x ./lingops-server 2>/dev/null || true

# ---- 读取端口 ----
PORT=$(grep -E '^[[:space:]]*port:' configs/config.yaml 2>/dev/null | head -1 | awk '{print $2}')
PORT=${PORT:-12800}
EXT_PORT=12801
ARTEX_PORT=8787
PG_PORT=5433
PG_DATA="${ARTEX_PGDATA:-/opt/homebrew/var/postgresql@16}"
PG_BIN="${ARTEX_PGBIN:-/opt/homebrew/opt/postgresql@16/bin}"

echo "========================================"
echo "   LingOps AWD/AWDP Platform v0.2 + 扩展"
echo "========================================"
echo

# ---- 前置检查 ----
if [ ! -x ./lingops-server ]; then
  echo "[错误] 找不到可执行的 ./lingops-server"
  exit 1
fi
if [ ! -f ./configs/config.yaml ]; then
  echo "[错误] 缺少 configs/config.yaml"
  exit 1
fi
mkdir -p data

if command -v lsof >/dev/null 2>&1; then
  if lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[错误] 端口 $PORT 已被占用，LingOps 可能已经在运行。"
    echo "       打开 http://127.0.0.1:$PORT ，或先执行 ./stop.sh"
    exit 1
  fi
fi

# ---- 扩展服务（端口扫描 / 上传点 / AI 修复包） ----
SCAN_PID=""
PG_PID=""
ARTEX_PID=""
WANT_EXT=1
WANT_ARTEX=1
for a in "$@"; do
  [ "$a" = "--no-ext" ] && WANT_EXT=0
  [ "$a" = "--no-artex" ] && WANT_ARTEX=0
done

if [ "$WANT_EXT" = "1" ] && [ -f ./ext/lp_scan_server.py ] && command -v python3 >/dev/null 2>&1; then
  if lsof -nP -iTCP:"$EXT_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "[扩展] 已在运行: http://127.0.0.1:$EXT_PORT"
  else
    python3 ./ext/lp_scan_server.py --port "$EXT_PORT" >/tmp/lingops-scan-ext.log 2>&1 &
    SCAN_PID=$!
    echo "[扩展] 已启动: http://127.0.0.1:$EXT_PORT  (日志 /tmp/lingops-scan-ext.log)"
  fi
elif [ "$WANT_EXT" = "1" ]; then
  echo "[扩展] 未启动（缺 python3 或 ext/lp_scan_server.py），端口扫描/上传点/AI 修复包不可用"
fi

# ---- ARTEX（LLM 自治渗透，独立进程 + PostgreSQL） ----
port_busy() { lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1; }

if [ "$WANT_ARTEX" = "1" ] && [ -x ./artex/artex ]; then
  # 0) 首次运行：从模板生成 config.json（仓库里不放真口令）
  if [ ! -f ./artex/config.json ] && [ -f ./artex/config.example.json ]; then
    cp ./artex/config.example.json ./artex/config.json
    echo "[ARTEX] 已生成 artex/config.json，请填入 database.password（见 docs/23-artex.md）"
  fi

  # 1) PostgreSQL：ARTEX 的唯一数据源
  if port_busy "$PG_PORT"; then
    echo "[ARTEX] PostgreSQL 已在运行 (:$PG_PORT)"
  elif [ -x "$PG_BIN/pg_ctl" ] && [ -d "$PG_DATA" ]; then
    "$PG_BIN/pg_ctl" -D "$PG_DATA" -o "-p $PG_PORT" -l /tmp/lingops-pg.log start >/dev/null 2>&1
    for _ in $(seq 1 40); do port_busy "$PG_PORT" && break; sleep 0.25; done
    if port_busy "$PG_PORT"; then
      echo "[ARTEX] PostgreSQL 已启动 (:$PG_PORT, 日志 /tmp/lingops-pg.log)"
      PG_PID="pg_ctl"
    else
      echo "[ARTEX] PostgreSQL 启动失败，看 /tmp/lingops-pg.log"
    fi
  else
    echo "[ARTEX] 找不到 PostgreSQL（$PG_BIN/pg_ctl），ARTEX 无法启动"
    echo "        安装: brew install postgresql@16"
  fi

  # 2) ARTEX 本体
  if port_busy "$ARTEX_PORT"; then
    echo "[ARTEX] 已在运行: http://127.0.0.1:$ARTEX_PORT"
  elif port_busy "$PG_PORT"; then
    # 密码只在数据库未初始化时生效；ARTEX_ADMIN_PASSWORD 可覆盖，见 docs/23-artex.md
    ( cd ./artex && ARTEX_ADMIN_PASSWORD="${ARTEX_ADMIN_PASSWORD:-admin123}" \
        exec ./artex -addr "127.0.0.1:$ARTEX_PORT" ) >/tmp/lingops-artex.log 2>&1 &
    ARTEX_PID=$!
    for _ in $(seq 1 40); do port_busy "$ARTEX_PORT" && break; sleep 0.25; done
    if port_busy "$ARTEX_PORT"; then
      echo "[ARTEX] 已启动: http://127.0.0.1:$ARTEX_PORT  (日志 /tmp/lingops-artex.log)"
    else
      echo "[ARTEX] 启动失败，看 /tmp/lingops-artex.log"
    fi
  fi
elif [ "$WANT_ARTEX" = "1" ]; then
  echo "[ARTEX] 未安装（缺 artex/artex），侧边栏 ARTEX 菜单会提示未启动"
fi

# ---- 主服务 ----
./lingops-server "$@" &
SERVER_PID=$!

cleanup() {
  [ -n "$SCAN_PID" ] && kill "$SCAN_PID" 2>/dev/null || true
  [ -n "$ARTEX_PID" ] && kill "$ARTEX_PID" 2>/dev/null || true
  kill "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

READY=""
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then READY=1; break; fi
  kill -0 "$SERVER_PID" 2>/dev/null || break
  sleep 0.5
done

if [ -n "$READY" ]; then
  echo
  echo "========================================"
  echo "  启动成功"
  echo "  控制台:   http://127.0.0.1:$PORT"
  echo "  账号:     admin / admin123  (首次登录后请修改)"
  echo "  扩展面板: http://127.0.0.1:$PORT/assets_v2/lp-ext/panel.html"
  if port_busy "$ARTEX_PORT"; then
    echo "  ARTEX:    http://127.0.0.1:$ARTEX_PORT  (账号 admin / 密码 admin123，界面只输密码)"
  fi
  echo "  教程:     docs/README.md"
  echo "  Ctrl+C 停止全部服务"
  echo "========================================"
else
  echo "[警告] 30 秒内未通过健康检查，请查看上方日志"
fi

wait "$SERVER_PID"
